import re

from twisted.internet import defer
from twisted.python.failure import Failure

from kato import KatoHttpClient

# characters that are disallowed from the channel name
CHANNEL_NAME_DISALLOWED = re.compile(r"[^a-zA-Z0-9_-]+", re.UNICODE)
# characters that are disallowed from the nick name
NICKNAME_DISALLOWED = re.compile(r"[^a-zA-Z0-9_-]+", re.UNICODE)
# space handling regex
SPACES = re.compile(r"[\s_]+", re.UNICODE)

# IRC channel <--> Kato room object
class Channel(object):
    # IRC channel name, with the channel leading character
    irc_channel = ""

    # KatoRoom object with which this channel is associated
    kato_room = None

    # whether the IRC user is in the channel
    joined = None

    def __init__(self, kato_room):
        if not kato_room:
            raise ValueError("Must provide Kato room")

        self.irc_channel = Channel.create_channel_name(kato_room)
        self.joined = False
        self.kato_room = kato_room

    def __repr__(self):
        return "Channel{irc_channel='%s', kato_room='%s', joined=%s}" % \
            (self.irc_channel, self.kato_room, self.joined)

    # create a channel name from a kato room
    @classmethod
    def create_channel_name(cls, kato_room):
        if kato_room.type == "support_front":
            return "#kato_support"

        return cls.normalize_channel_name(kato_room.name)

    # according to the IRC spec, channels must begin with a '&', '#', '+' or
    # '!'. Other than that, they must be at most 50 characters, and must not
    # contain a space, control G (ASCII 7), or a comma. The names themselves
    # are case insensitive.
    #
    # for reasons of practically, this function:
    # - normalizes the channel name to lowercase, prefixed with a #
    # - converts all spaces to underscores
    # - removes all non-alphanumeric characters
    # - truncates to length 50, if needed
    #
    # in addition, several rooms are given special names, such as the Kato
    # support room
    # TODO: check for uniqueness, and augment somehow
    @classmethod
    def normalize_channel_name(cls, name):
        name = name.lower()
        name = SPACES.sub('_', name)
        name = CHANNEL_NAME_DISALLOWED.sub('', name)
        # second pass, to remove double underscores if the original string
        # were "a & b" -> "a__b" -> "a_b"
        name = SPACES.sub('_', name)
        name = name.strip("_")
        name = name[:50]
        return "#" + name

# IRC nick <--> Kato account object
class Account(object):
    # IRC nickname with which this account is associated
    nickname = ""

    # KatoAccount object with which this account is associated
    # this is None for the pseudo system user
    kato_account = None

    def __init__(self, kato_account, nickname=None):
        self.kato_account = kato_account

        if nickname:
            self.nickname = nickname
        else:
            self.nickname = Account.create_nickname(kato_account)

    def __repr__(self):
        return "Account{nickname='%s', kato_account='%s'}" % \
            (self.nickname, self.kato_account)

    # create a nickname from a kato account name
    @classmethod
    def create_nickname(cls, kato_account):
        name = kato_account.name
        return cls.normalize_nickname(name)

    # according to the IRC spec, nick names follow the rule must be of length
    # 9 or shorter, begin with a letter or special character, and consist only
    # of letters, digits, ecpail characters, and a -
    # special chracters are defined as %x5B-60 / %x7B-7D
    # that is, "[", "]", "\", "`", "_", "^", "{", "|", "}"
    #
    # for reasons of practically, this function:
    # - normalizes the user's name to lowercase
    # - converts all spaces to underscores
    # - removes all non-alphanumeric characters
    # - truncates to length *50*, if needed; note that this violates the spec,
    #   but such short nicknames are silly, and irssi handles more
    #   TODO: strict mode to override this
    #
    # TODO: check for uniqueness, and augment somehow
    @classmethod
    def normalize_nickname(cls, name):
        name = name.lower()
        name = SPACES.sub('_', name)
        name = NICKNAME_DISALLOWED.sub('', name)
        # second pass, to remove double underscores if the original string
        # were "a & b" -> "a__b" -> "a_b"
        name = SPACES.sub('_', name)
        name = name.strip("_")
        name = name[:50]
        return name

    # TODO: better identifier
    # IRC identifier used for a fully-qualified identifier
    def irc_ident(self):
        return self.nickname + "!" + self.nickname + "@kato"

# object that manages chat operations and state
#
# all verbs here are from the perspective of the IRC client; for example,
# send_message sends a message (received from IRC) to Kato, and
# receive_message sends a message received from Kato to the local client's IRC
# message
#
# TODO: use a semaphore to prevent multiple operations at once, so messages stay ordered
class Chat(object):
    irc = None

    # not initialized until the IRC connection initializes the client with a
    # user-provided username/password
    kato = None

    # list of Channel objects
    channels = None

    # Account objects, indexed by the Account's ID
    accounts = None

    # Account object of the current user
    account = None

    def __init__(self, irc):
        self.irc = irc
        self.accounts = dict()
        self.channels = []

    # returns True/False depending on whether this chat connection is
    # connected to kato
    def is_connected(self):
        return self.kato != None

    # initializes a Kato connection
    # token should be an email / password combination, separated by a space
    # on error, a message will be provided to the user from the system user,
    # rather than returning an error via this function, and the connection
    # will be dropped
    def init_kato(self, token):
        self.kato = None
        kato = KatoHttpClient(KatoMessageReceiver(self))

        d_init = defer.Deferred()

        parts = token.split(" ", 1)
        if len(parts) != 2:
            self.receive_system_message("Whoops, your IRC password was not " +
                    "valid. Please send your Kato username (your email " +
                    "address) and your Kato password, separated by a space, " +
                    "as your IRC password.")
            self.disconnect()
            d_init.errback(ValueError("Invalid token"))
            return d_init

        email, password = parts
        d_login = kato.login(email, password)

        # called once all data has been loaded correctly, including members,
        # rooms, orgs, etc
        def init_success():
            d_init.callback(self)

        def error(failure=None):
            if failure and failure.check(ValueError):
                self.receive_system_message("Darn, we could not connect to " +
                    "Kato. Please check your username and password.")
            else:
                self.receive_system_message("Woah, something went wrong " +
                    "when connecting to Kato. Whoops. Sorry about that.")

            print "Unable to connect to Kato.", failure
            self.kato = None
            self.disconnect()
            d_init.errback(failure)

        # organization members result
        # account_list is a list of KatoAccount objects
        # see get_organization_members in KatoHttpClient
        def org_members_success(account_list):
            for account in account_list:
                self._add_kato_account(account)

        # rooms for a single organization result
        # room_list is a list of KatoRoom objects
        # see get_rooms in KatoHttpClient
        def rooms_success(room_list):
            for room in room_list:
                self._add_kato_room(room)

        # information about a single account
        # kato_account is the account of this user
        # see get_account_info in KatoHttpClient
        def account_info_success(kato_account):
            # register account
            # cannot set the nickname here because the user may not have given
            # the nickname to the server yet
            account = self._add_kato_account(kato_account, self.irc.nickname)

            # this account is for the current user, so register it specially
            self.account = account

            # process memberships
            deferds = []
            for kato_membership in kato_account.memberships:
                d_org_members = self.kato.get_organization_members(kato_membership.org_id)
                d_org_members.addCallbacks(org_members_success)
                deferds.append(d_org_members)

                d_org_rooms = self.kato.get_rooms(kato_membership.org_id)
                d_org_rooms.addCallbacks(rooms_success)
                deferds.append(d_org_rooms)

            # after all members and rooms have loaded, trigger
            d_loaded = defer.gatherResults(deferds, consumeErrors=True)
            def success(param=None):
                init_success()
            d_loaded.addCallbacks(success, error)

        # login succeeded
        # pre-fetch account information
        def login_success(ignored):
            # defined above; allow access chat-wide
            self.kato = kato

            d_account = self.kato.get_account_info()
            d_account.addCallbacks(account_info_success, error)

        d_login.addCallbacks(login_success, error)
        return d_init

    # disconnects
    # can be called either from a user-initiated disconnect or a lost Kato
    # connection
    def disconnect(self):
        def loggedout(ignored=None):
            print "Closing transport"
            self.irc.transport.loseConnection()
        def handle_error(failure):
            # failed to logout; kill the IRC connection anyways
            print "Failed to close Kato connection."
            self.irc.transport.loseConnection()

        # logout of kato
        if self.kato:
            d = self.kato.logout()
            d.addCallbacks(loggedout, handle_error)
        else:
            loggedout()

    # sends the given message to the given Channel
    def send_message(self, channel, message):
        message, mentions = self._process_irc_mentions(message)
        self.kato.send_message(channel.kato_room, message, mentions)

    # replaces IRC mentions with Kato mention text
    # returns the modified message + a set of account IDs for everyone
    # mentioned
    # an IRC mention is defined as follows:
    # - mention is the first word, or is proceeded by whitespace
    # - mention is the last word, or is followed by a character that is
    #   disallowed in the nickname
    # - the nickname itself may optionally be prepended by an @ character
    def _process_irc_mentions(self, message):
        mentions = set()

        # TODO: limit accounts by those in the organization of the room
        for id, account in self.accounts.iteritems():
            position = 0
            while True:
                position = message.find(account.nickname, position)
                next_char = position + len(account.nickname)

                if position == -1:
                    position = 0
                    break

                # before character
                if position == 0:
                    separated_before = True
                else:
                    # search for leading @, which we want to replace too, so
                    # we don't get @@, since we prepend an @ below
                    if message[position - 1] == "@":
                        position -= 1

                    # require a space before the nick
                    m = SPACES.match(message[position - 1])
                    separated_before = bool(m)

                # after character
                if next_char == len(message):
                    separated_after = True
                else:
                    m = NICKNAME_DISALLOWED.match(message[next_char])
                    separated_after = bool(m)

                if separated_before and separated_after:
                    message = "".join([message[:position], "@", id, message[next_char:]])
                    mentions.add(id)
                    # continue searching after the replaced ID + "@"
                    position = position + 1 + len(id)
                else:
                    # nickname matched, but is part of a bigger word; skip
                    position = next_char

        return message, mentions

    # receives a message in the given Channel from the given Account and sends it to the client
    def receive_message(self, channel, account, message):
        # skip messages sent by the current user
        if account.kato_account.id == self.kato.account_id:
            return

        # skip messages from channels that have not been joined
        if not channel.joined:
            return

        # convert Kato mentions to nicknames
        message = self._process_kato_mentions(message)

        self.irc.privmsg(account.irc_ident(), channel.irc_channel, message)

        # TODO: send read event?

    # replaces kato mentions with the IRC nickname of the account
    # returns a modified message
    def _process_kato_mentions(self, message):
        # TODO: limit accounts by those in the organization of the room
        # TODO: add detection of names, since Kato sometime doesn't do the
        # mentions correctly (see @.:. Skylar .:.)
        for id, account in self.accounts.iteritems():
            message = message.replace("@" + id, account.nickname)

        return message

    # sends a private message to the given Account
    def send_private_message(self, account, message):
        message, mentions = self._process_irc_mentions(message)
        self.kato.send_private_message(account.kato_account, message, mentions)

    # receives a private message from the given Account
    def receive_private_message(self, account, message):
        # skip messages sent by the current user
        if account.kato_account.id == self.kato.account_id:
            return

        # convert Kato mentions to nicknames
        message = self._process_kato_mentions(message)

        self.irc.privmsg(account.irc_ident(), account.nickname, message)

        # TODO: send read event?

    # provides the client with a system message
    # this can be used to report error conditions
    def receive_system_message(self, message):
        self.irc.privmsg(self.irc.SYSTEM_USER,
            self.irc.nickname,
            message)

    # TODO: better error handling
    # returns a Channel object for the given IRC channel name, with prefix,
    # via a deferred
    # if the channel is not valid, then an errback will be sent
    def find_channel_from_ircname(self, irc_channel):
        def synchronous():
            for channel in self.channels:
                if channel.irc_channel == irc_channel:
                    return channel
            else:
                # channel does not exist yet
                raise ValueError("Channel " + irc_channel + " not found")

        return defer.maybeDeferred(synchronous)

    # returns a Channel object for the given Kato room ID, via a deferred
    # if the channel is not valid, then an errback will be sent
    def find_channel_from_katoid(self, room_id):
        def synchronous():
            for channel in self.channels:
                if channel.kato_room and channel.kato_room.id == room_id:
                    return channel
            else:
                raise ValueError("Room ID is not valid")

        return defer.maybeDeferred(synchronous)

    # returns an Account for the given IRC nickname, via a deferred
    # if the account is not valid, then an errback will be sent
    def find_account_from_ircnick(self, nickname):
        def synchronous():
            for id, account in self.accounts.iteritems():
                if account.nickname == nickname:
                    return account
            else:
                raise ValueError("Could not find account with IRC nick: " +
                        nickname)

        return defer.maybeDeferred(synchronous)

    # returns an Account for the given Kato account ID, via a deferred
    # if the account is not valid, then an errback will be sent
    def find_account_from_katoid(self, account_id):
        def synchronous():
            try:
                return self.accounts[account_id]
            except KeyError:
                raise ValueError("Could not find account ID: " + account_id)

        return defer.maybeDeferred(synchronous)

    # adds/updates a kato account
    # updates only affect the kato_account object of the account
    def _add_kato_account(self, kato_account, nickname=None):
        if kato_account.id in self.accounts:
            # update existing account
            existing = self.accounts[kato_account.id]
            existing.kato_account = kato_account
        else:
            # new account
            self.accounts[kato_account.id] = Account(kato_account, nickname)

            # say hello, so that we can recieve and send messages
            self.kato.hello_account(kato_account)

        return self.accounts[kato_account.id]

    # adds/updates a kato room
    def _add_kato_room(self, kato_room):
        for channel in self.channels:
            if channel.kato_room.id == kato_room.id:
                # channel already added; update info
                channel.kato_room = kato_room
                break
        else:
            # channel does not exist yet; create it
            channel = Channel(kato_room)
            self.channels.append(channel)

    # indicates that the user has joined the given IRC channel
    #
    # returns a defer that fires with the Channel on success, or with an
    # errback if the Kato Room could not be joined, either because it does not
    # exist (ValueError) or for network reasons (other)
    def join_channel(self, irc_channel):
        d = defer.Deferred()

        for channel in self.channels:
            if channel.irc_channel == irc_channel:
                # channel already exists
                if channel.joined:
                    # already in the channel; do nothing
                    d.callback(channel)
                    break
                else:
                    # not in the channel yet; enter the channel
                    self.kato.enter_room(channel.kato_room)
                    channel.joined = True
                    d.callback(channel)
                    break
        else:
            # channel does not exist yet
            d.errback(ValueError(irc_channel +
                " does not correspond to a known Kato room."))

        return d

    # leave an IRC channel
    def leave_channel(self, irc_channel):
        print "Leaving", irc_channel
        for channel in self.channels:
            if channel.irc_channel == irc_channel:
                print "Leaving channel", channel
                channel.joined = False
                self.kato.leave_room(channel.kato_room)

        # left the room or room was not found; send the part message

# object that receives and acts upon messages from the Kato client
# kato_<MESSAGE_TYPE> will be called with the message
class KatoMessageReceiver(object):
    # Chat
    chat = None

    def __init__(self, chat):
        self.chat = chat

    # TODO
    #def kato_ANNOUNCE(self, message):
    #    pass

    # check message; used to check the status of the client for a given group
    # usual check sequence:
    #
    # server sends check message
    # {
    #     "ts":1379271141415,
    #     "type":"check",
    #     "group_id":"<GROUP_ID>"
    # }
    #
    # client responds
    # note that the tz_offset is positive for some reason
    # {
    #     "group_id":"<GROUP_ID>",
    #     "type":"presence",
    #     "params":{
    #         "status":"(online|away)",
    #         "tz_offset":<TZ_OFFSET>,
    #         "capabilities":[]
    #     }
    # }
    #
    # server responds with a presence message for the current account
    # see kato_PRESENCE
    # TODO
    #def kato_CHECK(self, message):
    #    pass

    # keep alive message used to check connection status
    # sent every 5 seconds from the client to the server, and the server
    # responses
    #
    # client sends
    # {"type":"keep_alive"}
    #
    # server responds
    # {"ts":1379270870453,"type":"keep_alive"}
    # TODO
    #def kato_KEEP_ALIVE(self, message):
    #    pass

    # TODO
    #def kato_OFF_RECORD(self, message):
    #    pass

    # TODO
    #def kato_OMITTED(self, message):
    #    pass

    # TODO
    #def kato_ON_RECORD(self, message):
    #    pass

    # used to indicate presence of an account, including the current user
    # see kato_CHECK
    #
    # server sends
    # {
    #     "ts":1379271141455,
    #     "type":"presence",
    #     "from":{
    #         "id":"<ACCOUNT_ID>",
    #         "status":"(verified_email|unverified_email)",
    #         "email":"<EMAIL_ADDRESS>",
    #         "name":"<ACCOUNT_NAME>"
    #     },
    #     "group_id":"<GROUP_ID>",
    #     "params":{
    #         "status":"(online|away)",
    #         "tz_offset":<TZ_OFFSET>,
    #         "capabilities":[]
    #     }
    # }
    # TODO
    #def kato_PRESENCE(self, message):
    #    pass

    # indicates that a given message has been read
    #
    # server sends
    # {
    #     "ts":1379272428497,
    #     "type":"read",
    #     "from":{
    #         "id":"<ACCOUNT_ID>",
    #         "status":"(verified_email|unverified_email)",
    #         "email":"<EMAIL_ADDRESS>",
    #         "name":"<NAME>"
    #     },
    #     "room_id":"<ROOM_ID>",
    #     "params":{
    #         "last_ts":1379272416000,
    #         "seq":17,
    #         "diff":0,
    #         "mentioned":false
    #     }
    # }
    def kato_READ(self, message):
        pass

    # TODO
    #def kato_RTC_SIGNAL(self, message):
    #    pass

    # TODO
    #def kato_RTC_START(self, message):
    #    pass

    # TODO
    #def kato_RTC_STOP(self, message):
    #    pass

    # TODO
    #def kato_SILENCE(self, message):
    #    pass

    # a text message
    # {
    #     "ts":1379214315159,
    #     "type":"text",
    #     "from":{
    #         "id":"<ACCOUNT_ID>",
    #         "status":"(verified_email|unverified_email)",
    #         "email":"<EMAIL_ADDRESS>",
    #         "name":"<NAME>"
    #     },
    #     # for a chat room, room_id is a hex string
    #     # for a private message, the lower account ID comes first, followed by the higher accountID
    #     "room_id":"<ROOM_ID>|<<ACCOUNT_ID>-<ACCOUNT_ID>",
    #     "params":{
    #         "data":{
    #             "id":"25d837dc23fb2e1c",
    #             # key not provided if no mentions
    #             "mention_names":{
    #                 "<ACCOUNT_ID>":"<ACCOUNT_NAME>"
    #             }
    #         },
    #         # if a mention, @<NAME> replaced with @<ACCOUNT_ID> in the body
    #         "text":"<MESSAGE_CONTENTS>",
    #         "mentions":["<ACCOUNT_ID>"],
    #         "mentions":[],
    #         "mentioned_everybody":false
    #     },
    #     "seq":1
    # }
    def kato_TEXT(self, message):
        #
        # channel message
        #

        def channel_found(channel):
            account_id = message["from"]["id"]
            d = self.chat.find_account_from_katoid(account_id)

            def sender_found(account):
                text = message["params"]["text"]
                self.chat.receive_message(channel, account, text)

            def sender_not_found(ignored):
                # cannot find the sender; fake it
                # this happens when an integration of some kind (e.g. Github)
                # sends a message; however, Kato doesn't give us permission to
                # fetch Github's info from their servers, so we have to just
                # pass the message along
                kato_account = KatoAccount(account_id,
                        message["from"]["name"],
                        "", # no email
                        message["from"]["status"],
                        [])
                account = Account(kato_account)
                self.chat.receive_message(channel, account, message["params"]["text"])

            d.addCallbacks(sender_found, sender_not_found)

        def channel_not_found(error):
            # TODO: try to find the channel (if it's new), alert the user, etc
            print "Channel not found", error

        #
        # private message
        #

        def priv_account_found(account):
            text = message["params"]["text"]
            self.chat.receive_private_message(account, text)

        def priv_account_not_found(error):
            # TODO: might be a new user; alert the user on failure
            print "Account not found", error

        room_id = message["room_id"]
        if "-" in room_id:
            # private message
            account_id = message["from"]["id"]
            d = self.chat.find_account_from_katoid(account_id)
            d.addCallbacks(priv_account_found, priv_account_not_found)
        else:
            # channel message
            d = self.chat.find_channel_from_katoid(room_id)
            d.addCallbacks(channel_found, channel_not_found)

    # used to indicate that a user is typing in a given room
    # {
    #     # room_id can be in either chat room or private message format
    #     "room_id": "<ROOM_ID>",
    #     "from": {
    #         "name": "<NAME>",
    #         "email": "<EMAIL_ADDRESS>",
    #         "status": "(verified_email|unverified_email)",
    #         "id": "<ACCOUNT_ID>"
    #     },
    #     "type": "typing",
    #     "ts": 1379214313294
    # }
    # TODO
    #def kato_TYPING(self, message):
    #    pass

    # used to indicate that a user is no longer typing in a given room
    # this message is only sent if a user does not send a message
    # {
    #     # room_id can be in either chat room or private message format
    #     "room_id": "<ROOM_ID>",
    #     "from": {
    #         "name": "<NAME>",
    #         "email": "<EMAIL_ADDRESS>",
    #         "status": "(verified_email|unverified_email)",
    #         "id": "<ACCOUNT_ID>"
    #     },
    #     "type": "reset_typing",
    #     "ts": 1379306032396
    # }
    #def kato_RESET_TYPING(self, message):
    #    pass

    # unknown type of message
    def kato_unknown(self, message):
        print "Received unknown message:"
        import pprint
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(message)
