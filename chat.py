# object that manages chat operations and state
#
# all verbs here are from the perspective of the IRC client; for example,
# send_message sends a message (received from IRC) to Kato, and
# receive_message sends a message received from Kato to the local client's IRC
# message
#
# TODO: use a semaphore to prevent multiple operations at once, so messages stay ordered
class Chat(object):
    irc_connection = None

    # not initialized until the IRC connection initializes the client with a
    # user-provided username/password
    kato_client = None

    # list of Channel objects
    #channels = []

    def __init__(self, irc_connection):
        self.irc_connection = irc_connection

    # initializes a Kato connection
    # token should be an email / password combination, separated by a space,
    # or a session ID / session key, also separated by a space
    # session IDs are in hex, so it is possible to distinguish from an email address
    # on error, a message will be provided to the user from the system user,
    # rather than returning an error via this function
    def init_kato(self, token):
        pass

    # sends the given message to the given Channel
    def send_message(self, channel, message):
        pass

    # receives a message from the given Channel and sends it to the client
    def receive_message(self, channel, message):
        pass

    # sends a private message to the given Account
    def send_private_message(self, account, message):
        pass

    # receives a private message from the given Account
    def receive_private_message(self, account, message):
        pass

    # provides the client with a system message
    # this can be used to report error conditions
    def receive_system_message(self, message):
        pass

    # returns a channel object for the given IRC channel name, with prefix,
    # via a deferred
    # if the channel is not valid, then an errback will be sent
    def find_channel_from_ircname(self, channel_name):
        pass

    # returns a channel object for the given Kato room ID, via a deferred
    # if the channel is not valid, then an errback will be sent
    def find_channel_from_katoid(self, room_id):
        pass

    # returns an account for the given IRC nickname, via a deferred
    # if the account is not valid, then an errback will be sent
    def find_account_from_ircnick(self, nickname):
        pass

    # returns an account for the given Kato account ID, via a deferred
    # if the account is not valid, then an errback will be sent
    def find_account_from_katoid(self, account_id):
        pass

class Channel(object):
    # IRC channel name, with the channel leading character
    irc_channel = ""

    # KatoRoom object with which this channel is associated
    kato_room = None

class Account(object):
    # IRC nickname with which this account is associated
    nickname = ""

    # KatoAccount object with which this account is associated
    kato_account = None
