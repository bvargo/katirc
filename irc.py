import socket

from twisted.internet import defer, protocol, task
from twisted.words.protocols import irc
from twisted.python import log

from chat import Chat, KatoMessageReceiver

# period, in seconds, for keep alive calls
KEEP_ALIVE_PERIOD = 30

# protcol instance representing a single IRC connection to this server by a
# single user that is mapped to a Kato session
class IRCConnection(irc.IRC):
    # hostname of the current server
    # initiated on connection
    hostname = socket.getfqdn()

    # encoding used to communicate with the client
    encoding = "utf-8"

    # nickserv user, for system messages
    SYSTEM_USER = 'root!root@services'

    # nickname provided by the user
    nickname = None

    # chat connection
    # initialized in __init__
    chat = None

    # whether the current IRC user has sent a password
    sentPass = False

    # welcome messages; sent after nick
    _welcomeMessages = [
            (irc.RPL_WELCOME, ":connected to " + hostname),
            (irc.RPL_YOURHOST, "Your host is " + hostname +
                ", running version 0.1"),
            (irc.RPL_CREATED,
                ":This server was created on TODO"),
            # <server name> <version> <available user modes>
            # <available channel modes>
            (irc.RPL_MYINFO,
                hostname + " 0.1 w n")
            ]

    def __init__(self):
        self.chat = Chat(self)

    #
    # twisted callbacks
    #

    def connectionMade(self):
        self.keep_alive_timer = task.LoopingCall(self.keep_alive)
        self.keep_alive_timer.start(KEEP_ALIVE_PERIOD)

    def connectionLost(self, reason):
        if self.keep_alive_timer:
            self.keep_alive_timer.stop()
        self.chat.disconnect()

    #
    # override protocol functions
    #

    # modifications:
    # - if a prefix is not specified, then the current server hostname is used
    # - if a to is not specified, then the nickname of the client is used
    def sendMessage(self, command, *args, **kwargs):
        if "prefix" not in kwargs:
            kwargs["prefix"] = self.hostname
        if "to" not in kwargs:
            kwargs["to"] = self.nickname.encode(self.encoding)

        # DEBUG
        print "Sending message", command, kwargs["to"], args, kwargs
        irc.IRC.sendMessage(self, command, kwargs["to"], *args, **kwargs)

    # modifications:
    # - debug logging
    def handleCommand(self, command, prefix, params):
        print "Received:", prefix, command, params
        irc.IRC.handleCommand(self, command, prefix, params)

    #
    # helpers
    #

    def sendMotd(self):
        # creates a message for the motd
        def msg(message):
            return (irc.RPL_MOTD, ":- " + message)

        # header
        messages = [
                (irc.RPL_MOTDSTART,
                    ":- " + self.hostname + " Message of the Day - "),
                msg("Welcome to KatIRC!"),
                msg(""),
                msg("This is an unofficial IRC server for Kato."),
                msg("See https://github.com/bvargo/katirc/."),
                msg(""),
                ]

        # list of available channels
        messages.append(msg("Known Kato Rooms:"))
        for channel in self.chat.channels:
            messages.append(
                    msg("  " + channel.irc_channel + ": " +
                        channel.kato_room.name))

        messages.append((irc.RPL_ENDOFMOTD,
            ":End of MOTD command"))

        # send messages
        for code, text in messages:
            self.sendMessage(code, text)

    #
    # Keep Alive
    #

    def keep_alive(self):
        if self.chat and self.chat.is_connected():
            # allow 3 keep alives as the timeout before we fail the connection
            online = self.chat.keep_alive(KEEP_ALIVE_PERIOD * 3)
            if not online:
                # kato is not online - kill the connection, forcing the IRC
                # user to reconnect
                self.chat.disconnect()

    #
    # IRC command handlers
    #

    # unknown command handler
    def irc_unknown(self, prefix, command, params):
        print "UNKNOWN COMMAND:", command
        print "\tPREFIX:", prefix
        print "\tPARAMS:", params


    # special handler for handles that delegates to irc_MODE_CHANNEL and
    # irc_MODE_USER as appropriate
    def irc_MODE(self, prefix, params):
        # TODO
        pass

    #
    # 3.1 Connection Registration
    #
    #    The commands described here are used to register a connection with an
    #    IRC server as a user as well as to correctly disconnect.
    #
    #    A "PASS" command is not required for a client connection to be
    #    registered, but it MUST precede the latter of the NICK/USER
    #    combination (for a user connection) or the SERVICE command (for a
    #    service connection). The RECOMMENDED order for a client to register
    #    is as follows:
    #
    #                            1. Pass message
    #            2. Nick message                 2. Service message
    #            3. User message
    #
    #    Upon success, the client will receive an RPL_WELCOME (for users) or
    #    RPL_YOURESERVICE (for services) message indicating that the
    #    connection is now registered and known the to the entire IRC network.
    #    The reply message MUST contain the full client identifier upon which
    #    it was registered.
    #

    #
    # 3.1.1 Password message
    #
    #       Command: PASS
    #    Parameters: <password>
    #
    #    The PASS command is used to set a 'connection password'.  The
    #    optional password can and MUST be set before any attempt to register
    #    the connection is made.  Currently this requires that user send a
    #    PASS command before sending the NICK/USER combination.
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS              ERR_ALREADYREGISTRED
    #
    #    Example:
    #
    #            PASS secretpasswordhere
    #
    def irc_PASS(self, prefix, params):
        self.sentPass = True

        if self.chat.is_connected():
            # password already set, since we have a kato connection; cannot reset
            self.sendMessage(irc.ERR_ALREADYREGISTRED,
                    ":Unauthorized command (already connected)")
        else:
            if len(params) == 0:
                # no password given
                self.sendMessage(irc.ERR_NEEDMOREPARAMS,
                        "PASS :Not enough parameters")
            else:
                # login to kato
                password = " ".join(params)
                d_login = self.chat.init_kato(password)

                def login_success(ignored):
                    # send MOTD
                    self.sendMotd()

                    # send welcome messages
                    for code, text in self._welcomeMessages:
                        self.sendMessage(code, text)

                def login_error(error):
                    # chat takes care of sending the appropriate error
                    # messages
                    print "Failure to authenticate for", self.nickname

                d_login.addCallbacks(login_success, login_error)

    #
    # 3.1.2 Nick message
    #
    #
    #       Command: NICK
    #    Parameters: <nickname>
    #
    #    NICK command is used to give user a nickname or change the existing
    #    one.
    #
    #    Numeric Replies:
    #
    #            ERR_NONICKNAMEGIVEN             ERR_ERRONEUSNICKNAME
    #            ERR_NICKNAMEINUSE               ERR_NICKCOLLISION
    #            ERR_UNAVAILRESOURCE             ERR_RESTRICTED
    #
    #    Examples:
    #
    #    NICK Wiz                ; Introducing new nick "Wiz" if session is
    #                            still unregistered, or user changing his
    #                            nickname to "Wiz"
    #
    #    :WiZ!jto@tolsun.oulu.fi NICK Kilroy
    #                            ; Server telling that WiZ changed his
    #                            nickname to Kilroy.
    #
    def irc_NICK(self, prefix, params):
        if len(params) != 1:
            self.sendMessage(irc.ERR_NONICKNAMEGIVEN,
                    ":No nickname given")
            return

        # decode nickname
        try:
            nickname = params[0].decode(self.encoding)
        except UnicodeDecodeError:
            self.sendMessage(irc.ERR_ERRONEUSNICKNAME,
                    params[0] + " :Erroneous nickname")

        self.nickname = nickname

        if not self.sentPass:
           self.privmsg(self.SYSTEM_USER,
                   nickname,
                   "Please setup your IRC client to send your Kato username " +
                   "and password as your IRC password, separated by a space.")
           self.transport.loseConnection()

    #
    # 3.1.3 User message
    #
    #       Command: USER
    #    Parameters: <user> <mode> <unused> <realname>
    #
    #    The USER command is used at the beginning of connection to specify
    #    the username, hostname and realname of a new user.
    #
    #    The <mode> parameter should be a numeric, and can be used to
    #    automatically set user modes when registering with the server.  This
    #    parameter is a bitmask, with only 2 bits having any signification: if
    #    the bit 2 is set, the user mode 'w' will be set and if the bit 3 is
    #    set, the user mode 'i' will be set.  (See Section 3.1.5 "User
    #    Modes").
    #
    #    The <realname> may contain space characters.
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS              ERR_ALREADYREGISTRED
    #
    #    Example:
    #
    #    USER guest 0 * :Ronnie Reagan   ; User registering themselves with a
    #                                    username of "guest" and real name
    #                                    "Ronnie Reagan".
    #
    #    USER guest 8 * :Ronnie Reagan   ; User registering themselves with a
    #                                    username of "guest" and real name
    #                                    "Ronnie Reagan", and asking to be set
    #                                    invisible.
    #
    def irc_USER(self, prefix, params):
        # nothing of use here, for now
        pass

    #
    # 3.1.4 Oper message
    #
    #       Command: OPER
    #    Parameters: <name> <password>
    #
    #    A normal user uses the OPER command to obtain operator privileges.
    #    The combination of <name> and <password> are REQUIRED to gain
    #    Operator privileges.  Upon success, the user will receive a MODE
    #    message (see section 3.1.5) indicating the new user modes.
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS              RPL_YOUREOPER
    #            ERR_NOOPERHOST                  ERR_PASSWDMISMATCH
    #
    #    Example:
    #
    #    OPER foo bar                    ; Attempt to register as an operator
    #                                    using a username of "foo" and "bar"
    #                                    as the password.
    #

    # def irc_OPER(self, prefix, params):
        # TODO

    #
    # 3.1.5 User mode message
    #
    #       Command: MODE
    #    Parameters: <nickname>
    #                *( ( "+" / "-" ) *( "i" / "w" / "o" / "O" / "r" ) )
    #
    #    The user MODE's are typically changes which affect either how the
    #    client is seen by others or what 'extra' messages the client is sent.
    #
    #    A user MODE command MUST only be accepted if both the sender of the
    #    message and the nickname given as a parameter are both the same.  If
    #    no other parameter is given, then the server will return the current
    #    settings for the nick.
    #
    #       The available modes are as follows:
    #
    #            a - user is flagged as away;
    #            i - marks a users as invisible;
    #            w - user receives wallops;
    #            r - restricted user connection;
    #            o - operator flag;
    #            O - local operator flag;
    #            s - marks a user for receipt of server notices.
    #
    #    Additional modes may be available later on.
    #
    #    The flag 'a' SHALL NOT be toggled by the user using the MODE command,
    #    instead use of the AWAY command is REQUIRED.
    #
    #    If a user attempts to make themselves an operator using the "+o" or
    #    "+O" flag, the attempt SHOULD be ignored as users could bypass the
    #    authentication mechanisms of the OPER command.  There is no
    #    restriction, however, on anyone `deopping' themselves (using "-o" or
    #    "-O").
    #
    #    On the other hand, if a user attempts to make themselves unrestricted
    #    using the "-r" flag, the attempt SHOULD be ignored.  There is no
    #    restriction, however, on anyone `deopping' themselves (using "+r").
    #    This flag is typically set by the server upon connection for
    #    administrative reasons.  While the restrictions imposed are left up
    #    to the implementation, it is typical that a restricted user not be
    #    allowed to change nicknames, nor make use of the channel operator
    #    status on channels.
    #
    #    The flag 's' is obsolete but MAY still be used.
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS              ERR_USERSDONTMATCH
    #            ERR_UMODEUNKNOWNFLAG            RPL_UMODEIS
    #
    #    Examples:
    #
    #    MODE WiZ -w                     ; Command by WiZ to turn off
    #                                    reception of WALLOPS messages.
    #
    #    MODE Angel +i                   ; Command from Angel to make herself
    #                                    invisible.
    #
    #    MODE WiZ -o                     ; WiZ 'deopping' (removing operator
    #                                    status).
    #
    # note the special method name
    # irc_MODE will dispatch to this method upon detection of a user mode
    # message, since the MODE command overlaps with irc_MODE_CHANNEL

    # def irc_MODE_USER(self, prefix, params):
        # TODO

    #
    # 3.1.6 Service message
    #
    #       Command: SERVICE
    #    Parameters: <nickname> <reserved> <distribution> <type>
    #                <reserved> <info>
    #
    #    The SERVICE command to register a new service.  Command parameters
    #    specify the service nickname, distribution, type and info of a new
    #    service.
    #
    #    The <distribution> parameter is used to specify the visibility of a
    #    service.  The service may only be known to servers which have a name
    #    matching the distribution.  For a matching server to have knowledge
    #    of the service, the network path between that server and the server
    #    on which the service is connected MUST be composed of servers which
    #    names all match the mask.
    #
    #    The <type> parameter is currently reserved for future usage.
    #
    #    Numeric Replies:
    #
    #            ERR_ALREADYREGISTRED            ERR_NEEDMOREPARAMS
    #            ERR_ERRONEUSNICKNAME
    #            RPL_YOURESERVICE                RPL_YOURHOST
    #            RPL_MYINFO
    #
    #    Example:
    #
    #    SERVICE dict * *.fr 0 0 :French Dictionary ; Service registering
    #                                    itself with a name of "dict".  This
    #                                    service will only be available on
    #                                    servers which name matches "*.fr".
    #

    # def irc_SERVICE(self, prefix, params):
        # TODO; not implemented in example

    #
    # 3.1.7 Quit
    #
    #       Command: QUIT
    #    Parameters: [ <Quit Message> ]
    #
    #    A client session is terminated with a quit message.  The server
    #    acknowledges this by sending an ERROR message to the client.
    #
    #    Numeric Replies:
    #
    #            None.
    #
    #    Example:
    #
    #    QUIT :Gone to have lunch        ; Preferred message format.
    #
    #    :syrk!kalt@millennium.stealth.net QUIT :Gone to have lunch ; User
    #                                    syrk has quit IRC to have lunch.
    #
    def irc_QUIT(self, prefix, params):
        self.chat.disconnect()

    #
    # 3.1.8 Squit
    #
    #       Command: SQUIT
    #    Parameters: <server> <comment>
    #
    #    The SQUIT command is available only to operators.  It is used to
    #    disconnect server links.  Also servers can generate SQUIT messages on
    #    error conditions.  A SQUIT message may also target a remote server
    #    connection.  In this case, the SQUIT message will simply be sent to
    #    the remote server without affecting the servers in between the
    #    operator and the remote server.
    #
    #    The <comment> SHOULD be supplied by all operators who execute a SQUIT
    #    for a remote server.  The server ordered to disconnect its peer
    #    generates a WALLOPS message with <comment> included, so that other
    #    users may be aware of the reason of this action.
    #
    #    Numeric replies:
    #
    #            ERR_NOPRIVILEGES                ERR_NOSUCHSERVER
    #            ERR_NEEDMOREPARAMS
    #
    #    Examples:
    #
    #    SQUIT tolsun.oulu.fi :Bad Link ?  ; Command to uplink of the server
    #                                    tolson.oulu.fi to terminate its
    #                                    connection with comment "Bad Link".
    #
    #    :Trillian SQUIT cm22.eng.umd.edu :Server out of control ; Command
    #                                    from Trillian from to disconnect
    #                                    "cm22.eng.umd.edu" from the net with
    #                                    comment "Server out of control".
    #

    # def irc_SQUIT(self, prefix, params):
        # TODO - not implemented in example

#
# 3.2 Channel operations
#
#    This group of messages is concerned with manipulating channels, their
#    properties (channel modes), and their contents (typically users).
#    For this reason, these messages SHALL NOT be made available to
#    services.
#
#    All of these messages are requests which will or will not be granted
#    by the server.  The server MUST send a reply informing the user
#    whether the request was granted, denied or generated an error.  When
#    the server grants the request, the message is typically sent back
#    (eventually reformatted) to the user with the prefix set to the user
#    itself.
#
#    The rules governing how channels are managed are enforced by the
#    servers.  These rules are beyond the scope of this document.  More
#    details are found in "Internet Relay Chat: Channel Management" [IRC-
#    CHAN].
#

    #
    # 3.2.1 Join message
    #
    #       Command: JOIN
    #    Parameters: ( <channel> *( "," <channel> ) [ <key> *( "," <key> ) ] )
    #                / "0"
    #
    #    The JOIN command is used by a user to request to start listening to
    #    the specific channel.  Servers MUST be able to parse arguments in the
    #    form of a list of target, but SHOULD NOT use lists when sending JOIN
    #    messages to clients.
    #
    #    Once a user has joined a channel, he receives information about
    #    all commands his server receives affecting the channel.  This
    #    includes JOIN, MODE, KICK, PART, QUIT and of course PRIVMSG/NOTICE.
    #    This allows channel members to keep track of the other channel
    #    members, as well as channel modes.
    #
    #    If a JOIN is successful, the user receives a JOIN message as
    #    confirmation and is then sent the channel's topic (using RPL_TOPIC) and
    #    the list of users who are on the channel (using RPL_NAMREPLY), which
    #    MUST include the user joining.
    #
    #    Note that this message accepts a special argument ("0"), which is
    #    a special request to leave all channels the user is currently a member
    #    of.  The server will process this message as if the user had sent
    #    a PART command (See Section 3.2.2) for each channel he is a member
    #    of.
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS              ERR_BANNEDFROMCHAN
    #            ERR_INVITEONLYCHAN              ERR_BADCHANNELKEY
    #            ERR_CHANNELISFULL               ERR_BADCHANMASK
    #            ERR_NOSUCHCHANNEL               ERR_TOOMANYCHANNELS
    #            ERR_TOOMANYTARGETS              ERR_UNAVAILRESOURCE
    #            RPL_TOPIC
    #
    #    Examples:
    #
    #    JOIN #foobar                    ; Command to join channel #foobar.
    #
    #    JOIN &foo fubar                 ; Command to join channel &foo using
    #                                    key "fubar".
    #
    #    JOIN #foo,&bar fubar            ; Command to join channel #foo using
    #                                    key "fubar" and &bar using no key.
    #
    #    JOIN #foo,#bar fubar,foobar     ; Command to join channel #foo using
    #                                    key "fubar", and channel #bar using
    #                                    key "foobar".
    #
    #    JOIN #foo,#bar                  ; Command to join channels #foo and
    #                                    #bar.
    #
    #    JOIN 0                          ; Leave all currently joined
    #                                    channels.
    #
    #    :WiZ!jto@tolsun.oulu.fi JOIN #Twilight_zone ; JOIN message from WiZ
    #                                    on channel #Twilight_zone
    #
    # TODO: handling of join messages for other users
    def irc_JOIN(self, prefix, params):
        # TODO: better error handling
        if len(params) == 0:
            return

        if params[0] == "0":
            # TODO: leave all
            return

        channel_names = params[0].split(",")
        for channel_name in channel_names:
            def joined(channel):
                # send the join message
                self.join(self.chat.account.irc_ident(), channel_name)

                # send the topic
                self.topic(self.nickname, channel_name, channel.kato_room.name)

                # send the users in the channel
                # for Kato, this is everyone in the organization
                nicknames = []
                for id, account in self.chat.accounts.iteritems():
                    for membership in account.kato_account.memberships:
                        if membership.org_id == channel.kato_room.org_id:
                            nicknames.append(account.nickname)

                self.names(self.nickname, channel_name, nicknames)

            def error(failure):
                value_error = failure.check(ValueError)
                if value_error:
                    self.sendMessage(irc.ERR_NOSUCHCHANNEL,
                            channel_name + " :No such channel")
                else:
                    self.sendMessage(irc.ERR_UNAVAILRESOURCE,
                            channel_name +
                            " :Channel is temporarily unavailable")

            d = self.chat.join_channel(channel_name)
            d.addCallbacks(joined, error)

    #
    # 3.2.2 Part message
    #
    #       Command: PART
    #    Parameters: <channel> *( "," <channel> ) [ <Part Message> ]
    #
    #    The PART command causes the user sending the message to be removed
    #    from the list of active members for all given channels listed in the
    #    parameter string.  If a "Part Message" is given, this will be sent
    #    instead of the default message, the nickname.  This request is always
    #    granted by the server.
    #
    #    Servers MUST be able to parse arguments in the form of a list of
    #    target, but SHOULD NOT use lists when sending PART messages to
    #    clients.
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS              ERR_NOSUCHCHANNEL
    #            ERR_NOTONCHANNEL
    #
    #    Examples:
    #
    #    PART #twilight_zone             ; Command to leave channel
    #                                    "#twilight_zone"
    #
    #    PART #oz-ops,&group5            ; Command to leave both channels
    #                                    "&group5" and "#oz-ops".
    #
    #    :WiZ!jto@tolsun.oulu.fi PART #playzone :I lost
    #                                    ; User WiZ leaving channel
    #                                    "#playzone" with the message "I
    #                                    lost".
    #
    def irc_PART(self, prefix, params):
        if len(params) == 0:
            self.sendMessage(irc.ERR_ALREADYREGISTRED,
                    ":Needs more parameters")

        # ignore part message

        channel_names = params[0].split(",")
        for channel_name in channel_names:
            # leave the room
            self.chat.leave_channel(channel_name)

            # send part message
            self.part(self.chat.account.irc_ident(), channel_name)

    #
    # 3.2.3 Channel mode message
    #
    #       Command: MODE
    #    Parameters: <channel> *( ( "-" / "+" ) *<modes> *<modeparams> )
    #
    #    The MODE command is provided so that users may query and change the
    #    characteristics of a channel.  For more details on available modes
    #    and their uses, see "Internet Relay Chat: Channel Management" [IRC-
    #    CHAN].  Note that there is a maximum limit of three (3) changes per
    #    command for modes that take a parameter.
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS              ERR_KEYSET
    #            ERR_NOCHANMODES                 ERR_CHANOPRIVSNEEDED
    #            ERR_USERNOTINCHANNEL            ERR_UNKNOWNMODE
    #            RPL_CHANNELMODEIS
    #            RPL_BANLIST                     RPL_ENDOFBANLIST
    #            RPL_EXCEPTLIST                  RPL_ENDOFEXCEPTLIST
    #            RPL_INVITELIST                  RPL_ENDOFINVITELIST
    #            RPL_UNIQOPIS
    #
    #    The following examples are given to help understanding the syntax of
    #    the MODE command, but refer to modes defined in "Internet Relay Chat:
    #    Channel Management" [IRC-CHAN].
    #
    #    Examples:
    #
    #    MODE #Finnish +imI *!*@*.fi     ; Command to make #Finnish channel
    #                                    moderated and 'invite-only' with user
    #                                    with a hostname matching *.fi
    #                                    automatically invited.
    #
    #    MODE #Finnish +o Kilroy         ; Command to give 'chanop' privileges
    #                                    to Kilroy on channel #Finnish.
    #
    #    MODE #Finnish +v Wiz            ; Command to allow WiZ to speak on
    #                                    #Finnish.
    #
    #    MODE #Fins -s                   ; Command to remove 'secret' flag
    #                                    from channel #Fins.
    #
    #    MODE #42 +k oulu                ; Command to set the channel key to
    #                                    "oulu".
    #
    #    MODE #42 -k oulu                ; Command to remove the "oulu"
    #                                    channel key on channel "#42".
    #
    #    MODE #eu-opers +l 10            ; Command to set the limit for the
    #                                    number of users on channel
    #                                    "#eu-opers" to 10.
    #
    #    :WiZ!jto@tolsun.oulu.fi MODE #eu-opers -l
    #                                    ; User "WiZ" removing the limit for
    #                                    the number of users on channel "#eu-
    #                                    opers".
    #
    #    MODE &oulu +b                   ; Command to list ban masks set for
    #                                    the channel "&oulu".
    #
    #    MODE &oulu +b *!*@*             ; Command to prevent all users from
    #                                    joining.
    #
    #    MODE &oulu +b *!*@*.edu +e *!*@*.bu.edu
    #                                    ; Command to prevent any user from a
    #                                    hostname matching *.edu from joining,
    #                                    except if matching *.bu.edu
    #
    #    MODE #bu +be *!*@*.edu *!*@*.bu.edu
    #                                    ; Comment to prevent any user from a
    #                                    hostname matching *.edu from joining,
    #                                    except if matching *.bu.edu
    #
    #    MODE #meditation e              ; Command to list exception masks set
    #                                    for the channel "#meditation".
    #
    #    MODE #meditation I              ; Command to list invitations masks
    #                                    set for the channel "#meditation".
    #
    #    MODE !12345ircd O               ; Command to ask who the channel
    #                                    creator for "!12345ircd" is
    #
    # note the special method name
    # irc_MODE will dispatch to this method upon detection of a channel mode
    # message, since the MODE command overlaps with irc_MODE_USER

    # def irc_MODE_CHANNEL(self, prefix, params):
        # TODO

    #
    # 3.2.4 Topic message
    #
    #       Command: TOPIC
    #    Parameters: <channel> [ <topic> ]
    #
    #    The TOPIC command is used to change or view the topic of a channel.
    #    The topic for channel <channel> is returned if there is no <topic>
    #    given.  If the <topic> parameter is present, the topic for that
    #    channel will be changed, if this action is allowed for the user
    #    requesting it.  If the <topic> parameter is an empty string, the
    #    topic for that channel will be removed.
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS              ERR_NOTONCHANNEL
    #            RPL_NOTOPIC                     RPL_TOPIC
    #            ERR_CHANOPRIVSNEEDED            ERR_NOCHANMODES
    #
    #    Examples:
    #
    #    :WiZ!jto@tolsun.oulu.fi TOPIC #test :New topic ; User Wiz setting the
    #                                    topic.
    #
    #    TOPIC #test :another topic      ; Command to set the topic on #test
    #                                    to "another topic".
    #
    #    TOPIC #test :                   ; Command to clear the topic on
    #                                    #test.
    #
    #    TOPIC #test                     ; Command to check the topic for
    #                                    #test.
    #

    # def irc_TOPIC(self, prefix, params):
        # TODO

    #
    # 3.2.5 Names message
    #
    #       Command: NAMES
    #    Parameters: [ <channel> *( "," <channel> ) [ <target> ] ]
    #
    #    By using the NAMES command, a user can list all nicknames that are
    #    visible to him. For more details on what is visible and what is not,
    #    see "Internet Relay Chat: Channel Management" [IRC-CHAN].  The
    #    <channel> parameter specifies which channel(s) to return information
    #    about.  There is no error reply for bad channel names.
    #
    #    If no <channel> parameter is given, a list of all channels and their
    #    occupants is returned.  At the end of this list, a list of users who
    #    are visible but either not on any channel or not on a visible channel
    #    are listed as being on `channel' "*".
    #
    #    If the <target> parameter is specified, the request is forwarded to
    #    that server which will generate the reply.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numerics:
    #
    #            ERR_TOOMANYMATCHES              ERR_NOSUCHSERVER
    #            RPL_NAMREPLY                    RPL_ENDOFNAMES
    #
    #    Examples:
    #
    #    NAMES #twilight_zone,#42        ; Command to list visible users on
    #                                    #twilight_zone and #42
    #
    #    NAMES                           ; Command to list all visible
    #                                    channels and users
    #

    # def irc_NAMES(self, prefix, params):
        # TODO

    #
    # 3.2.6 List message
    #
    #       Command: LIST
    #    Parameters: [ <channel> *( "," <channel> ) [ <target> ] ]
    #
    #    The list command is used to list channels and their topics.  If the
    #    <channel> parameter is used, only the status of that channel is
    #    displayed.
    #
    #    If the <target> parameter is specified, the request is forwarded to
    #    that server which will generate the reply.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numeric Replies:
    #
    #            ERR_TOOMANYMATCHES              ERR_NOSUCHSERVER
    #            RPL_LIST                        RPL_LISTEND
    #
    #    Examples:
    #
    #    LIST                            ; Command to list all channels.
    #
    #    LIST #twilight_zone,#42         ; Command to list channels
    #                                    #twilight_zone and #42
    #

    # def irc_LIST(self, prefix, params):
        # TODO

    #
    # 3.2.7 Invite message
    #
    #       Command: INVITE
    #    Parameters: <nickname> <channel>
    #
    #    The INVITE command is used to invite a user to a channel.  The
    #    parameter <nickname> is the nickname of the person to be invited to
    #    the target channel <channel>.  There is no requirement that the
    #    channel the target user is being invited to must exist or be a valid
    #    channel.  However, if the channel exists, only members of the channel
    #    are allowed to invite other users.  When the channel has invite-only
    #    flag set, only channel operators may issue INVITE command.
    #
    #    Only the user inviting and the user being invited will receive
    #    notification of the invitation.  Other channel members are not
    #    notified.  (This is unlike the MODE changes, and is occasionally the
    #    source of trouble for users.)
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS              ERR_NOSUCHNICK
    #            ERR_NOTONCHANNEL                ERR_USERONCHANNEL
    #            ERR_CHANOPRIVSNEEDED
    #            RPL_INVITING                    RPL_AWAY
    #
    #    Examples:
    #
    #    :Angel!wings@irc.org INVITE Wiz #Dust
    #
    #                                    ; Message to WiZ when he has been
    #                                    invited by user Angel to channel
    #                                    #Dust
    #
    #    INVITE Wiz #Twilight_Zone       ; Command to invite WiZ to
    #                                    #Twilight_zone
    #

    # def irc_INVITE(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.2.8 Kick command
    #
    #       Command: KICK
    #    Parameters: <channel> *( "," <channel> ) <user> *( "," <user> )
    #                [<comment>]
    #
    #    The KICK command can be used to request the forced removal of a user
    #    from a channel.  It causes the <user> to PART from the <channel> by
    #    force.  For the message to be syntactically correct, there MUST be
    #    either one channel parameter and multiple user parameter, or as many
    #    channel parameters as there are user parameters.  If a "comment" is
    #    given, this will be sent instead of the default message, the nickname
    #    of the user issuing the KICK.
    #
    #    The server MUST NOT send KICK messages with multiple channels or
    #    users to clients.  This is necessarily to maintain backward
    #    compatibility with old client software.
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS              ERR_NOSUCHCHANNEL
    #            ERR_BADCHANMASK                 ERR_CHANOPRIVSNEEDED
    #            ERR_USERNOTINCHANNEL            ERR_NOTONCHANNEL
    #
    #    Examples:
    #
    #    KICK &Melbourne Matthew         ; Command to kick Matthew from
    #                                    &Melbourne
    #
    #    KICK #Finnish John :Speaking English
    #                                    ; Command to kick John from #Finnish
    #                                    using "Speaking English" as the
    #                                    reason (comment).
    #
    #    :WiZ!jto@tolsun.oulu.fi KICK #Finnish John
    #                                    ; KICK message on channel #Finnish
    #                                    from WiZ to remove John from channel
    #

    # def irc_KICK(self, prefix, params):
        # TODO - not implemented in example

#
# 3.3 Sending messages
#
#
#   The main purpose of the IRC protocol is to provide a base for clients
#   to communicate with each other.  PRIVMSG, NOTICE and SQUERY
#   (described in Section 3.5 on Service Query and Commands) are the only
#   messages available which actually perform delivery of a text message
#   from one client to another - the rest just make it possible and try
#   to ensure it happens in a reliable and structured manner.
#

    #
    # 3.3.1 Private messages
    #
    #       Command: PRIVMSG
    #    Parameters: <msgtarget> <text to be sent>
    #
    #    PRIVMSG is used to send private messages between users, as well as to
    #    send messages to channels.  <msgtarget> is usually the nickname of
    #    the recipient of the message, or a channel name.
    #
    #    The <msgtarget> parameter may also be a host mask (#<mask>) or server
    #    mask ($<mask>).  In both cases the server will only send the PRIVMSG
    #    to those who have a server or host matching the mask.  The mask MUST
    #    have at least 1 (one) "." in it and no wildcards following the last
    #    ".".  This requirement exists to prevent people sending messages to
    #    "#*" or "$*", which would broadcast to all users.  Wildcards are the
    #    '*' and '?'  characters.  This extension to the PRIVMSG command is
    #    only available to operators.
    #
    #    Numeric Replies:
    #
    #            ERR_NORECIPIENT                 ERR_NOTEXTTOSEND
    #            ERR_CANNOTSENDTOCHAN            ERR_NOTOPLEVEL
    #            ERR_WILDTOPLEVEL                ERR_TOOMANYTARGETS
    #            ERR_NOSUCHNICK
    #            RPL_AWAY
    #
    #    Examples:
    #
    #    :Angel!wings@irc.org PRIVMSG Wiz :Are you receiving this message ?
    #                                    ; Message from Angel to Wiz.
    #
    #    PRIVMSG Angel :yes I'm receiving it !
    #                                    ; Command to send a message to Angel.
    #
    #    PRIVMSG jto@tolsun.oulu.fi :Hello !
    #                                    ; Command to send a message to a user
    #                                    on server tolsun.oulu.fi with
    #                                    username of "jto".
    #
    #    PRIVMSG kalt%millennium.stealth.net@irc.stealth.net :Are you a frog?
    #                                    ; Message to a user on server
    #                                    irc.stealth.net with username of
    #                                    "kalt", and connected from the host
    #                                    millennium.stealth.net.
    #
    #    PRIVMSG kalt%millennium.stealth.net :Do you like cheese?
    #                                    ; Message to a user on the local
    #                                    server with username of "kalt", and
    #                                    connected from the host
    #                                    millennium.stealth.net.
    #
    #    PRIVMSG Wiz!jto@tolsun.oulu.fi :Hello !
    #                                    ; Message to the user with nickname
    #                                    Wiz who is connected from the host
    #                                    tolsun.oulu.fi and has the username
    #                                    "jto".
    #
    #    PRIVMSG $*.fi :Server tolsun.oulu.fi rebooting.
    #                                    ; Message to everyone on a server
    #                                    which has a name matching *.fi.
    #
    #    PRIVMSG #*.edu :NSFNet is undergoing work, expect interruptions
    #                                    ; Message to all users who come from
    #                                    a host which has a name matching
    #                                    *.edu.
    #
    # TODO: better error handling
    # - lack of wild cards
    # - network failures
    def irc_PRIVMSG(self, prefix, params):
        # TODO: better error handling
        if len(params) != 2:
            return

        irc_channel = params[0]
        message = params[1].decode("utf-8")

        #
        # channel message
        #

        def channel_found(channel):
            self.chat.send_message(channel, message)

        def channel_not_found(failure):
            # TODO
            print "Could not find channel", irc_channel, failure

        #
        # private message
        #

        def priv_account_found(account):
            self.chat.send_private_message(account, message)

        def priv_account_not_found(failure):
            # TODO
            print "Could not find nick", irc_channel, failure

        if irc_channel[0] == "#":
            # channel message
            d = self.chat.find_channel_from_ircname(irc_channel)
            d.addCallbacks(channel_found, channel_not_found)
        else:
            # private message
            d = self.chat.find_account_from_ircnick(irc_channel)
            d.addCallbacks(priv_account_found, priv_account_not_found)

    #
    # 3.3.2 Notice
    #
    #       Command: NOTICE
    #    Parameters: <msgtarget> <text>
    #
    #    The NOTICE command is used similarly to PRIVMSG.  The difference
    #    between NOTICE and PRIVMSG is that automatic replies MUST NEVER be
    #    sent in response to a NOTICE message.  This rule applies to servers
    #    too - they MUST NOT send any error reply back to the client on
    #    receipt of a notice.  The object of this rule is to avoid loops
    #    between clients automatically sending something in response to
    #    something it received.
    #
    #    This command is available to services as well as users.
    #
    #    This is typically used by services, and automatons (clients with
    #    either an AI or other interactive program controlling their actions).
    #
    #    See PRIVMSG for more details on replies and examples.
    #
    def irc_NOTICE(self, prefix, params):
        if len(params) >= 2:
            nick = params[0]
            message = params[1]
            log.msg("NOTICE from " + nick + ": " + message)

#
# 3.4 Server queries and commands
#
#    The server query group of commands has been designed to return
#    information about any server which is connected to the network.
#
#    In these queries, where a parameter appears as <target>, wildcard
#    masks are usually valid.  For each parameter, however, only one query
#    and set of replies is to be generated.  In most cases, if a nickname
#    is given, it will mean the server to which the user is connected.
#
#    These messages typically have little value for services, it is
#    therefore RECOMMENDED to forbid services from using them.
#

    #
    # 3.4.1 Motd message
    #
    #       Command: MOTD
    #    Parameters: [ <target> ]
    #
    #    The MOTD command is used to get the "Message Of The Day" of the given
    #    server, or current server if <target> is omitted.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numeric Replies:
    #            RPL_MOTDSTART                   RPL_MOTD
    #            RPL_ENDOFMOTD                   ERR_NOMOTD
    #

    # def irc_MOTD(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.4.2 Lusers message
    #
    #       Command: LUSERS
    #    Parameters: [ <mask> [ <target> ] ]
    #
    #    The LUSERS command is used to get statistics about the size of the
    #    IRC network.  If no parameter is given, the reply will be about the
    #    whole net.  If a <mask> is specified, then the reply will only
    #
    #    concern the part of the network formed by the servers matching the
    #    mask.  Finally, if the <target> parameter is specified, the request
    #    is forwarded to that server which will generate the reply.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numeric Replies:
    #
    #            RPL_LUSERCLIENT                 RPL_LUSEROP
    #            RPL_LUSERUNKOWN                 RPL_LUSERCHANNELS
    #            RPL_LUSERME                     ERR_NOSUCHSERVER
    #

    # def irc_LUSERS(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.4.3 Version message
    #
    #       Command: VERSION
    #    Parameters: [ <target> ]
    #
    #    The VERSION command is used to query the version of the server
    #    program.  An optional parameter <target> is used to query the version
    #    of the server program which a client is not directly connected to.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER                RPL_VERSION
    #
    #    Examples:
    #
    #    VERSION tolsun.oulu.fi          ; Command to check the version of
    #                                    server "tolsun.oulu.fi".
    #

    # def irc_VERSION(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.4.4 Stats message
    #
    #       Command: STATS
    #    Parameters: [ <query> [ <target> ] ]
    #
    #    The stats command is used to query statistics of certain server.  If
    #    <query> parameter is omitted, only the end of stats reply is sent
    #    back.
    #
    #    A query may be given for any single letter which is only checked by
    #    the destination server and is otherwise passed on by intermediate
    #    servers, ignored and unaltered.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Except for the ones below, the list of valid queries is
    #    implementation dependent.  The standard queries below SHOULD be
    #    supported by the server:
    #
    #             l - returns a list of the server's connections, showing how
    #                 long each connection has been established and the
    #                 traffic over that connection in Kbytes and messages for
    #                 each direction;
    #             m - returns the usage count for each of commands supported
    #                 by the server; commands for which the usage count is
    #                 zero MAY be omitted;
    #             o - returns a list of configured privileged users,
    #                 operators;
    #             u - returns a string showing how long the server has been
    #                 up.
    #
    #    It is also RECOMMENDED that client and server access configuration be
    #    published this way.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER
    #            RPL_STATSLINKINFO                RPL_STATSUPTIME
    #            RPL_STATSCOMMANDS                RPL_STATSOLINE
    #            RPL_ENDOFSTATS
    #
    #    Examples:
    #
    #    STATS m                         ; Command to check the command usage
    #                                    for the server you are connected to
    #

    # def irc_STATS(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.4.5 Links message
    #
    #       Command: LINKS
    #    Parameters: [ [ <remote server> ] <server mask> ]
    #
    #    With LINKS, a user can list all servernames, which are known by the
    #    server answering the query.  The returned list of servers MUST match
    #    the mask, or if no mask is given, the full list is returned.
    #
    #    If <remote server> is given in addition to <server mask>, the LINKS
    #    command is forwarded to the first server found that matches that name
    #    (if any), and that server is then required to answer the query.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER
    #            RPL_LINKS                        RPL_ENDOFLINKS
    #
    #    Examples:
    #
    #    LINKS *.au                      ; Command to list all servers which
    #                                    have a name that matches *.au;
    #
    #    LINKS *.edu *.bu.edu            ; Command to list servers matching
    #                                    *.bu.edu as seen by the first server
    #                                    matching *.edu.
    #

    # def irc_LINKS(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.4.6 Time message
    #
    #       Command: TIME
    #    Parameters: [ <target> ]
    #
    #    The time command is used to query local time from the specified
    #    server. If the <target> parameter is not given, the server receiving
    #    the command must reply to the query.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER              RPL_TIME
    #
    #    Examples:
    #    TIME tolsun.oulu.fi             ; check the time on the server
    #                                    "tolson.oulu.fi"
    #

    # def irc_TIME(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.4.7 Connect message
    #
    #       Command: CONNECT
    #    Parameters: <target server> <port> [ <remote server> ]
    #
    #    The CONNECT command can be used to request a server to try to
    #    establish a new connection to another server immediately.  CONNECT is
    #    a privileged command and SHOULD be available only to IRC Operators.
    #    If a <remote server> is given and its mask doesn't match name of the
    #    parsing server, the CONNECT attempt is sent to the first match of
    #    remote server. Otherwise the CONNECT attempt is made by the server
    #    processing the request.
    #
    #    The server receiving a remote CONNECT command SHOULD generate a
    #    WALLOPS message describing the source and target of the request.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER              ERR_NOPRIVILEGES
    #            ERR_NEEDMOREPARAMS
    #
    #    Examples:
    #
    #    CONNECT tolsun.oulu.fi 6667     ; Command to attempt to connect local
    #                                    server to tolsun.oulu.fi on port 6667
    #

    # def irc_CONNECT(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.4.8 Trace message
    #
    #       Command: TRACE
    #    Parameters: [ <target> ]
    #
    #    TRACE command is used to find the route to specific server and
    #    information about its peers.  Each server that processes this command
    #    MUST report to the sender about it.  The replies from pass-through
    #    links form a chain, which shows route to destination.  After sending
    #    this reply back, the query MUST be sent to the next server until
    #    given <target> server is reached.
    #
    #    TRACE command is used to find the route to specific server.  Each
    #    server that processes this message MUST tell the sender about it by
    #    sending a reply indicating it is a pass-through link, forming a chain
    #    of replies.  After sending this reply back, it MUST then send the
    #    TRACE message to the next server until given server is reached.  If
    #    the <target> parameter is omitted, it is RECOMMENDED that TRACE
    #    command sends a message to the sender telling which servers the local
    #    server has direct connection to.
    #
    #    If the destination given by <target> is an actual server, the
    #    destination server is REQUIRED to report all servers, services and
    #    operators which are connected to it; if the command was issued by an
    #    operator, the server MAY also report all users which are connected to
    #    it.  If the destination given by <target> is a nickname, then only a
    #    reply for that nickname is given.  If the <target> parameter is
    #    omitted, it is RECOMMENDED that the TRACE command is parsed as
    #    targeted to the processing server.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER
    #
    #       If the TRACE message is destined for another server, all
    #       intermediate servers must return a RPL_TRACELINK reply to indicate
    #       that the TRACE passed through it and where it is going next.
    #
    #            RPL_TRACELINK
    #
    #       A TRACE reply may be composed of any number of the following
    #       numeric replies.
    #
    #            RPL_TRACECONNECTING           RPL_TRACEHANDSHAKE
    #            RPL_TRACEUNKNOWN              RPL_TRACEOPERATOR
    #            RPL_TRACEUSER                 RPL_TRACESERVER
    #            RPL_TRACESERVICE              RPL_TRACENEWTYPE
    #            RPL_TRACECLASS                RPL_TRACELOG
    #            RPL_TRACEEND
    #
    #    Examples:
    #
    #    TRACE *.oulu.fi                 ; TRACE to a server matching
    #                                    *.oulu.fi
    #

    # def irc_TRACE(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.4.9 Admin command
    #
    #       Command: ADMIN
    #    Parameters: [ <target> ]
    #
    #    The admin command is used to find information about the administrator
    #    of the given server, or current server if <target> parameter is
    #    omitted.  Each server MUST have the ability to forward ADMIN messages
    #    to other servers.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER
    #            RPL_ADMINME                   RPL_ADMINLOC1
    #            RPL_ADMINLOC2                 RPL_ADMINEMAIL
    #
    #    Examples:
    #
    #    ADMIN tolsun.oulu.fi            ; request an ADMIN reply from
    #                                    tolsun.oulu.fi
    #
    #    ADMIN syrk                      ; ADMIN request for the server to
    #                                    which the user syrk is connected
    #

    # def irc_ADMIN(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.4.10 Info command
    #
    #       Command: INFO
    #    Parameters: [ <target> ]
    #
    #    The INFO command is REQUIRED to return information describing the
    #    server: its version, when it was compiled, the patchlevel, when it
    #    was started, and any other miscellaneous information which may be
    #    considered to be relevant.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER
    #            RPL_INFO                      RPL_ENDOFINFO
    #
    #    Examples:
    #
    #    INFO csd.bu.edu                 ; request an INFO reply from
    #                                    csd.bu.edu
    #
    #    INFO Angel                      ; request info from the server that
    #                                    Angel is connected to.
    #

    # def irc_INFO(self, prefix, params):
        # TODO - not implemented in example

#
# 3.5 Service Query and Commands
#
#    The service query group of commands has been designed to return
#    information about any service which is connected to the network.
#

    #
    # 3.5.1 Servlist message
    #
    #       Command: SERVLIST
    #    Parameters: [ <mask> [ <type> ] ]
    #
    #    The SERVLIST command is used to list services currently connected to
    #    the network and visible to the user issuing the command.  The
    #    optional parameters may be used to restrict the result of the query
    #    (to matching services names, and services type).
    #
    #    Numeric Replies:
    #
    #            RPL_SERVLIST                  RPL_SERVLISTEND
    #

    # def irc_SERVLIST(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.5.2 Squery
    #
    #       Command: SQUERY
    #    Parameters: <servicename> <text>
    #
    #    The SQUERY command is used similarly to PRIVMSG.  The only difference
    #    is that the recipient MUST be a service.  This is the only way for a
    #    text message to be delivered to a service.
    #
    #    See PRIVMSG for more details on replies and example.
    #
    #    Examples:
    #
    #    SQUERY irchelp :HELP privmsg
    #                                    ; Message to the service with
    #                                    nickname irchelp.
    #
    #    SQUERY dict@irc.fr :fr2en blaireau
    #                                    ; Message to the service with name
    #                                      dict@irc.fr.

    # def irc_SQUERY(self, prefix, params):
        # TODO - not implemented in example

#
# 3.6 User based queries
#
#    User queries are a group of commands which are primarily concerned
#    with finding details on a particular user or group users.  When using
#    wildcards with any of these commands, if they match, they will only
#    return information on users who are 'visible' to you.  The visibility
#    of a user is determined as a combination of the user's mode and the
#    common set of channels you are both on.
#
#    Although services SHOULD NOT be using this class of message, they are
#    allowed to.
#

    #
    # 3.6.1 Who query
    #
    #       Command: WHO
    #    Parameters: [ <mask> [ "o" ] ]
    #
    #    The WHO command is used by a client to generate a query which returns
    #    a list of information which 'matches' the <mask> parameter given by
    #    the client.  In the absence of the <mask> parameter, all visible
    #    (users who aren't invisible (user mode +i) and who don't have a
    #    common channel with the requesting client) are listed.  The same
    #    result can be achieved by using a <mask> of "0" or any wildcard which
    #    will end up matching every visible user.
    #
    #    The <mask> passed to WHO is matched against users' host, server, real
    #    name and nickname if the channel <mask> cannot be found.
    #
    #    If the "o" parameter is passed only operators are returned according
    #    to the <mask> supplied.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER
    #            RPL_WHOREPLY                  RPL_ENDOFWHO
    #
    #    Examples:
    #
    #    WHO *.fi                        ; Command to list all users who match
    #                                    against "*.fi".
    #
    #    WHO jto* o                      ; Command to list all users with a
    #                                    match against "jto*" if they are an
    #                                    operator.
    #

    # def irc_WHO(self, prefix, params):
        # TODO

    #
    # 3.6.2 Whois query
    #
    #       Command: WHOIS
    #    Parameters: [ <target> ] <mask> *( "," <mask> )
    #
    #    This command is used to query information about particular user.
    #    The server will answer this command with several numeric messages
    #    indicating different statuses of each user which matches the mask (if
    #    you are entitled to see them).  If no wildcard is present in the
    #    <mask>, any information about that nick which you are allowed to see
    #    is presented.
    #
    #    If the <target> parameter is specified, it sends the query to a
    #    specific server.  It is useful if you want to know how long the user
    #    in question has been idle as only local server (i.e., the server the
    #    user is directly connected to) knows that information, while
    #    everything else is globally known.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER              ERR_NONICKNAMEGIVEN
    #            RPL_WHOISUSER                 RPL_WHOISCHANNELS
    #            RPL_WHOISCHANNELS             RPL_WHOISSERVER
    #            RPL_AWAY                      RPL_WHOISOPERATOR
    #            RPL_WHOISIDLE                 ERR_NOSUCHNICK
    #            RPL_ENDOFWHOIS
    #
    #    Examples:
    #
    #    WHOIS wiz                       ; return available user information
    #                                    about nick WiZ
    #
    #    WHOIS eff.org trillian          ; ask server eff.org for user
    #                                    information  about trillian
    #

    # def irc_WHOIS(self, prefix, params):
        # TODO

    #
    # 3.6.3 Whowas
    #
    #       Command: WHOWAS
    #    Parameters: <nickname> *( "," <nickname> ) [ <count> [ <target> ] ]
    #
    #    Whowas asks for information about a nickname which no longer exists.
    #    This may either be due to a nickname change or the user leaving IRC.
    #    In response to this query, the server searches through its nickname
    #    history, looking for any nicks which are lexically the same (no wild
    #    card matching here).  The history is searched backward, returning the
    #    most recent entry first.  If there are multiple entries, up to
    #    <count> replies will be returned (or all of them if no <count>
    #    parameter is given).  If a non-positive number is passed as being
    #    <count>, then a full search is done.
    #
    #    Wildcards are allowed in the <target> parameter.
    #
    #    Numeric Replies:
    #
    #            ERR_NONICKNAMEGIVEN           ERR_WASNOSUCHNICK
    #            RPL_WHOWASUSER                RPL_WHOISSERVER
    #            RPL_ENDOFWHOWAS
    #
    #    Examples:
    #
    #    WHOWAS Wiz                      ; return all information in the nick
    #                                    history about nick "WiZ";
    #
    #    WHOWAS Mermaid 9                ; return at most, the 9 most recent
    #                                    entries in the nick history for
    #                                    "Mermaid";
    #
    #
    #    WHOWAS Trillian 1 *.edu         ; return the most recent history for
    #                                    "Trillian" from the first server
    #                                    found to match "*.edu".

    # def irc_WHOWAS(self, prefix, params):
        # TODO - not implemented in example

#
# 3.7 Miscellaneous messages
#
#    Messages in this category do not fit into any of the above categories
#    but are nonetheless still a part of and REQUIRED by the protocol.
#

    #
    # 3.7.1 Kill message
    #
    #       Command: KILL
    #    Parameters: <nickname> <comment>
    #
    #    The KILL command is used to cause a client-server connection to be
    #    closed by the server which has the actual connection.  Servers
    #    generate KILL messages on nickname collisions.  It MAY also be
    #    available available to users who have the operator status.
    #
    #    Clients which have automatic reconnect algorithms effectively make
    #    this command useless since the disconnection is only brief.  It does
    #    however break the flow of data and can be used to stop large amounts
    #    of 'flooding' from abusive users or accidents.  Abusive users usually
    #    don't care as they will reconnect promptly and resume their abusive
    #    behaviour.  To prevent this command from being abused, any user may
    #    elect to receive KILL messages generated for others to keep an 'eye'
    #    on would be trouble spots.
    #
    #    In an arena where nicknames are REQUIRED to be globally unique at all
    #    times, KILL messages are sent whenever 'duplicates' are detected
    #    (that is an attempt to register two users with the same nickname) in
    #    the hope that both of them will disappear and only 1 reappear.
    #
    #    When a client is removed as the result of a KILL message, the server
    #    SHOULD add the nickname to the list of unavailable nicknames in an
    #    attempt to avoid clients to reuse this name immediately which is
    #    usually the pattern of abusive behaviour often leading to useless
    #    "KILL loops".  See the "IRC Server Protocol" document [IRC-SERVER]
    #    for more information on this procedure.
    #
    #    The comment given MUST reflect the actual reason for the KILL.  For
    #    server-generated KILLs it usually is made up of details concerning
    #    the origins of the two conflicting nicknames.  For users it is left
    #    up to them to provide an adequate reason to satisfy others who see
    #    it.  To prevent/discourage fake KILLs from being generated to hide
    #    the identify of the KILLer, the comment also shows a 'kill-path'
    #    which is updated by each server it passes through, each prepending
    #    its name to the path.
    #
    #    Numeric Replies:
    #
    #            ERR_NOPRIVILEGES              ERR_NEEDMOREPARAMS
    #            ERR_NOSUCHNICK                ERR_CANTKILLSERVER
    #
    #    NOTE:
    #    It is RECOMMENDED that only Operators be allowed to kill other users
    #    with KILL command.  This command has been the subject of many
    #    controversies over the years, and along with the above
    #    recommendation, it is also widely recognized that not even operators
    #    should be allowed to kill users on remote servers.
    #

    # def irc_KILL(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.7.2 Ping message
    #
    #       Command: PING
    #    Parameters: <server1> [ <server2> ]
    #
    #    The PING command is used to test the presence of an active client or
    #    server at the other end of the connection.  Servers send a PING
    #    message at regular intervals if no other activity detected coming
    #    from a connection.  If a connection fails to respond to a PING
    #    message within a set amount of time, that connection is closed.  A
    #    PING message MAY be sent even if the connection is active.
    #
    #    When a PING message is received, the appropriate PONG message MUST be
    #    sent as reply to <server1> (server which sent the PING message out)
    #    as soon as possible.  If the <server2> parameter is specified, it
    #    represents the target of the ping, and the message gets forwarded
    #    there.
    #
    #    Numeric Replies:
    #
    #            ERR_NOORIGIN                  ERR_NOSUCHSERVER
    #
    #    Examples:
    #
    #    PING tolsun.oulu.fi             ; Command to send a PING message to
    #                                    server
    #
    #    PING WiZ tolsun.oulu.fi         ; Command from WiZ to send a PING
    #                                    message to server "tolsun.oulu.fi"
    #
    #    PING :irc.funet.fi              ; Ping message sent by server
    #                                    "irc.funet.fi"
    #
    def irc_PING(self, prefix, params):
        self.sendMessage("PONG", self.hostname)

    #
    # 3.7.3 Pong message
    #
    #       Command: PONG
    #    Parameters: <server> [ <server2> ]
    #
    #    PONG message is a reply to ping message.  If parameter <server2> is
    #    given, this message MUST be forwarded to given target.  The <server>
    #    parameter is the name of the entity who has responded to PING message
    #    and generated this message.
    #
    #    Numeric Replies:
    #
    #            ERR_NOORIGIN                  ERR_NOSUCHSERVER
    #
    #    Example:
    #
    #    PONG csd.bu.edu tolsun.oulu.fi  ; PONG message from csd.bu.edu to
    #                                    tolsun.oulu.fi
    #

    # def irc_PONG(self, prefix, params):
        # TODO - not implemented in example

    #
    # 3.7.4 Error
    #
    #       Command: ERROR
    #    Parameters: <error message>
    #
    #    The ERROR command is for use by servers when reporting a serious or
    #    fatal error to its peers.  It may also be sent from one server to
    #    another but MUST NOT be accepted from any normal unknown clients.
    #
    #    Only an ERROR message SHOULD be used for reporting errors which occur
    #    with a server-to-server link.  An ERROR message is sent to the server
    #    at the other end (which reports it to appropriate local users and
    #    logs) and to appropriate local users and logs.  It is not to be
    #    passed onto any other servers by a server if it is received from a
    #    server.
    #
    #    The ERROR message is also used before terminating a client
    #    connection.
    #
    #    When a server sends a received ERROR message to its operators, the
    #    message SHOULD be encapsulated inside a NOTICE message, indicating
    #    that the client was not responsible for the error.
    #
    #    Numerics:
    #
    #            None.
    #
    #    Examples:
    #
    #    ERROR :Server *.fi already exists ; ERROR message to the other server
    #                                    which caused this error.
    #
    #    NOTICE WiZ :ERROR from csd.bu.edu -- Server *.fi already exists
    #                                    ; Same ERROR message as above but
    #                                    sent to user WiZ on the other server.
    #

    # def irc_ERROR(self, prefix, params):
        # TODO - not implemented in example

    #
    # 4. Optional features
    #
    #    This section describes OPTIONAL messages.  They are not required in a
    #    working server implementation of the protocol described herein.  In
    #    the absence of the feature, an error reply message MUST be generated
    #    or an unknown command error.  If the message is destined for another
    #    server to answer then it MUST be passed on (elementary parsing
    #    REQUIRED) The allocated numerics for this are listed with the
    #    messages below.
    #
    #    From this section, only the USERHOST and ISON messages are available
    #    to services.
    #

    #
    # 4.1 Away
    #
    #       Command: AWAY
    #    Parameters: [ <text> ]
    #
    #    With the AWAY command, clients can set an automatic reply string for
    #    any PRIVMSG commands directed at them (not to a channel they are on).
    #    The server sends an automatic reply to the client sending the PRIVMSG
    #    command.  The only replying server is the one to which the sending
    #    client is connected to.
    #
    #    The AWAY command is used either with one parameter, to set an AWAY
    #    message, or with no parameters, to remove the AWAY message.
    #
    #    Because of its high cost (memory and bandwidth wise), the AWAY
    #    message SHOULD only be used for client-server communication.  A
    #    server MAY choose to silently ignore AWAY messages received from
    #    other servers.  To update the away status of a client across servers,
    #    the user mode 'a' SHOULD be used instead.  (See Section 3.1.5)
    #
    #    Numeric Replies:
    #
    #            RPL_UNAWAY                    RPL_NOWAWAY
    #
    #    Example:
    #
    #    AWAY :Gone to lunch.  Back in 5 ; Command to set away message to
    #                                    "Gone to lunch.  Back in 5".
    #

    # def irc_AWAY(self, prefix, params):
        # TODO - not implemented in example

    #
    # 4.2 Rehash message
    #
    #       Command: REHASH
    #    Parameters: None
    #
    #    The rehash command is an administrative command which can be used by
    #    an operator to force the server to re-read and process its
    #    configuration file.
    #
    #    Numeric Replies:
    #
    #            RPL_REHASHING                 ERR_NOPRIVILEGES
    #
    #
    #    Example:
    #
    #    REHASH                          ; message from user with operator
    #                                    status to server asking it to reread
    #                                    its configuration file.
    #

    # def irc_REHASH(self, prefix, params):
        # TODO - not implemented in example

    #
    # 4.3 Die message
    #
    #       Command: DIE
    #    Parameters: None
    #
    #    An operator can use the DIE command to shutdown the server.  This
    #    message is optional since it may be viewed as a risk to allow
    #    arbitrary people to connect to a server as an operator and execute
    #    this command.
    #
    #    The DIE command MUST always be fully processed by the server to which
    #    the sending client is connected and MUST NOT be passed onto other
    #    connected servers.
    #
    #    Numeric Replies:
    #
    #            ERR_NOPRIVILEGES
    #
    #    Example:
    #
    #    DIE                             ; no parameters required.
    #

    # def irc_DIE(self, prefix, params):
        # TODO - not implemented in example

    #
    # 4.4 Restart message
    #
    #       Command: RESTART
    #    Parameters: None
    #
    #    An operator can use the restart command to force the server to
    #    restart itself.  This message is optional since it may be viewed as a
    #    risk to allow arbitrary people to connect to a server as an operator
    #    and execute this command, causing (at least) a disruption to service.
    #
    #    The RESTART command MUST always be fully processed by the server to
    #    which the sending client is connected and MUST NOT be passed onto
    #    other connected servers.
    #
    #    Numeric Replies:
    #
    #            ERR_NOPRIVILEGES
    #
    #    Example:
    #
    #    RESTART                         ; no parameters required.
    #

    # def irc_RESTART(self, prefix, params):
        # TODO - not implemented in example

    #
    # 4.5 Summon message
    #
    #       Command: SUMMON
    #    Parameters: <user> [ <target> [ <channel> ] ]
    #
    #    The SUMMON command can be used to give users who are on a host
    #    running an IRC server a message asking them to please join IRC.  This
    #    message is only sent if the target server (a) has SUMMON enabled, (b)
    #    the user is logged in and (c) the server process can write to the
    #    user's tty (or similar).
    #
    #    If no <server> parameter is given it tries to summon <user> from the
    #    server the client is connected to is assumed as the target.
    #
    #    If summon is not enabled in a server, it MUST return the
    #    ERR_SUMMONDISABLED numeric.
    #
    #    Numeric Replies:
    #
    #            ERR_NORECIPIENT               ERR_FILEERROR
    #            ERR_NOLOGIN                   ERR_NOSUCHSERVER
    #            ERR_SUMMONDISABLED            RPL_SUMMONING
    #
    #    Examples:
    #
    #    SUMMON jto                      ; summon user jto on the server's
    #                                    host
    #
    #    SUMMON jto tolsun.oulu.fi       ; summon user jto on the host which a
    #                                    server named "tolsun.oulu.fi" is
    #                                    running.
    #

    # def irc_SUMMON(self, prefix, params):
        # TODO - not implemented in example

    #
    # 4.6 Users
    #
    #       Command: USERS
    #    Parameters: [ <target> ]
    #
    #    The USERS command returns a list of users logged into the server in a
    #    format similar to the UNIX commands who(1), rusers(1) and finger(1).
    #    If disabled, the correct numeric MUST be returned to indicate this.
    #
    #    Because of the security implications of such a command, it SHOULD be
    #    disabled by default in server implementations.  Enabling it SHOULD
    #    require recompiling the server or some equivalent change rather than
    #    simply toggling an option and restarting the server.  The procedure
    #    to enable this command SHOULD also include suitable large comments.
    #
    #    Numeric Replies:
    #
    #            ERR_NOSUCHSERVER              ERR_FILEERROR
    #            RPL_USERSSTART                RPL_USERS
    #            RPL_NOUSERS                   RPL_ENDOFUSERS
    #            ERR_USERSDISABLED
    #
    #    Disabled Reply:
    #
    #            ERR_USERSDISABLED
    #
    #    Example:
    #
    #    USERS eff.org                   ; request a list of users logged in
    #                                    on server eff.org
    #

    # def irc_USERS(self, prefix, params):
        # TODO - not implemented in example

    #
    # 4.7 Operwall message
    #
    #       Command: WALLOPS
    #    Parameters: <Text to be sent>
    #
    #    The WALLOPS command is used to send a message to all currently
    #    connected users who have set the 'w' user mode for themselves.  (See
    #    Section 3.1.5 "User modes").
    #
    #    After implementing WALLOPS as a user command it was found that it was
    #    often and commonly abused as a means of sending a message to a lot of
    #    people.  Due to this, it is RECOMMENDED that the implementation of
    #    WALLOPS allows and recognizes only servers as the originators of
    #    WALLOPS.
    #
    #    Numeric Replies:
    #
    #            ERR_NEEDMOREPARAMS
    #
    #    Example:
    #
    #    :csd.bu.edu WALLOPS :Connect '*.uiuc.edu 6667' from Joshua ; WALLOPS
    #                                    message from csd.bu.edu announcing a
    #                                    CONNECT message it received from
    #                                    Joshua and acted upon.
    #

    # def irc_WALLOPS(self, prefix, params):
        # TODO - not implemented in example

    #
    # 4.8 Userhost message
    #
    #       Command: USERHOST
    #    Parameters: <nickname> *( SPACE <nickname> )
    #
    #    The USERHOST command takes a list of up to 5 nicknames, each
    #    separated by a space character and returns a list of information
    #    about each nickname that it found.  The returned list has each reply
    #    separated by a space.
    #
    #    Numeric Replies:
    #
    #            RPL_USERHOST                  ERR_NEEDMOREPARAMS
    #
    #    Example:
    #
    #    USERHOST Wiz Michael syrk       ; USERHOST request for information on
    #                                    nicks "Wiz", "Michael", and "syrk"
    #
    #    :ircd.stealth.net 302 yournick :syrk=+syrk@millennium.stealth.net
    #                                    ; Reply for user syrk
    #

    # def irc_USERHOST(self, prefix, params):
        # TODO

    #
    # 4.9 Ison message
    #
    #       Command: ISON
    #    Parameters: <nickname> *( SPACE <nickname> )
    #
    #    The ISON command was implemented to provide a quick and efficient
    #    means to get a response about whether a given nickname was currently
    #    on IRC. ISON only takes one (1) type of parameter: a space-separated
    #    list of nicks.  For each nickname in the list that is present, the
    #
    #    server adds that to its reply string.  Thus the reply string may
    #    return empty (none of the given nicks are present), an exact copy of
    #    the parameter string (all of them present) or any other subset of the
    #    set of nicks given in the parameter.  The only limit on the number of
    #    nicks that may be checked is that the combined length MUST NOT be too
    #    large as to cause the server to chop it off so it fits in 512
    #    characters.
    #
    #    ISON is only processed by the server local to the client sending the
    #    command and thus not passed onto other servers for further
    #    processing.
    #
    #    Numeric Replies:
    #
    #            RPL_ISON                      ERR_NEEDMOREPARAMS
    #
    #    Example:
    #
    #    ISON phone trillian WiZ jarlek Avalon Angel Monstah syrk
    #                                    ; Sample ISON request for 7 nicks.
    #

    # def irc_ISON(self, prefix, params):
        # TODO - not implemented in example

# factory for creating instance of the IRC client
class IRCFactory(protocol.ServerFactory):
    protocol = IRCConnection
