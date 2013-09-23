#!/usr/bin/env python

import sys
import base64
import os
import json
from math import ceil
import random

import twisted.internet
from twisted.internet import reactor, defer, protocol
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.python import log
from twisted.web.client import Agent
from twisted.web.http_headers import Headers

from autobahn.websocket import WebSocketClientFactory, \
                               WebSocketClientProtocol, \
                               WebSocketProtocol, \
                               connectWS

# TODO: switch to github/dreid/treq for HTTP requests
# http://blog.mailgun.com/post/stress-testing-http-with-twisted-python-and-treq/

# TODO: error handling:
# - json decoding
# - login
# - network connections

KATO_API_BASE_URL = "https://api.kato.im"
KATO_API_WS_URL = "wss://api.kato.im/ws"
KATO_API_ORIGIN = "https://kato.im"

#KATO_API_BASE_URL = "http://localhost:8888"
#KATO_API_WS_URL = "ws://localhost:8888/ws"

# string producer, used with twisted's HTTP client for the producer of the body
class StringProducer(object):
    def __init__(self, body):
        self.body = body;
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass

class KatoAccount(object):
    # account ID
    id = ""

    # name associated with the account
    name = ""

    # email address associated with the account
    email = ""

    # email verification status
    # one of verified_email or unverified_email
    status = ""

    # list of KatoAccountMembership objects
    memberships = []

    def __init__(self, id, name, email, status, memberships):
        self.id = id
        self.name = name
        self.email = email
        self.status = status
        self.memberships = memberships


    @classmethod
    def from_json(cls, message):
        return KatoAccount(message.id,
                message.name,
                message.email,
                message.status,
                KatoAccountMembership.from_json(message.memberships))

class KatoAccountMembership(object):
    # ID of the organization in which the account is a member
    org_id = ""

    # Name of the organization
    org_name = ""

    # one of member or owner
    role = ""

    def __init__(self, org_id, org_name, role):
        self.org_id = org_id
        self.org_name = org_name
        self.role = role

    @classmethod
    def from_json(cls, message):
        return KatoAccountMembership(message.org_id, message.org_name, message.role)

class KatoRoom(object):
    # ID of the room
    id = ""

    # type of room
    # usually None, if a normal room; otherwise, a string, such as
    # "support_front"
    type = ""

    # name of the room
    name = ""

    # organization ID that owns the room
    org_id = ""

    # milliseconds since the unix epoch
    created_ts = 0

    def __init__(self, id, type, name, org_id, created_ts):
        self.id = id
        self.type = type
        self.name = name
        self.org_id = org_id
        self.created_ts = created_ts

    @classmethod
    def from_json(cls, message):
        return KatoRoom(message.id,
                message.type,
                message.name,
                message.org_id,
                message.created_ts)


# http client for Kato
class KatoHttpClient(object):
    # session ID and key for the Kato connection
    # initialize using login or useExistingSession
    session_id = ""
    session_key = ""

    # account ID of the current logged-in user
    account_id = -1

    # KatoWebsocket connection
    # set when the websocket is open, None when the websocket is closed
    websocket = None

    # KatoMessageReceiver
    # receives websocket messages
    message_receiver = None

    # deferred that is fired when connection is established
    # if none, then there is nothing to be fired
    initialize_deferred = None

    # creates an http client with the provided message receiver
    # TODO: if None, then do not initialize websocket connection
    def __init__(self, message_receiver):
        self.message_receiver = message_receiver

    # logs into Kato using the provided email address and password
    # returns a defer that fires when the user is logged in, or errors when
    # the user could not be logged in
    def login(self, email, password):
        url = KATO_API_BASE_URL + "/sessions/" + self._create_session_id()
        data = dict()
        data["email"] = email
        data["password"] = password

        #d = self._httpRequest("PUT", url, json.dumps(data))
        # XXX
        d = self._httpRequest("GET", "https://bvargo.net/miner/")

        def process_login_response(response):
            cookies = response.headers.getRawHeaders("Set-Cookie")
            # TODO: parse cookie
            print "response headers", response.headers

            # nothing to return to the caller
            return None
        d.addCallback(process_login_response)
        d.addCallback(self._initialize)

        return d

    # creates a session ID using the same algorithm that Kato uses
    def _create_session_id(self):
        result = []
        for i in range(0, 8):
            result.append(hex(int(ceil((0xffffffff * random.random()))))[2:])
        return ''.join(result)

    # uses an existing session for connecting to Kato
    # returns a deferred that fires upon success
    def login_with_session(self, session_id, session_key):
        self.session_id = session_id
        self.session_key = session_key
        return self._initialize()

    # called after the session ID and key have been set to complete the login
    # returns a deferred that fires when complete
    def _initialize(self):
        self.initialize_deferred = defer.Deferred()

        d_account = self.get_account_id(self.session_id)

        def process_account_id(account_id):
            self.account_id = account_id
            return None
        def initialize_ws(ignored):
            #cookie = "session_key=%s; session_id=%s" % \
            #    (self.session_key, self.session_id)
            cookie = "session_key=%s; session_id=%s" % \
                (self.session_key, self.session_id)
            factory = KatoWebsocketFactory(KATO_API_WS_URL,
                    self,
                    cookie = cookie,
                    debug = debug,
                    debugCodePaths = debug,
                    origin = KATO_API_ORIGIN)
            connectWS(factory)
            return None
        def handle_error(failure):
            if self.initialize_deferred:
                d = self.initialize_deferred
                self.initialize_deferred = None
                d.errback(failure)

        d_account.addCallback(process_account_id)
        d_account.addCallback(initialize_ws)

        # trigger err on the initialization deferred if there is an error
        # before the websocket phase
        d_account.addErrback(handle_error)

        # fired in websocket_opened or fired with error in websocket_closed
        return self.initialize_deferred

    #
    # websocket callbacks
    #
    def websocket_opened(self, websocket):
        print "Websocket opened."
        self.websocket = websocket
        # XXX
        websocket.sendMessage('{"room_id":"7bcb1e41eaa8ac0cf6048e4c69e2f605cf324374d155556960921037100c644","type":"hello"}')

        # fire initialization deferred, if present
        if self.initialize_deferred:
            d = self.initialize_deferred
            self.initialize_deferred = None
            d.callback(None)

    def websocket_closed(self, websocket, wasClean, code, reason):
        print "Websocket closed."
        self.websocket = None

        # fire initialization deferred, if present
        if self.initialize_deferred:
            d = self.initialize_deferred
            self.initialize_deferred = None
            d.errback(IOError("Error connecting: " + reason))

    def websocket_message(self, websocket, message_str, binary=None):
        method = None

        message = json.loads(message_str)

        if "type" in message:
            message_type = message["type"]
            message_type = message_type.upper()
            method = getattr(self.message_receiver,
                    "kato_%s" % message_type,
                    None)

        if method:
            method(message)
        else:
            self.message_receiver.kato_unknown(message)

    # returns the account ID, given a session ID, via a deferred
    def get_account_id(self, session_id):
        url = KATO_API_BASE_URL + "/sessions/" + session_id
        # returns:
        # {
        #     "id":"<SESSION_ID>",
        #     "account_id":"<ACCOUNT_ID>"
        # }

        # async get data
        d = self._httpRequestJson("GET", url)

        def process_response(response):
            if "account_id" in response.json:
                return response.json["account_id"]
            else:
                raise ValueError("Response does not contain account_id: " + data)
        d.addCallback(process_response)
        return d

    # returns KatoAccount instance via a deferred
    def get_account_info(self, account_id=None):
        if not account_id:
            account_id = self.accountId

        url = KATO_API_BASE_URL + "/accounts/" + account_id
        # returns
        # {
        #     "id":"<ACCOUNT_ID>",
        #     "status":"(verified_email | unverified_email)",
        #     "email":"<EMAIL_OF_ACCOUNT>",
        #     "name":"<NAME_ON_ACCOUNT>",
        #     "memberships": [
        #         {
        #             "org_id":"<ORG_ID>",
        #             "org_name":"<ORG_NAME>",
        #             "role":"(member|owner)"
        #         }
        #     ]
        # }

        # async get data
        d = self._httpRequestJson("GET", url)

        def process_response(response):
            if not response.json:
                raise ValueError("Response was empty")
            return KatoAccount.from_json(response.json)
        d.addCallback(process_response)
        return d

    # organization ID to list of KatoAccount objects for everyone in the
    # organization EXCEPT for the current user
    def get_organization_members(self, org_id):
        url = KATO_API_BASE_URL + "/organizations/" + org_id + "/account"
        # returns
        # [
        #     {
        #         "id":"<ACCOUNT_ID>",
        #         "status":"(verified_email | unverified_email)",
        #         "email":"<EMAIL_OF_ACCOUNT>",
        #         "name":"<NAME_ON_ACCOUNT>",
        #         "memberships": [
        #             {
        #                 "org_id":"<ORG_ID>",
        #                 "org_name":"<ORG_NAME>",
        #                 "role":"(member|owner)"
        #             }
        #         ]
        #     }
        # ]

        # async get data
        d = self._httpRequestJson("GET", url)

        def process_response(response):
            if not response.json:
                raise ValueError("Response was empty")

            accounts = []
            for entry in response.json:
                accounts.append(KatoAccount.from_json(entry))
            return accounts

        d.addCallback(process_response)
        return d

    # organization ID to list of Room objects for every room visible to the
    # current user
    # note that does does NOT include private conversations, which have the ID
    # of <ORG_ID>-<ACCOUNT_ID>
    def get_rooms(self, org_id):
        url = KATO_API_BASE_URL + "/organizations/" + org_id + "/forums"
        # returns
        # [
        #     {
        #         "created_ts": <MILLISECONDS_SINCE_EPOCH>,
        #         "type": (null | "support_front" | ...; usually null),
        #         "name": "<NAME_OF_ROOM>",
        #         "organization_id": "<ORGANIZATION_OWNING_ROOM>",
        #         "id": "<ROOM_ID>"
        #     }
        # ]

        # async get data
        d = self._httpRequestJson("GET", url)

        def process_response(response):
            if not response.json:
                raise ValueError("Response was empty")

            rooms = []
            for entry in response.json:
                rooms.append(KatoRoom.from_json(entry))
            return rooms

        d.addCallback(process_response)
        return d

    # like _httpRequest, but also adds a json attribute to the response object
    def _httpRequestJson(self, method, url, body=None, headers={}):
        d = self._httpRequest(method, url, body, headers)

        def process_response(response):
            response.json = json.loads(response.content)
            return response
        d.addCallback(process_response)
        return d

    # executes an HTTP request to the given URL, returning the response via a
    # deferred
    # the response will have an additional attribute, content, containing the
    # received content
    def _httpRequest(self, method, url, body=None, headers=None):
        # add session information as the cookie
        if not headers:
            headers = dict()
        if self.session_id and self.session_key:
            headers["Cookie"] = ["session_key=%s; session_id=%s" % \
                (self.session_key, self.session_id)]

        agent = Agent(reactor)
        d = agent.request(method,
                url,
                Headers(headers),
                StringProducer(body) if body else None)

        def handle_response(response):
            if response.code == 204:
                # no content
                response.content = ""
                return defer.succeed(response)
            else:
                class Receiver(protocol.Protocol):
                    def __init__(self, deferred):
                        self.buffer = ""
                        self.deferred = deferred

                    def dataReceived(self, data):
                        self.buffer += data

                    def connectionLost(self, reason):
                        # TODO: test for twisted.web.client.ResponseDone
                        response.content = self.buffer
                        self.deferred.callback(response)

                d = defer.Deferred()
                response.deliverBody(Receiver(d))
                return d
        d.addCallback(handle_response)
        return d

# websocket connection to Kato
class KatoWebsocket(WebSocketClientProtocol):
    def onOpen(self):
        # notify the client that the websocket opened
        self.factory.kato_client.websocket_opened(self)

        # TODO
        #self.sendMessage('{"room_id":"7bcb1e41eaa8ac0cf6048e4c69e2f605cf324374d155556960921037100c644","type":"hello"}')

    def onClose(self, wasClean, code, reason):
        # notify the client that the websocket closed
        self.factory.kato_client.websocket_closed(self,
                wasClean = wasClean,
                code = code,
                reason = reason)

    def onMessage(self, message, binary):
        # notify the client of the message
        self.factory.kato_client.websocket_message(self,
                message,
                binary = binary)

    # override startHanshake so that we can add the cookie header and fix the
    # origin
    def startHandshake(self):
        """
        Start WebSockets opening handshake.
        """

        # construct WS opening handshake HTTP header
        request = "GET %s HTTP/1.1\x0d\x0a" % self.factory.resource.encode("utf-8")

        if self.factory.useragent is not None and self.factory.useragent != "":
            request += "User-Agent: %s\x0d\x0a" % self.factory.useragent.encode("utf-8")

        #request += "Host: %s:%d\x0d\x0a" % (self.factory.host.encode("utf-8"), self.factory.port)
        request += "Host: %s\x0d\x0a" % self.factory.host.encode("utf-8")
        request += "Upgrade: WebSocket\x0d\x0a"
        request += "Connection: Upgrade\x0d\x0a"

        # this seems to prohibit some non-compliant proxies from removing the
        # connection "Upgrade" header
        # See also:
        #   http://www.ietf.org/mail-archive/web/hybi/current/msg09841.html
        #   http://code.google.com/p/chromium/issues/detail?id=148908
        #
        request += "Pragma: no-cache\x0d\x0a"
        request += "Cache-Control: no-cache\x0d\x0a"

        # handshake random key
        if self.version == 0:
            (self.websocket_key1, number1) = self.createHixieKey()
            (self.websocket_key2, number2) = self.createHixieKey()
            self.websocket_key3 = os.urandom(8)
            accept_val = struct.pack(">II", number1, number2) + self.websocket_key3
            self.websocket_expected_challenge_response = hashlib.md5(accept_val).digest()

            # Safari does NOT set Content-Length, even though the body is
            # non-empty, and the request unchunked. We do it.
            # See also: http://www.ietf.org/mail-archive/web/hybi/current/msg02149.html
            request += "Content-Length: %s\x0d\x0a" % len(self.websocket_key3)

            # First two keys.
            request += "Sec-WebSocket-Key1: %s\x0d\x0a" % self.websocket_key1
            request += "Sec-WebSocket-Key2: %s\x0d\x0a" % self.websocket_key2
        else:
            self.websocket_key = base64.b64encode(os.urandom(16))
            request += "Sec-WebSocket-Key: %s\x0d\x0a" % self.websocket_key

        # optional origin announced
        if self.factory.origin:
            if self.version > 10 or self.version == 0:
                request += "Origin: %s\x0d\x0a" % self.factory.origin.encode("utf-8")
            else:
                # note: fixed bug where origin was a number, not a string
                request += "Sec-WebSocket-Origin: %s\x0d\x0a" % self.factory.origin.encode("utf-8")

        # optional cookie added
        if self.factory.cookie:
            request += "Cookie: %s\x0d\x0a" % self.factory.cookie

        # optional list of WS subprotocols announced
        if len(self.factory.protocols) > 0:
            request += "Sec-WebSocket-Protocol: %s\x0d\x0a" % ','.join(self.factory.protocols)

        # set WS protocol version depending on WS spec version
        if self.version != 0:
            request += "Sec-WebSocket-Version: %d\x0d\x0a" % WebSocketProtocol.SPEC_TO_PROTOCOL_VERSION[self.version]

        request += "\x0d\x0a"

        if self.version == 0:
            # Write HTTP request body for Hixie-76
            request += self.websocket_key3

        self.http_request_data = request

        if self.debug:
            log.msg(self.http_request_data)

        self.sendData(self.http_request_data)

class KatoWebsocketFactory(ReconnectingClientFactory, WebSocketClientFactory):
    protocol = KatoWebsocket

    # http://twistedmatrix.com/documents/current/api/twisted.internet.protocol.ReconnectingClientFactory.html
    maxDelay = 10
    maxRetries = 5

    # KatoHttpClient instance
    kato_client = None

    def __init__(self, url, kato_client, cookie=None, **kwargs):
        WebSocketClientFactory.__init__(self, url, **kwargs)

        self.kato_client = kato_client
        self.cookie = cookie
        self.setProtocolOptions(version = 13)

    def startedConnecting(self, connector):
        print 'Started to connect.'
        print connector

    def clientConnectionLost(self, connector, reason):
        print 'Lost connection. Reason:', reason
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        print 'Connection failed. Reason:', reason
        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)


# object that receives and acts upon messages from the Kato client
class KatoMessageReceiver(object):
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
    # TODO
    #def kato_READ(self, message):
    #    pass

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
    # TODO
    #def kato_TEXT(self, message):
    #    pass

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


if __name__ == '__main__':
    log.startLogging(sys.stdout)

    kato_client = KatoHttpClient(KatoMessageReceiver())
    d = kato_client.login_with_session("session_id", "session_key")

    def success(ignored):
        print "Logged in!"
    def error(failure):
        print "Not logged in. Error."
    d.addCallbacks(success, error)

    reactor.run()
