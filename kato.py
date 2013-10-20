#!/usr/bin/env python

import sys
import base64
import os
import json
from math import ceil
import random
from urllib import quote

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
    memberships = None

    def __init__(self, id, name, email, status, memberships):
        self.id = id
        self.name = name
        self.email = email
        self.status = status
        self.memberships = memberships

    def __repr__(self):
        return "KatoAccount{id='%s', name='%s', email='%s', status='%s', memberships=%s}" % \
            (self.id, self.name, self.email, self.status, self.memberships)

    @classmethod
    def from_json(cls, message):
        memberships = []
        for membership in message["memberships"]:
            memberships.append(KatoAccountMembership.from_json(membership))
        return KatoAccount(message["id"],
                message["name"],
                message["email"],
                message["status"],
                memberships)

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

    def __repr__(self):
        return "KatoAccountMembership{org_id='%s', org_name='%s', role='%s'}" % \
            (self.org_id, self.org_name, self.role)

    @classmethod
    def from_json(cls, message):
        return KatoAccountMembership(message["org_id"], message["org_name"], message["role"])

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

    def __repr__(self):
        return "KatoRoom{id='%s', type='%s', name='%s', org_id='%s', created_ts=%s}" % \
            (self.id, self.type, self.name, self.org_id, self.created_ts)

    @classmethod
    def from_json(cls, message):
        return KatoRoom(message["id"],
                message["type"],
                message["name"],
                message["organization_id"],
                message["created_ts"])


# http client for Kato
class KatoHttpClient(object):
    # whether debugging is enabled
    debug = False

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
        self.session_id = self._create_session_id()

        url = KATO_API_BASE_URL + "/sessions/" + self.session_id
        data = dict()
        data["email"] = email
        data["password"] = password

        headers = dict()
        headers["Content-Type"] = ["application/json"]
        d = self._httpRequest("PUT", url, json.dumps(data), headers=headers)

        def process_login_response(response):
            # find and set the session key from the cookies
            cookies = response.headers.getRawHeaders("set-cookie")
            self.session_key = None

            if cookies:
                for cookie in cookies:
                    # at least one cookie should look like this:
                    # session_key=a9a7da00-3be0-11ed-a444-bc764e10c2df; Version=1; Expires=Tue, 19-Nov-2013 19:15:53 GMT; Max-Age=2592000; Domain=.api.kato.im; Path=/; Secure; HttpOnly
                    cookie_parts = cookie.split(";")
                    for cookie_part in cookie_parts:
                        cookie_part = cookie_part.strip()
                        parts = cookie_part.split("=");
                        if len(parts) == 2:
                            key, value = parts
                            if key == "session_key":
                                self.session_key = value

            if not self.session_key:
                raise ValueError("Could not login to Kato")

            # nothing to return to the caller
            return None
        d.addCallback(process_login_response)
        d.addCallback(self._initialize)

        return d

    # creates a session ID using the same algorithm that Kato uses
    def _create_session_id(self):
        return self._create_id(8)

    # creates a message ID using the same algorithm that Kato uses
    def _create_message_id(self):
        return self._create_id(2)

    # ID generation
    def _create_id(self, byte_size):
        result = []
        for i in range(0, byte_size):
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
    def _initialize(self, ignored=None):
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
                    debug = self.debug,
                    debugCodePaths = self.debug,
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

    # logs out of kato
    # returns a deferred that fires when complete
    def logout(self):
        # close websocket connection
        if self.websocket:
            self.websocket.dropConnection()
            self.websocket = None

        # DELETE on the sessions resource to logout
        url = KATO_API_BASE_URL + "/sessions/" + self.session_id
        d = self._httpRequest("DELETE", url)

        return d

    #
    # websocket callbacks
    #
    def websocket_opened(self, websocket):
        print "Websocket opened."
        self.websocket = websocket

        # fire initialization deferred, if present
        if self.initialize_deferred:
            d = self.initialize_deferred
            self.initialize_deferred = None
            d.callback(None)

    def websocket_closed(self, websocket, wasClean, code, reason):
        # TODO: handle websocket closed not during login
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
        url = KATO_API_BASE_URL + "/sessions/" + quote(session_id)
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
            account_id = self.account_id

        url = KATO_API_BASE_URL + "/accounts/" + quote(account_id)
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
        url = KATO_API_BASE_URL + "/organizations/" + quote(org_id) + "/accounts"
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
        url = KATO_API_BASE_URL + "/organizations/" + quote(org_id) + "/forums"
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

    # enters a KatoRoom
    def enter_room(self, room):
        hello = dict()
        hello["type"] = "hello"
        hello["room_id"] = room.id
        self.websocket.sendJson(hello);

    # leaves a room
    def leave_room(self, room):
        # so we don't actually know if this is possible
        # pretend we left the room and did nothing?
        pass

    # sends the given message to the given KatoRoom
    #
    # messages look like this:
    # {
    #     "room_id":"<ROOM_ID>",
    #     "type":"text",
    #     "params":{
    #         "data":{"id":"<ID(2)>"},
    #         "text":"<MESSAGE_TEXT>",
    #         "mentions":[],
    #         "mentioned_everybody":false
    #     }
    # }
    def send_message(self, room, message):
        data = dict()
        data["id"] = str(self._create_message_id())

        params = dict()
        params["data"] = data
        params["text"] = message
        # TODO
        params["mentions"] = []
        params["mentioned_everybody"] = False

        msg = dict()
        msg["type"] = "text"
        msg["room_id"] = room.id
        msg["params"] = params

        self.websocket.sendJson(msg);

    # sends a private message to the given KatoAccount
    # TODO
    def send_private_message(self, account, message):
        pass

    # like _httpRequest, but also adds a json attribute to the response object
    def _httpRequestJson(self, method, url, body=None, headers={}):
        d = self._httpRequest(method, url, body, headers)

        def process_response(response):
            if not response.content:
                raise ValueError("No response to URL: %s" % (url))
            else:
                print "Response to %s: %s" % (url, response.content)
            response.json = json.loads(response.content)
            return response
        d.addCallback(process_response)
        return d

    # executes an HTTP request to the given URL, returning the response via a
    # deferred
    # the response will have an additional attribute, content, containing the
    # received content
    def _httpRequest(self, method, url, body=None, headers=None):
        # convert to bytes, if needed
        url = str(url)

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
            # response has the following fields:
            # - version (http version)
            # - code (http response code)
            # - phrase (phrase associated with http response code)
            # - headers (response headers)
            # - content (added below)

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

    # message is an object that should be JSON serialized and sent to the
    # server
    def sendJson(self, message):
        j = json.dumps(message)
        print "SENDING JSON TO KATO:", j
        self.sendMessage(j)

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
