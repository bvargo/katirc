#!/usr/bin/env python

import sys

from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.python import log

from irc import IRCFactory

if __name__ == '__main__':
    log.startLogging(sys.stdout)

    # IRC server factory.
    ircfactory = IRCFactory()

    # server endpoint on TCP port 6667 listening for IRC messages
    endpoint = TCP4ServerEndpoint(reactor, 6667)
    endpoint.listen(ircfactory)

    reactor.run()
