#!/usr/bin/env python3

# Copyright © 2016-2017 Faidon Liambotis
# Copyright © 2016-2017 Wikimedia Foundation, Inc.
#
# Derived work of https://github.com/jaraco/irc which is
# Copyright © 1999-2002 Joel Rosdahl
# Copyright © 2011-2016 Jason R. Coombs
# Copyright © 2009 Ferry Boender
#
# License: MIT

# TODO:
# - fix user registration
#   + needs 002, 003, 004, 005
#   + possibly needs 251, 252, 254, 255, 265, 266, 372
# - add len(params) checks in all handle_*
# - audit all handle_* for conformance to RFC
#   + https://www.ietf.org/rfc/rfc1459.txt
#   + http://ircv3.net/irc/
#   + https://modern.ircdocs.horse/
# - handle WHO
# - use IRCMessage from IRCError
# - cleanup IRCMessage
# - add PINGs
# - add statistics/introspection
# - split into multiple files
# - tests! https://a3nm.net/git/irctk/about
# - make botname/motd configurable
# - SSL (separate port? STARTTLS? STS?)

import argparse
import errno
import logging
import socket
import select
import re
import threading
import socketserver
import ircnumeric

BOTNAME = 'rc-pmtpa'
SRV_WELCOME = """
- *******************************************************
- This is the Wikimedia RC->IRC gateway
-
- https://wikitech.wikimedia.org/wiki/Irc.wikimedia.org
- *******************************************************
- Sending messages to channels is not allowed.
-
- A channel exists for all Wikimedia wikis which have been
- changed since the last time the server was restarted. In
- general, the name is just the domain name with the .org
- left off. For example, the changes on the English Wikipedia
- are available at #en.wikipedia
-
- If you want to talk, please join one of the many
- Wikimedia-related channels on irc.freenode.net.
-
- Alternatively, you can use Wikimedia's EventStreams service,
- which streams recent changes as JSON using the SSE protocol.
- See https://wikitech.wikimedia.org/wiki/EventStreams for details.
"""

log = logging.getLogger("ircstream")


class IRCMessage(object):
    def __init__(self, command, params=[], source=None):
        self.command = command
        self.params = params
        self.source = source

    @classmethod
    def from_message(cls, message):
        s = message.split(' ')

        source = None
        if s[0].startswith(':'):
            source = s[0][1:]
            s = s[1:]

        command = s[0].upper()
        original_params = s[1:]
        params = []

        while len(original_params):
            # skip multiple spaces in middle of message, as per 1459
            if original_params[0] == '' and len(original_params) > 1:
                original_params.pop(0)
                continue
            elif original_params[0].startswith(':'):
                arg = ' '.join(original_params)[1:]
                params.append(arg)
                break
            else:
                params.append(original_params.pop(0))

        return cls(command, params, source)

    def __str__(self):
        components = []

        if self.source:
            components.append(':' + self.source)

        components.append(self.command)

        if self.params:
            base = []
            for arg in self.params:
                casted = str(arg)
                if casted and ' ' not in casted and casted[0] != ':':
                    base.append(casted)
                else:
                    base.append(':' + casted)
                    break

            components.append(' '.join(base))

        return ' '.join(components)

    def __repr__(self):
        return '<IRCMessage: "{0}">'.format(self.command)


class IRCError(Exception):
    """
    Exception thrown by IRC command handlers to notify client of a
    server/client error.
    """
    def __init__(self, code, value):
        self.code = ircnumeric.codes[code]
        self.value = value

    def __str__(self):
        return repr(self.value)


class IRCChannel(object):
    """
    An IRC channel.
    """
    def __init__(self, name, topic='No topic'):
        self.name = name
        self.topic_by = 'Unknown'
        self.topic = topic
        self.clients = set()


class IRCClient(socketserver.BaseRequestHandler):
    """
    IRC client connect and command handling. Client connection is handled by
    the ``handle`` method which sets up a two-way communication with the
    client.  It then handles commands sent by the client by dispatching them to
    the ``handle_`` methods.
    """
    class Disconnect(BaseException):
        pass

    def __init__(self, request, client_address, server):
        self.host = "{}:{}".format(*client_address)
        self.user = None
        self.realname = None        # Client's real name
        self.nick = None            # Client's currently registered nickname
        self.send_queue = []        # Messages to send to client (strings)
        self.channels = {}          # Channels the client is in

        super().__init__(request, client_address, server)

    def client_msg(self, command, params):
        msg = IRCMessage(command, params, self.client_ident)
        self.send_queue.append(str(msg))

    def server_msg(self, command, params):
        msg = IRCMessage(command, params, self.server.servername)
        self.send_queue.append(str(msg))

    def handle(self):
        log.info('Client connected: %s', self.host)
        self.buffer = b''

        try:
            while True:
                self._handle_one()
        except self.Disconnect:
            self.request.close()

    def _handle_one(self):
        """
        Handle one read/write cycle.
        """
        ready_to_read, ready_to_write, in_error = select.select(
            [self.request], [], [self.request], 0.1)

        if in_error:
            raise self.Disconnect()

        # Write any commands to the client
        while self.send_queue:
            msg = self.send_queue.pop(0)
            self._send(msg)

        # See if the client has any commands for us.
        if ready_to_read:
            self._handle_incoming()

    def _handle_incoming(self):
        try:
            data = self.request.recv(1024)
        except Exception:
            raise self.Disconnect()

        if not data:
            raise self.Disconnect()

        self.buffer += data
        lines = re.split(b'\r?\n', self.buffer)
        self.buffer = lines.pop()

        for line in lines:
            line = line.decode('utf-8')
            self._handle_line(line)

    def _handle_line(self, line):
        try:
            log.debug('<- %s: %s' % (self.internal_ident, line))
            msg = IRCMessage.from_message(line)
            handler = getattr(self, 'handle_%s' % msg.command.lower(), None)
            if not handler:
                log.info('No handler for command "%s" from client %s',
                         msg.command, self.internal_ident)
                raise IRCError('ERR_UNKNOWNCOMMAND',
                               '%s :Unknown command' % msg.command)
            handler(msg.params)
        except IRCError as e:
            response = ':%s %s %s' % (self.server.servername, e.code, e.value)
            self._send(response)
        except Exception as e:
            response = ':%s ERROR %r' % (self.server.servername, e)
            self._send(response)
            log.error(str(e))
            raise

    def _send(self, msg):
        log.debug('-> %s: %s', self.internal_ident, msg)
        try:
            self.request.send(msg.encode('utf-8') + b'\r\n')
        except socket.error as e:
            if e.errno == errno.EPIPE:
                raise self.Disconnect()
            else:
                raise

    def handle_mode(self, params):
        pass

    def handle_whois(self, params):
        pass

    def handle_cap(self, params):
        pass

    def handle_nick(self, params):
        """
        Handle the initial setting of the user's nickname and nick changes.
        """
        # TODO: handle no nick given, emit 431
        nick = params[0]

        # Valid nickname?
        if re.search('[^a-zA-Z0-9\-\[\]\'`^{}_]', nick):
            raise IRCError('ERR_ERRONEUSNICKNAME', ':%s' % nick)

        if not self.nick:
            # New connection and nick is available; register and send welcome
            # and MOTD.
            self.nick = nick
            self.server.clients.add(self)
            self.server_msg(ircnumeric.codes['RPL_WELCOME'], [self.nick, SRV_WELCOME])
            self.server_msg(ircnumeric.codes['RPL_ENDOFMOTD'], [self.nick])
        else:
            # Nick is available. Change the nick.
            self.nick = nick
            self.client_msg('NICK', nick)

    def handle_user(self, params):
        """
        Handle the USER command which identifies the user to the server.
        """
        if len(params) != 4:
            raise IRCError('ERR_NEEDMOREPARAMS', 'USER :Not enough parameters')

        user, mode, unused, realname = params
        self.user = user
        self.mode = mode
        self.realname = realname

    def handle_ping(self, params):
        """
        Handle client PING requests to keep the connection alive.
        """
        origin = params[0]
        self.server_msg('PONG', [origin])

    def handle_join(self, params):
        """
        Handle the JOINing of a user to a channel. Valid channel names start
        with a # and consist of a-z, A-Z, 0-9 and/or '_' and '.'.
        """
        channel_names = params[0]  # Ignore keys
        for channel_name in channel_names.split(','):
            r_channel_name = channel_name.strip()

            # Valid channel name?
            if not re.match('^#([a-zA-Z0-9_.])+$', r_channel_name):
                raise IRCError('ERR_NOSUCHCHANNEL',
                               '%s :No such channel' % r_channel_name)

            # Add user to the channel (create new channel if not exists)
            channel = self.server.get_channel(r_channel_name)
            channel.clients.add(self)

            # Add channel to user's channel list
            self.channels[channel.name] = channel

            # Send join message yourself
            self.client_msg('JOIN', [r_channel_name])

            self.handle_topic([r_channel_name])
            self.handle_names([r_channel_name])

    def handle_topic(self, params):
        channel = params[0]

        if len(params) > 1:
            raise IRCError('ERR_CHANOPRIVSNEEDED',
                           "%s :You're not channel operator" % channel)
        else:
            self.server_msg(ircnumeric.codes['RPL_TOPIC'], [
                self.nick,
                channel,
                'Welcome to the %s stream' % channel,
                ])

    def handle_names(self, params):
        channel = params[0]

        # Send user list of the channel back to the user.
        # Only return ourselves and the bot, not others in the channel
        nicks = (self.nick, BOTNAME)

        self.server_msg(ircnumeric.codes['RPL_NAMREPLY'], [
            self.nick,
            '=',
            channel,
            ' '.join(nicks),
            ])

        self.server_msg(ircnumeric.codes['RPL_ENDOFNAMES'], [
            self.nick,
            channel,
            'End of /NAMES list',
            ])

    def handle_privmsg(self, params):
        """
        Handle sending a private message to a user or channel.

        No-op in our case, as we only allow the stream to message users.
        """
        target, msg = params[:2]
        if not msg:
            raise IRCError('ERR_NEEDMOREPARAMS', 'PRIVMSG :Not enough parameters')

        if target.startswith('#') or target.startswith('$'):
            raise IRCError('ERR_CANNOTSENDTOCHAN',
                           '%s :Cannot send to channel' % target)
        else:
            raise IRCError('ERR_NOSUCHNICK', 'PRIVMSG :%s' % target)

    def handle_part(self, params):
        """
        Handle a client parting from channel(s).
        """
        for pchannel in params[0].split(','):
            if pchannel.strip() in self.server.channels:
                # Send message to all clients in all channels user is in, and
                # remove the user from the channels.
                channel = self.server.channels.get(pchannel.strip())
                if channel and self in channel.clients:
                    self.client_msg("PART", [pchannel])
                    channel.clients.remove(self)
                    self.channels.pop(pchannel)
            else:
                self.server_msg(ircnumeric.codes['ERR_NOSUCHCHANNEL'],
                                [pchannel, 'No such channel'])

    def handle_quit(self, params):
        """
        Handle the client breaking off the connection with a QUIT command.
        """
        # Remove the user from the channels.
        for channel in self.channels.values():
            channel.clients.remove(self)

        raise self.Disconnect()

    @property
    def client_ident(self):
        """
        Return the client identifier as included in many command replies.
        """
        return '{}!{}@{}'.format(
            self.nick, self.user, self.server.servername)

    @property
    def internal_ident(self):
        """
        Return the internal (non-wire-protocol) client identifier
        """
        return '{}!{}/{}'.format(self.nick, self.user, self.host)

    def finish(self):
        """
        The client conection is finished. Do some cleanup to ensure that the
        client doesn't linger around in any channel or the client list, in case
        the client didn't properly close the connection with PART and QUIT.
        """
        log.info('Client disconnected: %s', self.internal_ident)
        for channel in self.channels.values():
            if self in channel.clients:
                self.client_msg('QUIT', ['EOF from client'])
                channel.clients.remove(self)

        self.server.clients.remove(self)
        log.info('Connection finished: %s', self.internal_ident)

    def __repr__(self):
        """
        Return a user-readable description of the client
        """
        return '<%s %s!%s@%s (%s)>' % (
            self.__class__.__name__,
            self.nick,
            self.user,
            self.host[0],
            self.realname,
            )


class IRCServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    channels = {}
    "Existing channels (IRCChannel instances) by channel name"

    clients = set()
    "Connected clients (IRCClient instances) by nick name"

    def __init__(self, *args, **kwargs):
        self.servername = 'localhost'
        self.channels = {}
        self.clients = set()

        super().__init__(*args, **kwargs)

    def get_channel(self, name):
        """
        Return an IRCChannel for the channel name, creating one if needed
        """
        return self.channels.setdefault(name, IRCChannel(name))

    def broadcast(self, target, msg):
        botid = BOTNAME + "!" + BOTNAME + "@" + self.servername
        message = IRCMessage('PRIVMSG', [target, msg], source=botid)

        channel = self.get_channel(target)
        for client in channel.clients:
            client.send_queue.append(str(message))


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        data = data.decode('utf-8')

        sp = data.split("\t")
        try:
            channel = sp[0].strip()
            text = sp[1].lstrip().replace('\r', '').replace('\n', '')
        except Exception:
            return

        log.debug('Broadcasting to %s: %s' % (channel, text))
        self.server.irc.broadcast(channel, text)


class EchoServer(socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("-a", "--address", dest="listen_address",
                        default='127.0.0.1', help="IP on which to listen")
    parser.add_argument("-p", "--port", dest="listen_port", default=6667,
                        type=int, help="Port on which to listen")
    parser.add_argument("-e", "--echo-port", dest="echo_port", default=9390,
                        type=int, help="Port on which to listen")
    parser.add_argument('-l', '--log-level', dest="log_level", default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        help="Set log level (DEBUG, INFO, WARNING, ERROR)")

    return parser.parse_args()


def main():
    options = get_args()
    logging.basicConfig(level=getattr(logging, options.log_level))

    log.info("Starting IRCStream")

    try:
        irc_bind_address = options.listen_address, options.listen_port
        ircserver = IRCServer(irc_bind_address, IRCClient)
        _tmpl = 'Listening for IRC clients on {listen_address}:{listen_port}'
        log.info(_tmpl.format(**vars(options)))
        irc_thread = threading.Thread(target=ircserver.serve_forever)
        irc_thread.daemon = True
        irc_thread.start()

        echo_bind_address = '', options.echo_port
        echoserver = EchoServer(echo_bind_address, EchoHandler)
        _tmpl = 'Listening for Echo on port {echo_port}'
        log.info(_tmpl.format(**vars(options)))
        echoserver.irc = ircserver

        echo_thread = threading.Thread(target=echoserver.serve_forever)
        echo_thread.daemon = True
        echo_thread.start()

        input()
    except KeyboardInterrupt:
        return
    except socket.error as e:
        log.error(repr(e))
        raise SystemExit(-2)


if __name__ == "__main__":
    main()
