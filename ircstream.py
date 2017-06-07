#!/usr/bin/env python3

# Copyright © 2016 Faidon Liambotis
# Copyright © 2016 Wikimedia Foundation, Inc.
#
# Derived work of https://github.com/jaraco/irc which is
# Copyright © 1999-2002 Joel Rosdahl
# Copyright © 2011-2016 Jason R. Coombs
# Copyright © 2009 Ferry Boender
#
# License: MIT

import argparse
import errno
import logging
import socket
import select
import re
import threading
import socketserver
import events

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
- Alternatively, you can use Wikimedia's RCStream service,
- which streams recent changes as JSON using the WebSockets protocol.
- See https://wikitech.wikimedia.org/wiki/RCStream for details.
"""

log = logging.getLogger("ircstream")


class IRCError(Exception):
    """
    Exception thrown by IRC command handlers to notify client of a
    server/client error.
    """
    def __init__(self, code, value):
        self.code = events.codes[code]
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
        self.user = None
        self.host = client_address  # Client's hostname / ip.
        self.realname = None        # Client's real name
        self.nick = None            # Client's currently registered nickname
        self.send_queue = []        # Messages to send to client (strings)
        self.channels = {}          # Channels the client is in

        super().__init__(request, client_address, server)

    def handle(self):
        log.info('Client connected: %s', self.client_ident())
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
            log.debug('from %s: %s' % (self.client_ident(), line))
            command, sep, params = line.partition(' ')
            handler = getattr(self, 'handle_%s' % command.lower(), None)
            if not handler:
                _tmpl = 'No handler for command: %s. Full line: %s'
                log.info(_tmpl % (command, line))
                raise IRCError('unknowncommand',
                    '%s :Unknown command' % command)
            response = handler(params)
        except AttributeError as e:
            log.error(str(e))
            raise
        except IRCError as e:
            response = ':%s %s %s' % (self.server.servername, e.code, e.value)
        except Exception as e:
            response = ':%s ERROR %r' % (self.server.servername, e)
            log.error(response)
            raise

        if response:
            self._send(response)

    def _send(self, msg):
        log.debug('to %s: %s', self.client_ident(), msg)
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
        nick = params

        # Valid nickname?
        if re.search('[^a-zA-Z0-9\-\[\]\'`^{}_]', nick):
            raise IRCError('erroneusnickname', ':%s' % nick)

        if not self.nick:
            # New connection and nick is available; register and send welcome
            # and MOTD.
            self.nick = nick
            self.server.clients.add(self)
            response = ':%s %s %s :%s' % (self.server.servername,
                events.codes['welcome'], self.nick, SRV_WELCOME)
            self.send_queue.append(response)
            response = ':%s 376 %s :End of MOTD command.' % (
                self.server.servername, self.nick)
            self.send_queue.append(response)
            return
        else:
            # Nick is available. Change the nick.
            self.nick = nick
            message = ':%s NICK :%s' % (self.client_ident(), nick)

            # Send a notification of the nick change to the client itself
            return message

    def handle_user(self, params):
        """
        Handle the USER command which identifies the user to the server.
        """
        params = params.split(' ', 3)

        if len(params) != 4:
            raise IRCError('needmoreparams',
                'USER :Not enough parameters')

        user, mode, unused, realname = params
        self.user = user
        self.mode = mode
        self.realname = realname
        return ''

    def handle_ping(self, params):
        """
        Handle client PING requests to keep the connection alive.
        """
        response = ':{self.server.servername} PONG :{self.server.servername}'
        return response.format(**locals())

    def handle_join(self, params):
        """
        Handle the JOINing of a user to a channel. Valid channel names start
        with a # and consist of a-z, A-Z, 0-9 and/or '_' and '.'.
        """
        channel_names = params.split(' ', 1)[0]  # Ignore keys
        for channel_name in channel_names.split(','):
            r_channel_name = channel_name.strip()

            # Valid channel name?
            if not re.match('^#([a-zA-Z0-9_.])+$', r_channel_name):
                raise IRCError('nosuchchannel',
                    '%s :No such channel' % r_channel_name)

            # Add user to the channel (create new channel if not exists)
            channel = self.server.get_channel(r_channel_name)
            channel.clients.add(self)

            # Add channel to user's channel list
            self.channels[channel.name] = channel

            # Send the topic
            response_join = ':%s TOPIC %s :%s' % (channel.topic_by,
                channel.name, channel.topic)
            self.send_queue.append(response_join)

            # Send join message to everybody in the channel, including yourself
            # and send user list of the channel back to the user.
            response_join = ':%s JOIN :%s' % (self.client_ident(),
                r_channel_name)

            # Only return ourselves and the bot, not others in the channel
            nicks = (self.nick, BOTNAME)

            _vals = (self.server.servername, self.nick, channel.name,
                ' '.join(nicks))
            response_userlist = ':%s 353 %s = %s :%s' % _vals
            self.send_queue.append(response_userlist)

            _vals = self.server.servername, self.nick, channel.name
            response = ':%s 366 %s %s :End of /NAMES list' % _vals
            self.send_queue.append(response)

    def handle_privmsg(self, params):
        """
        Handle sending a private message to a user or channel.

        No-op in our case, as we only allow the stream to message users.
        """
        target, sep, msg = params.partition(' ')
        if not msg:
            raise IRCError('needmoreparams',
                'PRIVMSG :Not enough parameters')

        if target.startswith('#') or target.startswith('$'):
            # Message to channel. Check if the channel exists.
            raise IRCError('cannotsendtochan',
                '%s :Cannot send to channel' % target)
        else:
            raise IRCError('nosuchnick', 'PRIVMSG :%s' % target)

    def handle_part(self, params):
        """
        Handle a client parting from channel(s).
        """
        for pchannel in params.split(','):
            if pchannel.strip() in self.server.channels:
                # Send message to all clients in all channels user is in, and
                # remove the user from the channels.
                channel = self.server.channels.get(pchannel.strip())
                response = ':%s PART :%s' % (self.client_ident(), pchannel)

                if channel and self in channel.clients:
                    self.send_queue.append(response)
                    channel.clients.remove(self)
                    self.channels.pop(pchannel)
            else:
                _vars = self.server.servername, pchannel, pchannel
                response = ':%s 403 %s :%s' % _vars
                self.send_queue.append(response)

    def handle_quit(self, params):
        """
        Handle the client breaking off the connection with a QUIT command.
        """
        response = ':%s QUIT :%s' % (self.client_ident(), params.lstrip(':'))
        # Send quit message to all clients in all channels user is in, and
        # remove the user from the channels.
        for channel in self.channels.values():
            self.send_queue.append(response)
            channel.clients.remove(self)

    def client_ident(self):
        """
        Return the client identifier as included in many command replies.
        """
        return '{}!{}@{}'.format(
            self.nick, self.user, self.server.servername)

    def finish(self):
        """
        The client conection is finished. Do some cleanup to ensure that the
        client doesn't linger around in any channel or the client list, in case
        the client didn't properly close the connection with PART and QUIT.
        """
        log.info('Client disconnected: %s', self.client_ident())
        response = ':%s QUIT :EOF from client' % self.client_ident()
        for channel in self.channels.values():
            if self in channel.clients:
                # Client is gone without properly QUITing or PARTing this
                # channel.
                self.send_queue.append(response)
                channel.clients.remove(self)

        self.server.clients.remove(self)
        log.info('Connection finished: %s', self.client_ident())

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
        message = ':%s PRIVMSG %s %s' % (botid, target, msg)

        channel = self.get_channel(target)
        for client in channel.clients:
            client.send_queue.append(message)


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        data = data.decode('utf-8')

        log.debug('received: %s' % data)

        sp = data.split("\t")
        if len(sp) != 2:
            return

        channel = sp[0].strip()
        text = sp[1].lstrip().replace('\r', '').replace('\n', '')

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
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
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
    except socket.error as e:
        log.error(repr(e))
        raise SystemExit(-2)


if __name__ == "__main__":
    main()
