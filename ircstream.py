#!/usr/bin/env python3

# Copyright © 2016-2019 Faidon Liambotis
# Copyright © 2016-2019 Wikimedia Foundation, Inc.
#
# Derived work of https://github.com/jaraco/irc which is
# Copyright © 1999-2002 Joel Rosdahl
# Copyright © 2011-2016 Jason R. Coombs
# Copyright © 2009 Ferry Boender
#
# License: MIT

# Useful references:
# * Modern IRC Client Protocol https://modern.ircdocs.horse/
# * RFC 1459, RFC 2812

# TODO:
# - handle WHO better
# =================
# ----------------------------------------
# Exception happened during processing of request from ('127.0.0.1', 43218)
# Traceback (most recent call last):
#   File "ircstream.py", line 227, in handle
#   File "ircstream.py", line 250, in _handle_one
#   File "ircstream.py", line 266, in _handle_incoming
#     self.buffer = lines.pop()
#   File "ircstream.py", line 287, in _handle_line
#     self.internal_ident,
#   File "ircstream.py", line 615, in handle_quit
# IRCClient.Disconnect
#
# During handling of the above exception, another exception occurred:
#
# Traceback (most recent call last):
#   File "/usr/lib/python3.7/socketserver.py", line 650, in process_request_thread
#     self.finish_request(request, client_address)
#   File "/usr/lib/python3.7/socketserver.py", line 360, in finish_request
#     self.RequestHandlerClass(request, client_address, self)
#   File "ircstream.py", line 197, in __init__
#     self.send_queue = []  # Messages to send to client (strings)
#   File "/usr/lib/python3.7/socketserver.py", line 720, in __init__
#     self.handle()
#   File "ircstream.py", line 229, in handle
#     while True:
# OSError: [Errno 107] Transport endpoint is not connected
# ----------------------------------------
# =================
# - handle LIST
# =================
# - pylint!
# - strong typing
# - IPv6 support
# =================
# - (reverse) ping
# =================
# - revisit client ident + internal ident
#   + say "unregistered" if !self.registered
# - CHANMODES in end_registration?
# - logging overhaul
#   + context with client ID?
#   + structured logging?
# =================
# - remove source from server messages and handle it on client messages
#    + https://modern.ircdocs.horse/#source
# - handle numerics from client...?
# - cleanup IRCMessage
# - better docstrings
# - add PINGs
# - add a timeout if you're not part of any channels
# - add statistics/introspection (Prometheus?)
# - tests!
#   + https://a3nm.net/git/irctk/about
#   + https://github.com/DanielOaks/irc-parser-tests
# - make network/botname/motd configurable
# - SSL (separate port? STARTTLS? STS?)
# - Kafka and/or SSE

import argparse
import datetime
import errno
import logging
import re
import select
import socket
import socketserver
import threading

from ircnumeric import RPL, ERR

__version__ = "0.1"

NETWORK = "Wikimedia"
BOTNAME = "rc-pmtpa"
SRV_WELCOME = """
*******************************************************
This is the Wikimedia RC->IRC gateway

https://wikitech.wikimedia.org/wiki/Irc.wikimedia.org
*******************************************************
Sending messages to channels is not allowed.

A channel exists for all Wikimedia wikis which have been
changed since the last time the server was restarted. In
general, the name is just the domain name with the .org
left off. For example, the changes on the English Wikipedia
are available at #en.wikipedia

If you want to talk, please join one of the many
Wikimedia-related channels on irc.freenode.net.

Alternatively, you can use Wikimedia's EventStreams service,
which streams recent changes as JSON using the SSE protocol.
See https://wikitech.wikimedia.org/wiki/EventStreams for details.
"""

log = logging.getLogger("ircstream")


class IRCMessage(object):
    def __init__(self, command, params=[], source=None):
        self.command = command
        self.params = params
        self.source = source

    @classmethod
    def from_message(cls, message):
        s = message.split(" ")

        source = None
        if s[0].startswith(":"):
            source = s[0][1:]
            s = s[1:]

        command = s[0].upper()
        original_params = s[1:]
        params = []

        while len(original_params):
            # skip multiple spaces in middle of message, as per 1459
            if original_params[0] == "" and len(original_params) > 1:
                original_params.pop(0)
                continue
            elif original_params[0].startswith(":"):
                arg = " ".join(original_params)[1:]
                params.append(arg)
                break
            else:
                params.append(original_params.pop(0))

        return cls(command, params, source)

    def __str__(self):
        components = []

        if self.source:
            components.append(":" + self.source)

        components.append(self.command)

        if self.params:
            base = []
            for arg in self.params:
                casted = str(arg)
                if casted and " " not in casted and casted[0] != ":":
                    base.append(casted)
                else:
                    base.append(":" + casted)
                    break

            components.append(" ".join(base))

        return " ".join(components)

    def __repr__(self):
        return '<IRCMessage: "{0}">'.format(self.command)


class IRCError(Exception):
    """
    Exception thrown by IRC command handlers to notify client of a
    server/client error.
    """

    def __init__(self, command, params):
        self.command = command
        self.params = params


class IRCChannel(object):
    """
    An IRC channel.
    """

    def __init__(self, name, topic="No topic"):
        self.name = name
        self.topic_by = "Unknown"
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
        self.host = client_address
        self.registered = False
        self.user = None
        self.realname = None  # Client's real name
        self.nick = None  # Client's currently registered nickname
        self.send_queue = []  # Messages to send to client (strings)
        self.channels = {}  # Channels the client is in

        super().__init__(request, client_address, server)

    def msg(self, command, params, sync=False):
        # allow a single bare string as a parameter, for convenience
        if type(params) == str:
            params = [params]

        if command == "ERROR":
            source = None
        elif type(command) == RPL or type(command) == ERR or command == "PONG":
            source = self.server.servername
        else:
            source = self.client_ident

        if type(command) == RPL or type(command) == ERR:
            command = str(command)
            # always start replies with the client's nickname
            if self.nick:
                params.insert(0, self.nick)
            else:
                params.insert(0, "*")

        msg = IRCMessage(command, params, source)
        if sync:
            self._send(str(msg))
        else:
            self.send_queue.append(str(msg))

    def handle(self):
        log.info("Client connected: [%s]:%s", *self.host[:2])
        self.buffer = b""

        try:
            while True:
                self._handle_one()
        except self.Disconnect:
            self.request.shutdown(socket.SHUT_RDWR)
            self.request.close()

    def _handle_one(self):
        """
        Handle one read/write cycle.
        """
        ready_to_read, ready_to_write, in_error = select.select(
            [self.request], [], [self.request], 0.1
        )

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
        lines = re.split(b"\r?\n", self.buffer)
        self.buffer = lines.pop()

        for line in lines:
            self._handle_line(line)

    def _handle_line(self, line):
        try:
            line = line.decode("utf-8").strip()
            # ignore empty lines
            if not line:
                return
            log.debug("<- %s: %s", self.internal_ident, line)
            msg = IRCMessage.from_message(line)

            non_registered_cmds = ("USER", "NICK", "QUIT", "PING")
            if not self.registered and msg.command not in non_registered_cmds:
                raise IRCError(ERR.NOTREGISTERED, "You have not registered")

            handler = getattr(self, f"handle_{msg.command.lower()}", None)
            if not handler:
                log.debug(
                    'No handler for command "%s" (client %s)',
                    msg.command,
                    self.internal_ident,
                )
                raise IRCError(ERR.UNKNOWNCOMMAND, [msg.command, "Unknown command"])
            handler(msg.params)
        except IRCError as exc:
            self.msg(exc.command, exc.params)
        except UnicodeDecodeError:
            return
        except Exception as exc:
            self.msg("ERROR", f"Internal server error ({exc})")
            log.exception("Internal server error: %s", exc)

    def _send(self, msg):
        log.debug("-> %s: %s", self.internal_ident, msg)
        try:
            self.request.send(msg.encode("utf-8") + b"\r\n")
        except UnicodeEncodeError:
            log.debug("Internal encoding error: %s", exc)
        except socket.error as exc:
            if exc.errno == errno.EPIPE:
                raise self.Disconnect()
            else:
                raise

    def handle_cap(self, params):
        """Stub for the CAP (capability) command."""
        raise IRCError(ERR.UNKNOWNCOMMAND, ["CAP", "Unknown command"])

    def handle_who(self, params):
        """Stub for the WHO command."""
        self.msg(RPL.ENDOFWHO, ["*", "End of /WHO list."])

    def handle_mode(self, params):
        """Handle the MODE command, for both channel and user modes."""
        try:
            target = params[0]
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["MODE", "Not enough parameters"])

        if target.startswith("#"):
            # channel modes
            if len(params) > 1:
                raise IRCError(
                    ERR.CHANOPRIVSNEEDED, [target, "You're not a channel operator"]
                )
            else:
                self.msg(RPL.CHANNELMODEIS, [target, "+mts"])
        else:
            # user modes
            if len(params) > 1:
                # could raise ERR.UMODEUNKNOWNFLAG/"Unknown MODE flag" here
                # but common clients send a MODE at startup, making this noisy
                pass
            elif target == self.nick:
                self.msg(RPL.UMODEIS, "+i")
            elif target == BOTNAME:
                raise IRCError(ERR.USERSDONTMATCH, "Can't change mode for other users")
            else:
                raise IRCError(ERR.NOSUCHNICK, [target, "No such nick/channel"])

    def handle_whois(self, params):
        """Handle the WHOIS command."""
        if len(params) == 2:
            nicklist = params[1]
        elif len(params) == 1:
            nicklist = params[0]
        else:
            raise IRCError(ERR.NONICKNAMEGIVEN, "No nickname given")

        # ignore queries for multiple users (as some networks do)
        nickmask = nicklist.split(",")[0]

        def whois_reply(nick, user, host, realname):
            # "<host> CANNOT start with a colon as this would get parsed as a
            # trailing parameter – IPv6 addresses such as "::1" are prefixed
            # with a zero to ensure this."
            if host.startswith(":"):
                host = "0" + host
            self.msg(RPL.WHOISUSER, [nick, user, host, "*", realname])
            servername = self.server.servername
            self.msg(RPL.WHOISSERVER, [nick, servername, "IRCStream"])
            self.msg(RPL.WHOISIDLE, [nick, "0", "seconds idle"])

        if nickmask == self.nick:
            whois_reply(self.nick, self.user, self.host[0], self.realname)
        elif nickmask == BOTNAME:
            whois_reply(BOTNAME, BOTNAME, self.server.servername, BOTNAME)
        else:
            # not an IRCError, because we need to send NOSUCHNICK after it
            self.msg(ERR.NOSUCHNICK, [nickmask, "No such nick/channel"])

        # nicklist and not nickmask, on purpose
        self.msg(RPL.ENDOFWHOIS, [nicklist, "End of /WHOIS list"])

    def handle_nick(self, params):
        """Handle the initial setting of the user's nickname and nick changes."""
        try:
            nick = params[0]
        except IndexError:
            raise IRCError(ERR.NONICKNAMEGIVEN, "No nickname given")

        # is this a valid nickname?
        if re.search("[^a-zA-Z0-9\-\[\]'`^{}_]", nick):
            raise IRCError(ERR.ERRONEUSNICKNAME, [nick, "Erroneus nickname"])

        if not self.registered:
            self.nick = nick
            if self.nick and self.user:
                self.end_registration()
        else:
            # existing registration, but changing nicks
            self.msg("NICK", [nick])
            self.nick = nick

    def handle_user(self, params):
        """Handle the USER command which identifies the user to the server."""
        try:
            user, _, _, realname = params[:4]
        except ValueError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["USER", "Not enough parameters"])

        if self.registered:
            raise IRCError(ERR.ALREADYREGISTERED, "You may not reregister")

        self.user = user
        self.realname = realname

        # we have both USER and NICK, end registration
        if self.nick and self.user:
            self.end_registration()

    def end_registration(self):
        """
        End the registration process.

        Called after both USER and NICK have been given. Responds with a whole
        chain of replies, as appropriate.
        """
        self.registered = True
        self.msg(RPL.WELCOME, "Welcome to IRCStream")
        self.msg(
            RPL.YOURHOST,
            f"Your host is {self.server.servername}, running version {__version__}",
        )
        self.msg(RPL.CREATED, f"This server was created {self.server.boot_time:%c}")
        self.msg(
            RPL.MYINFO, f"{self.server.servername} {__version__} i bklmtns",
        )
        self.msg(
            RPL.ISUPPORT,
            [
                f"NETWORK={NETWORK}",
                "CASEMAPPING=rfc1459",
                "CHANLIMIT=#:20000",
                "CHANMODES=b,k,l,mtns",
                "CHANNELLEN=50",
                "CHANTYPES=#",
                "PREFIX=",
                "SAFELIST",
                "are available on this server",
            ],
        )
        self.msg(RPL.UMODEIS, "+i")
        self.handle_motd([])
        self.server.clients.add(self)

    def handle_motd(self, params):
        """Handle the MOTD command. Also called once a client first connects."""
        self.msg(RPL.MOTDSTART, "- Message of the day -")
        for line in SRV_WELCOME.strip().split("\n"):
            self.msg(RPL.MOTD, "- " + line)
        self.msg(RPL.ENDOFMOTD, "End of /MOTD command.")

    def handle_ping(self, params):
        """Handle client PING requests to keep the connection alive."""
        try:
            origin = params[0]
        except IndexError:
            raise IRCError(ERR.NOORIGIN, "No origin specified")

        try:
            destination = params[1]
        except IndexError:
            destination = self.server.servername

        self.msg("PONG", [destination, origin])

    def handle_join(self, params):
        """
        Handle the JOINing of a user to a channel. Valid channel names start
        with a # and consist of a-z, A-Z, 0-9 and/or '_' and '.'.
        """
        try:
            channels = params[0]  # ignore param 1, i.e. channel keys
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["JOIN", "Not enough parameters"])

        for channel in channels.split(","):
            channel = channel.strip()

            # is this a valid channel name?
            if not re.match("^#([a-zA-Z0-9_.])+$", channel):
                raise IRCError(ERR.NOSUCHCHANNEL, [channel, "No such channel"])

            # add user to the channel (create new channel if not exists)
            channelobj = self.server.get_channel(channel)
            channelobj.clients.add(self)

            # add channel to user's channel list
            self.channels[channelobj.name] = channelobj

            # send join message
            self.msg("JOIN", channel)
            self.handle_topic([channel])
            self.handle_names([channel])

    def handle_topic(self, params):
        """
        Handle the TOPIC command. Show a pregenerated topic and timestamp when
        asked for one, and always deny setting the topic.
        """
        try:
            channel = params[0]
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["TOPIC", "Not enough parameters"])

        if channel not in self.channels:
            raise IRCError(ERR.NOTONCHANNEL, [channel, "You're not on that channel"])

        # if a new topic was given...
        if len(params) > 1:
            raise IRCError(
                ERR.CHANOPRIVSNEEDED, [channel, "You're not a channel operator"]
            )

        self.msg(RPL.TOPIC, [channel, f"Welcome to the {channel} stream"])
        botid = BOTNAME + "!" + BOTNAME + "@" + self.server.servername
        self.msg(
            RPL.TOPICWHOTIME, [channel, botid, int(self.server.boot_time.timestamp())]
        )

    def handle_names(self, params):
        """
        Handle the NAMES command. Every channel has the "bot" connected,
        plus, optionally, the connecting client.
        """
        try:
            channels = params[0]
        except IndexError:
            self.msg(RPL.ENDOFNAMES, ["*", "End of /NAMES list"])
            return

        # ignore queries for multiple channels (as some networks do)
        channel = channels.split(",")[0].strip()

        if channel in self.channels:
            nicklist = (self.nick, BOTNAME)
        else:
            nicklist = (BOTNAME,)

        self.msg(RPL.NAMREPLY, ["=", channel, " ".join(nicklist)])
        self.msg(RPL.ENDOFNAMES, [channel, "End of /NAMES list"])

    def handle_privmsg(self, params):
        """
        Handle sending a message to a user or channel.
        No-op in our case, as we only allow the bot to message users.
        """
        try:
            targets, msg = params[:2]
        except ValueError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["PRIVMSG", "Not enough parameters"])

        for target in targets.split(","):
            target = target.strip()

            if target.startswith("#"):
                self.msg(ERR.CANNOTSENDTOCHAN, [target, "Cannot send to channel"])
            elif target == BOTNAME:
                # bot ignores all messages
                pass
            elif target == self.nick:
                # echo back
                self.msg("PRIVMSG", [target, msg])
            else:
                self.msg(ERR.NOSUCHNICK, [target, "No such nick/channel"])

    def handle_part(self, params):
        """
        Handle the PART command.
        """
        try:
            channels = params[0]
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["PART", "Not enough parameters"])

        for channel in channels.split(","):
            channel = channel.strip()

            if channel in self.channels:
                channelobj = self.channels.pop(channel)
                channelobj.clients.remove(self)
                self.msg("PART", channel)
            else:
                # don't raise IRCError because this can be one of many channels
                self.msg(ERR.NOTONCHANNEL, [channel, "You're not on that channel"])

    def handle_quit(self, params):
        """
        Handle the client breaking off the connection with a QUIT command.
        """
        # Remove the user from the channels.
        for channel in self.channels.values():
            channel.clients.remove(self)

        try:
            reason = params[0]
        except IndexError:
            reason = "No reason"

        self.msg("ERROR", f"Closing Link: (Quit: {reason})", sync=True)
        raise self.Disconnect()

    @property
    def client_ident(self):
        """
        Return the client identifier as included in many command replies.
        """
        return f"{self.nick}!{self.user}@{self.server.servername}"

    @property
    def internal_ident(self):
        """
        Return the internal (non-wire-protocol) client identifier
        """
        return f"{self.nick}!{self.user}/{self.host[0]}:{self.host[1]}"

    def finish(self):
        """
        The client conection is finished. Do some cleanup to ensure that the
        client doesn't linger around in any channel or the client list, in case
        the client didn't properly close the connection with PART and QUIT.
        """
        log.info("Client disconnected: %s", self.internal_ident)
        for channel in self.channels.values():
            if self in channel.clients:
                self.msg("QUIT", "EOF from client")
                channel.clients.remove(self)

        try:
            self.server.clients.remove(self)
        except KeyError:
            # was never added, e.g. if was never identified
            pass
        log.info("Connection finished: %s", self.internal_ident)

    def __repr__(self):
        """
        Return a user-readable description of the client
        """
        return f"<{self.__class__.__name__} {self.internal_ident} {self.realname}>"


class IRCServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    channels = {}
    "Existing channels (IRCChannel instances) by channel name"

    clients = set()
    "Connected clients (IRCClient instances) by nick name"

    def __init__(self, *args, **kwargs):
        self.servername = "localhost"  # TODO
        self.boot_time = datetime.datetime.utcnow()
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
        message = IRCMessage("PRIVMSG", [target, msg], source=botid)

        channel = self.get_channel(target)
        for client in channel.clients:
            client.send_queue.append(str(message))


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        try:
            data = data.decode("utf-8")
            sp = data.split("\t")
            channel = sp[0].strip()
            text = sp[1].lstrip().replace("\r", "").replace("\n", "")
        except:
            return

        log.debug("Broadcasting to %s: %s", channel, text)
        self.server.irc.broadcast(channel, text)


class EchoServer(socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-a",
        "--address",
        dest="listen_address",
        default="127.0.0.1",
        help="IP on which to listen",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="listen_port",
        default=6667,
        type=int,
        help="Port on which to listen",
    )
    parser.add_argument(
        "-e",
        "--echo-port",
        dest="echo_port",
        default=9390,
        type=int,
        help="Port on which to listen",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        dest="log_level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set log level (DEBUG, INFO, WARNING, ERROR)",
    )

    return parser.parse_args()


def main():
    options = get_args()
    logging.basicConfig(level=getattr(logging, options.log_level))

    log.info("Starting IRCStream")

    try:
        irc_bind_address = options.listen_address, options.listen_port
        ircserver = IRCServer(irc_bind_address, IRCClient)
        log.info(
            f"Listening for IRC clients on {options.listen_address}:{options.listen_port}"
        )
        irc_thread = threading.Thread(target=ircserver.serve_forever)
        irc_thread.daemon = True
        irc_thread.start()

        echo_bind_address = "", options.echo_port
        echoserver = EchoServer(echo_bind_address, EchoHandler)
        log.info(f"Listening for Echo on port {options.echo_port}")
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
