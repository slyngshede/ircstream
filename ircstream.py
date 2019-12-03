#!/usr/bin/env python3
"""IRCStream -- Wikimedia RC->IRC gateway

This is a simple gateway to the Wikimedia recent changes feed, using the IRC
protocol. It was made mainly for compatibility reasons, as there are a number
of legacy clients using this interface.

This software presents itself as an IRC server, with limited functionality.
Sending messages to channels or other users is not allowed. Each user is within
their own little bubble, unable to see or interact with other connected users,
except for the recent changes bot. Overlapping usernames are allowed.

A channel is created opportunistically as users join channels, and matched
against the feed to announce new changes. In general, the name is just the
domain name with the .org left off. For example, the changes on the English
Wikipedia are available at #en.wikipedia.
"""

__version__ = "0.9.0"
__author__ = "Faidon Liambotis"
__copyright__ = """
Copyright © 2016-2019 Faidon Liambotis
Copyright © 2016-2019 Wikimedia Foundation, Inc.
Copyright © 2011-2016 Jason R. Coombs
Copyright © 2009 Ferry Boender
Copyright © 1999-2002 Joel Rosdahl
"""
__license__ = """
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY CODE, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

# This includes some (heavily modified) code from https://github.com/jaraco/irc
#
# Other useful references:
# * RFC 1459, RFC 2812
# * Modern IRC Client Protocol https://modern.ircdocs.horse/
# * IRC Definition files https://defs.ircdocs.horse/defs/

import argparse
import datetime
import enum
import errno
import logging
import re
import select
import socket
import socketserver
import threading
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

import prometheus_client  # type: ignore

SERVERNAME = "irc.wikimedia.org"
NETWORK = "Wikimedia"
BOTNAME = "rc-pmtpa"
TOPIC_TMPL = "Stream for topic {}"
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


logger = logging.getLogger("ircstream")  # pylint: disable=invalid-name
log = logging.LoggerAdapter(logger, {"host": "", "client_id": ""})  # pylint: disable=invalid-name


class IRCNumeric(enum.Enum):
    """Base class for IRC numeric enums"""

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}_{self.name}"


class RPL(IRCNumeric):
    """Standard IRC RPL_* replies, as defined in RFCs"""

    WELCOME = "001"
    YOURHOST = "002"
    CREATED = "003"
    MYINFO = "004"
    ISUPPORT = "005"
    UMODEIS = "221"
    WHOISUSER = "311"
    WHOISSERVER = "312"
    ENDOFWHO = "315"
    WHOISIDLE = "317"
    ENDOFWHOIS = "318"
    LIST = "322"
    LISTEND = "323"
    CHANNELMODEIS = "324"
    TOPIC = "332"
    TOPICWHOTIME = "333"
    NAMREPLY = "353"
    ENDOFNAMES = "366"
    ENDOFBANLIST = "368"
    MOTD = "372"
    MOTDSTART = "375"
    ENDOFMOTD = "376"


class ERR(IRCNumeric):
    """Erroneous IRC ERR_* replies, as defined in RFCs"""

    NOSUCHNICK = "401"
    NOSUCHCHANNEL = "403"
    CANNOTSENDTOCHAN = "404"
    NOORIGIN = "409"
    UNKNOWNCOMMAND = "421"
    NONICKNAMEGIVEN = "431"
    ERRONEUSNICKNAME = "432"
    NOTONCHANNEL = "442"
    NOTREGISTERED = "451"
    NEEDMOREPARAMS = "461"
    ALREADYREGISTERED = "462"
    CHANOPRIVSNEEDED = "482"
    UMODEUNKNOWNFLAG = "501"
    USERSDONTMATCH = "502"


class IRCMessage:
    """Represents an RFC 1459/2681 message.

    Can be either initialized:
    * with its constructor using a command, params and (optionally) a source
    * given a preformatted string, using the from_message() class method
    """

    def __init__(self, command: str, params: Iterable[str], source: Optional[str] = None) -> None:
        self.command = command
        self.params = params
        self.source = source

    @classmethod
    def from_message(cls, message: str) -> "IRCMessage":
        """Parses a previously formatted IRC message.

        Returns an instance of IRCMessage, that one can query for self.command
        and self.params.
        """
        parts = message.split(" ")

        source = None
        if parts[0].startswith(":"):
            source = parts[0][1:]
            parts = parts[1:]

        command = parts[0].upper()
        original_params = parts[1:]
        params = []

        while original_params:
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

    def __str__(self) -> str:
        """Generates an RFC-compliant formatted string for the instance."""
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

    def __repr__(self) -> str:
        return '<IRCMessage: "{0}">'.format(self.command)


class IRCError(Exception):
    """Exception thrown by IRC command handlers to notify client of a server/client error."""

    def __init__(self, command: Union[str, IRCNumeric], params: Union[List[str], str]) -> None:
        super().__init__()
        self.command = command
        self.params = params


class IRCChannel:
    """Represents an IRC channel."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._clients: Set[IRCClient] = set()
        self._lock = threading.Lock()

    def add_member(self, client: "IRCClient") -> None:
        """Adds a client to the channel (race-free)."""
        with self._lock:
            self._clients.add(client)

    def remove_member(self, client: "IRCClient") -> None:
        """Removes a client from a channel (race-free).

        No-op if they weren't there already."""
        with self._lock:
            try:
                self._clients.remove(client)
            except KeyError:
                pass

    def members(self) -> Iterable["IRCClient"]:
        """Lists the clients in the channel."""
        with self._lock:
            clients = list(self._clients)
        return clients


class IRCClient(socketserver.BaseRequestHandler):
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """IRC client connect and command handling.

    Client connection is handled by the ``handle`` method which sets up a
    two-way communication with the client.  It then handles commands sent by
    the client by dispatching them to the ``handle_`` methods.
    """

    server: "IRCServer"

    class Disconnect(BaseException):
        """Raised when we are about to be disconnected from the client."""

    def __init__(self, request: Any, client_address: Any, server: "IRCServer") -> None:
        self.host, self.port = client_address[:2]
        # trim IPv4 mapped prefix
        if self.host.startswith("::ffff:"):
            self.host = self.host[len("::ffff:") :]

        context = {"ip": self.host, "client_id": f"[{self.host}]:{self.port}"}
        self.log = logging.LoggerAdapter(logger, context)

        self.signon = datetime.datetime.utcnow()
        self.keepalive = (self.signon, False)  # (last_heard, ping_sent)
        self.buffer = b""
        self.user, self.realname, self.nick = "", "", ""
        self.send_queue: List[str] = []
        self.channels: Dict[str, IRCChannel] = {}

        super().__init__(request, client_address, server)  # type: ignore

    def msg(self, command: Union[str, IRCNumeric], params: Union[List[str], str], sync: bool = False) -> None:
        """Prepares and queues a response to the client.

        This generally does the right thing, and reduces boilerplate by
          * using the correct source depending on the command;
          * prepending the client nickname on replies/errors.
        """
        # allow a single bare string as a parameter, for convenience
        if isinstance(params, str):
            params = [params]

        if command in ("PING", "ERROR"):
            source = None
        elif isinstance(command, (RPL, ERR)) or command == "PONG":
            source = self.server.servername
        else:
            source = self.client_ident

        if isinstance(command, (RPL, ERR)):
            # always start replies with the client's nickname
            if self.nick:
                params.insert(0, self.nick)
            else:
                params.insert(0, "*")

        msg = IRCMessage(str(command), params, source)
        if sync:
            self._send(str(msg))
        else:
            self.send_queue.append(str(msg))

    def handle(self) -> None:
        """Handle a new connection from a client."""
        self.log.info("Client connected")
        self.buffer = b""

        try:
            while True:
                self._handle_one()
        except self.Disconnect:
            self.request.close()

    def _handle_one(self) -> None:
        """Handles one read/write cycle."""
        ready_to_read, _, in_error = select.select([self.request], [], [self.request], 0.1)

        if in_error:
            raise self.Disconnect()

        timeout = 60
        # if we haven't heard in N seconds, disconnect
        delta = datetime.datetime.utcnow() - self.keepalive[0]
        if delta > datetime.timedelta(seconds=timeout):
            raise self.Disconnect()

        # if we haven't heard in N/4 seconds, send a PING
        if delta > datetime.timedelta(seconds=timeout / 4) and not self.keepalive[1]:
            self.msg("PING", self.server.servername)
            self.keepalive = (self.keepalive[0], True)

        # write any commands to the client
        while self.send_queue:
            msg = self.send_queue.pop(0)
            self._send(msg)

        # see if the client has any commands for us
        if ready_to_read:
            self._handle_incoming()

    def _handle_incoming(self) -> None:
        """Receives data from a client.

        Splits into multiple lines, and call _handle_line() for each.
        """
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

    def _handle_line(self, bline: bytes) -> None:
        """Handles a single line of input (i.e. a command and arguments)."""
        try:
            line = bline.decode("utf-8").strip()
            # ignore empty lines
            if not line:
                return
            self.log.debug("<- %s", line)
            msg = IRCMessage.from_message(line)

            whitelisted = ("CAP", "PASS", "USER", "NICK", "QUIT", "PING", "PONG")
            if not (self.nick and self.user) and msg.command not in whitelisted:
                raise IRCError(ERR.NOTREGISTERED, "You have not registered")

            handler = getattr(self, f"handle_{msg.command.lower()}", None)
            if not handler:
                self.log.debug('No handler for command "%s"', msg.command)
                raise IRCError(ERR.UNKNOWNCOMMAND, [msg.command, "Unknown command"])
            handler(msg.params)
        except IRCError as exc:
            self.msg(exc.command, exc.params)
        except UnicodeDecodeError:
            return
        except Exception as exc:  # pylint: disable=broad-except
            self.server.metrics["errors"].labels("ise").inc()
            self.msg("ERROR", f"Internal server error ({exc})")
            self.log.exception("Internal server error: %s", exc)

    def _send(self, msg: str) -> None:
        """Sends a message to a connected client."""
        self.log.debug("-> %s", msg)
        try:
            self.request.send(msg.encode("utf-8") + b"\r\n")
        except UnicodeEncodeError as exc:
            self.log.debug("Internal encoding error: %s", exc)
        except socket.error as exc:
            if exc.errno == errno.EPIPE:
                raise self.Disconnect()
            raise

    def handle_cap(self, params: List[str]) -> None:  # pylint: disable=no-self-use
        """Stub for the CAP (capability) command."""
        raise IRCError(ERR.UNKNOWNCOMMAND, ["CAP", "Unknown command"])

    def handle_who(self, params: List[str]) -> None:
        """Stub for the WHO command."""
        try:
            mask = params[0]
        except IndexError:
            mask = "*"
        self.msg(RPL.ENDOFWHO, [mask, "End of /WHO list."])

    def handle_mode(self, params: List[str]) -> None:
        """Handles the MODE command, for both channel and user modes."""
        try:
            target = params[0]
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["MODE", "Not enough parameters"])

        modestring: Optional[str]
        try:
            modestring = params[1]
        except IndexError:
            modestring = None

        if target.startswith("#"):
            # channel modes
            if modestring is None:
                self.msg(RPL.CHANNELMODEIS, [target, "+mts"])
            elif modestring == "b":
                self.msg(RPL.ENDOFBANLIST, [target, "End of channel ban list"])
            else:
                raise IRCError(ERR.CHANOPRIVSNEEDED, [target, "You're not a channel operator"])
        else:
            # user modes
            if modestring:
                # could raise ERR.UMODEUNKNOWNFLAG/"Unknown MODE flag" here
                # but common clients send a MODE at startup, making this noisy
                pass
            elif target == self.nick:
                self.msg(RPL.UMODEIS, "+i")
            elif target == BOTNAME:
                raise IRCError(ERR.USERSDONTMATCH, "Can't change mode for other users")
            else:
                raise IRCError(ERR.NOSUCHNICK, [target, "No such nick/channel"])

    def handle_whois(self, params: List[str]) -> None:
        """Handles the WHOIS command."""
        if len(params) == 2:
            nicklist = params[1]
        elif len(params) == 1:
            nicklist = params[0]
        else:
            raise IRCError(ERR.NONICKNAMEGIVEN, "No nickname given")

        # ignore queries for multiple users (as some networks do)
        nickmask = nicklist.split(",")[0]

        def whois_reply(nick: str, user: str, host: str, realname: str, signon: datetime.datetime) -> None:
            # "<host> CANNOT start with a colon as this would get parsed as a
            # trailing parameter – IPv6 addresses such as "::1" are prefixed
            # with a zero to ensure this."
            if host.startswith(":"):
                host = "0" + host
            self.msg(RPL.WHOISUSER, [nick, user, host, "*", realname])
            servername = self.server.servername
            self.msg(RPL.WHOISSERVER, [nick, servername, "IRCStream"])
            self.msg(RPL.WHOISIDLE, [nick, "0", str(int(signon.timestamp())), "seconds idle, signon time"])

        if nickmask == self.nick:
            whois_reply(self.nick, self.user, self.host, self.realname, self.signon)
        elif nickmask == BOTNAME:
            whois_reply(BOTNAME, BOTNAME, self.server.servername, BOTNAME, self.server.boot_time)
        else:
            raise IRCError(ERR.NOSUCHNICK, [nickmask, "No such nick/channel"])

        # nicklist and not nickmask, on purpose
        self.msg(RPL.ENDOFWHOIS, [nicklist, "End of /WHOIS list"])

    def handle_nick(self, params: List[str]) -> None:
        """Handles the initial setting of the user's nickname and nick changes."""
        try:
            nick = params[0]
        except IndexError:
            raise IRCError(ERR.NONICKNAMEGIVEN, "No nickname given")

        # is this a valid nickname?
        if re.search(r"[^a-zA-Z0-9\-\[\]'`^{}_]", nick) or len(nick) < 2:
            raise IRCError(ERR.ERRONEUSNICKNAME, [nick, "Erroneus nickname"])

        if not (self.nick and self.user):
            self.nick = nick
            if self.user:
                self.end_registration()
        else:
            # existing registration, but changing nicks
            self.msg("NICK", [nick])
            self.nick = nick

    def handle_user(self, params: List[str]) -> None:
        """Handles the USER command which identifies the user to the server."""
        try:
            user, _, _, realname = params[:4]
        except ValueError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["USER", "Not enough parameters"])

        if self.user:
            raise IRCError(ERR.ALREADYREGISTERED, "You may not reregister")

        self.user = user
        self.realname = realname

        # we have both USER and NICK, end registration
        if self.nick:
            self.end_registration()

    def end_registration(self) -> None:
        """Ends the registration process.

        Called after both USER and NICK have been given. Responds with a whole
        chain of replies, as appropriate.
        """
        cmodes = ("b", "k", "l", "mtns")  # channel modes, types A-D

        self.msg(RPL.WELCOME, "Welcome to IRCStream")
        self.msg(
            RPL.YOURHOST, f"Your host is {self.server.servername}, running version {__version__}",
        )
        self.msg(RPL.CREATED, f"This server was created {self.server.boot_time:%c}")
        self.msg(
            RPL.MYINFO, f"{self.server.servername} {__version__} i {''.join(cmodes)}",
        )
        self.msg(
            RPL.ISUPPORT,
            [
                f"NETWORK={NETWORK}",
                "CASEMAPPING=rfc1459",
                "CHANLIMIT=#:2000",
                f"CHANMODES={','.join(cmodes)}",
                "CHANNELLEN=50",
                "CHANTYPES=#",
                "PREFIX=",
                "SAFELIST",
                "are available on this server",
            ],
        )
        self.msg(RPL.UMODEIS, "+i")
        self.handle_motd([])
        self.server.add_client(self)
        self.log.info("Client identified as %s!%s", self.nick, self.user)

    def handle_motd(self, _: List[str]) -> None:
        """Handles the MOTD command."""
        self.msg(RPL.MOTDSTART, "- Message of the day -")
        for line in SRV_WELCOME.strip().split("\n"):
            self.msg(RPL.MOTD, "- " + line)
        self.msg(RPL.ENDOFMOTD, "End of /MOTD command.")

    def handle_ping(self, params: List[str]) -> None:
        """Handles client PING requests to keep the connection alive."""
        try:
            origin = params[0]
        except IndexError:
            raise IRCError(ERR.NOORIGIN, "No origin specified")

        try:
            destination = params[1]
        except IndexError:
            destination = self.server.servername

        self.msg("PONG", [destination, origin])

    def handle_pong(self, _: List[str]) -> None:
        """Handles client PONG responses to keep the connection alive."""
        self.keepalive = (datetime.datetime.utcnow(), False)

    def handle_join(self, params: List[str]) -> None:
        """Handles the JOIN command.

        Valid channel names start with a # and consist of a-z, A-Z, 0-9 and/or
        '_' and '.'.
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
            channelobj.add_member(self)

            # add channel to user's channel list
            self.channels[channelobj.name] = channelobj

            # send join message
            self.msg("JOIN", channel)
            self.handle_topic([channel])
            self.handle_names([channel])

    def handle_topic(self, params: List[str]) -> None:
        """Handles the TOPIC command.

        Shows a hardcoded topic message when asked for one, and always deny
        setting the topic, as this is not supported.
        """
        try:
            channel = params[0]
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["TOPIC", "Not enough parameters"])

        if channel not in self.channels:
            raise IRCError(ERR.NOTONCHANNEL, [channel, "You're not on that channel"])

        # if a new topic was given...
        if len(params) > 1:
            raise IRCError(ERR.CHANOPRIVSNEEDED, [channel, "You're not a channel operator"])

        self.msg(RPL.TOPIC, [channel, TOPIC_TMPL.format(channel)])
        botid = BOTNAME + "!" + BOTNAME + "@" + self.server.servername
        self.msg(
            RPL.TOPICWHOTIME, [channel, botid, str(int(self.server.boot_time.timestamp()))],
        )

    def handle_names(self, params: List[str]) -> None:
        """Handles the NAMES command.

        Every channel has the "bot" connected, plus, optionally, the connecting
        client.
        """
        try:
            channels = params[0]
        except IndexError:
            self.msg(RPL.ENDOFNAMES, ["*", "End of /NAMES list"])
            return

        # ignore queries for multiple channels (as some networks do)
        channel = channels.split(",")[0].strip()

        nicklist: Iterable[str]
        if channel in self.channels:
            nicklist = (self.nick, "@" + BOTNAME)
        else:
            nicklist = ("@" + BOTNAME,)

        self.msg(RPL.NAMREPLY, ["=", channel, " ".join(nicklist)])
        self.msg(RPL.ENDOFNAMES, [channel, "End of /NAMES list"])

    def handle_privmsg(self, params: List[str]) -> None:
        """Handles the PRIVMSG command, sending a message to a user or channel.

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

    def handle_part(self, params: List[str]) -> None:
        """Handles the PART command."""
        try:
            channels = params[0]
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["PART", "Not enough parameters"])

        for channel in channels.split(","):
            channel = channel.strip()

            if channel in self.channels:
                channelobj = self.channels.pop(channel)
                channelobj.remove_member(self)
                self.msg("PART", channel)
            else:
                # don't raise IRCError because this can be one of many channels
                self.msg(ERR.NOTONCHANNEL, [channel, "You're not on that channel"])

    def handle_list(self, params: List[str]) -> None:
        """Handles the LIST command."""
        channels: Iterable[str]
        try:
            given_channels = params[0]
            channels = set(self.channels) & set(given_channels.split(","))
        except IndexError:
            channels = self.channels

        for channel in sorted(channels):
            self.msg(RPL.LIST, [channel, "2", TOPIC_TMPL.format(channel)])
        self.msg(RPL.LISTEND, "End of /LIST")

    def handle_quit(self, params: List[str]) -> None:
        """Handles the client breaking off the connection with a QUIT command."""
        for channel in self.channels.values():
            channel.remove_member(self)

        try:
            reason = params[0]
        except IndexError:
            reason = "No reason"

        self.msg("ERROR", f"Closing Link: (Quit: {reason})", sync=True)
        raise self.Disconnect()

    @property
    def client_ident(self) -> str:
        """Returns the client identifier as included in many command replies."""
        if not (self.nick and self.user):
            raise IRCError(ERR.NOTREGISTERED, "You have not registered")
        return f"{self.nick}!{self.user}@{self.server.servername}"

    @property
    def internal_ident(self) -> str:
        """Returns the internal (non-wire-protocol) client identifier."""
        host_port = f"[{self.host}]:{self.port}"
        if not (self.nick and self.user):
            return f"unidentified/{host_port}"
        return f"{self.nick}!{self.user}/{host_port}"

    def finish(self) -> None:
        """Finishes the client connection.

        Do some cleanup to ensure that the client doesn't linger around in any
        channel or the client list, in case the client didn't properly close
        the connection with PART and QUIT.
        """
        self.log.info("Client disconnected")
        for channel in self.channels.values():
            channel.remove_member(self)

        try:
            self.server.remove_client(self)
        except KeyError:
            # was never added, e.g. if was never identified
            pass
        self.log.info("Connection finished")

    def __repr__(self) -> str:
        """Returns a user-readable description of the client."""
        return f"<{self.__class__.__name__} {self.internal_ident} {self.realname}>"


class IRCServer(socketserver.ThreadingTCPServer):
    """A socketserver TCPServer instance representing an IRC server."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: Tuple[str, int], RequestHandlerClass: type) -> None:
        if ":" in server_address[0]:
            self.address_family = socket.AF_INET6
        self.servername = SERVERNAME
        self.boot_time = datetime.datetime.utcnow()
        self._channels: Dict[str, IRCChannel] = {}
        self._clients: Set[IRCClient] = set()
        self._clients_lock = threading.Lock()

        # set up a few Prometheus metrics
        self.metrics = {
            "clients": prometheus_client.Gauge("ircstream_clients", "Number of IRC clients"),
            "channels": prometheus_client.Gauge("ircstream_channels", "Number of IRC channels"),
            "messages": prometheus_client.Counter("ircstream_messages", "Count of RC messages broadcasted"),
            "errors": prometheus_client.Counter("ircstream_errors", "Count of errors and exceptions", ["type"]),
        }
        self.metrics["clients"].set_function(lambda: len(self._clients))
        self.metrics["channels"].set_function(lambda: len(self._channels))

        super().__init__(server_address, RequestHandlerClass)

    def server_bind(self) -> None:
        """Binds to an IP address.

        Override to set an opt to listen to both IPv4/IPv6 on the same socket.
        """
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        super().server_bind()

    def get_channel(self, name: str) -> IRCChannel:
        """Returns an IRCChannel instance for the given channel name.

        Creates one if necessary, in a race-free way.
        """
        # setdefault() is thread-safe, cf. issue 13521
        return self._channels.setdefault(name, IRCChannel(name))

    def add_client(self, client: IRCClient) -> None:
        """Adds a client to the client list (race-free)."""
        with self._clients_lock:
            self._clients.add(client)

    def remove_client(self, client: IRCClient) -> None:
        """Removes a client from the client list (race-free)."""
        with self._clients_lock:
            self._clients.remove(client)

    def broadcast(self, target: str, msg: str) -> None:
        """Broadcasts a message to all clients that have joined a channel.

        The source of the message is the BOTNAME.
        """
        botid = BOTNAME + "!" + BOTNAME + "@" + self.servername
        message = IRCMessage("PRIVMSG", [target, msg], source=botid)

        channel = self.get_channel(target)
        for client in channel.members():
            try:
                client.send_queue.append(str(message))
            except Exception:  # pylint: disable=broad-except
                self.metrics["errors"].labels("broadcast").inc()
                # ignore exceptions, to catch races and other corner cases
                continue
        self.metrics["messages"].inc()


class EchoServer(socketserver.UDPServer):
    """A socketserver implementing the Echo protocol, as used by MediaWiki"""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: Tuple[str, int], RequestHandlerClass: type, ircserver: IRCServer) -> None:
        self.irc = ircserver
        super().__init__(server_address, RequestHandlerClass)


class EchoHandler(socketserver.BaseRequestHandler):
    """A socketserver handler implementing the Echo protocol, as used by MediaWiki"""

    server: EchoServer

    def handle(self) -> None:
        data = self.request[0]
        try:
            data = data.decode("utf-8")
            channel, text = data.split("\t", maxsplit=1)
            channel = channel.strip()
            text = text.lstrip().replace("\r", "").replace("\n", "")
        except Exception:  # pylint: disable=broad-except
            return

        log.debug("Broadcasting to %s: %s", channel, text)
        self.server.irc.broadcast(channel, text)


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    """Parses and returns the parsed command line arguments."""
    parser = argparse.ArgumentParser(
        prog="ircstream",
        description="Wikimedia RC->IRC gateway",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("-la", "--address", dest="listen_address", default="::", help="IP on which to listen")
    parser.add_argument("-lp", "--port", dest="listen_port", default=6667, type=int, help="Port on which to listen")
    parser.add_argument("-pp", "--prom-port", dest="prom_port", default=9200, type=int, help="Port on which to listen")
    parser.add_argument("-ea", "--echo-address", dest="echo_address", default="0.0.0.0", help="IP on which to listen")
    parser.add_argument("-ep", "--echo-port", dest="echo_port", default=9390, type=int, help="Port on which to listen")
    log_levels = ("DEBUG", "INFO", "WARNING", "ERROR")  # no public method to get a list from logging :(
    parser.add_argument("--log-level", dest="log_level", default="INFO", choices=log_levels, help="Set log level")

    return parser.parse_args(argv)


def setup_logging(log_level: str) -> None:
    """Sets up logging parameters."""
    logger.setLevel(log_level)
    stream_handler = logging.StreamHandler()
    fmt = logging.Formatter("%(levelname)s %(client_id)s %(message)s")
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Main entry point."""
    options = parse_args(argv)
    setup_logging(options.log_level)
    log.warning("Starting IRCStream")

    try:
        irc_bind_address = options.listen_address, options.listen_port
        ircserver = IRCServer(irc_bind_address, IRCClient)
        log.warning("Listening for IRC clients on [%s]:%s", options.listen_address, options.listen_port)
        irc_thread = threading.Thread(target=ircserver.serve_forever)
        irc_thread.daemon = True
        irc_thread.start()

        echo_bind_address = options.echo_address, options.echo_port
        echoserver = EchoServer(echo_bind_address, EchoHandler, ircserver)
        log.warning("Listening for Echo on port [%s]:%s", options.echo_address, options.echo_port)
        echo_thread = threading.Thread(target=echoserver.serve_forever)
        echo_thread.daemon = True
        echo_thread.start()

        prometheus_client.start_http_server(options.prom_port)
        log.warning("Exposing Prometheus metrics on port %s", options.prom_port)

        input()
    except KeyboardInterrupt:
        return
    except socket.error as exc:
        log.error(repr(exc))
        raise SystemExit(-2)


if __name__ == "__main__":
    main()
