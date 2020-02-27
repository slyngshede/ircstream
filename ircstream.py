#!/usr/bin/env python3
"""IRCStream — Wikimedia RecentChanges → IRC gateway.

This is a simple gateway to the Wikimedia recent changes feed, using the IRC
protocol. It was written mainly for compatibility reasons, as there are a
number of legacy clients in the wild relying on this interface.

This software presents itself as an IRC server, but only supports a restricted
command set. Sending messages to channels or other clients is not allowed. Each
client is within a private namespace, unable to view messages and interact with
other connected clients, create channels, or speak on them.

Other clients are not even viewable on channel lists, /who etc. The sole
exception is a (fake) bot user, that emits the recent changes feed, and which
is also embedded in the server (i.e. it's not a real client).
"""

from __future__ import annotations

__version__ = "0.9.0"
__author__ = "Faidon Liambotis"
__copyright__ = """
Copyright © Faidon Liambotis
Copyright © Wikimedia Foundation, Inc.
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

import argparse
import configparser
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

import prometheus_client  # type: ignore  # prometheus/client_python #491

import structlog  # type: ignore  # hynek/structlog #165


class IRCNumeric(enum.Enum):
    """Base class for IRC numeric enums."""

    def __str__(self) -> str:
        """Return the numeric in the wire protocol format, e.g. 001."""
        return str(self.value).zfill(3)

    def __repr__(self) -> str:
        """Return the representation of the numeric, e.g. RPL_WELCOME."""
        return f"{self.__class__.__name__}_{self.name}"


@enum.unique
class RPL(IRCNumeric):
    """Standard IRC RPL_* replies, as defined in RFCs."""

    WELCOME = 1
    YOURHOST = 2
    CREATED = 3
    MYINFO = 4
    ISUPPORT = 5
    UMODEIS = 221
    WHOISUSER = 311
    WHOISSERVER = 312
    ENDOFWHO = 315
    WHOISIDLE = 317
    ENDOFWHOIS = 318
    LIST = 322
    LISTEND = 323
    CHANNELMODEIS = 324
    TOPIC = 332
    TOPICWHOTIME = 333
    NAMREPLY = 353
    ENDOFNAMES = 366
    ENDOFBANLIST = 368
    MOTD = 372
    MOTDSTART = 375
    ENDOFMOTD = 376


@enum.unique
class ERR(IRCNumeric):
    """Erroneous IRC ERR_* replies, as defined in RFCs."""

    NOSUCHNICK = 401
    NOSUCHCHANNEL = 403
    CANNOTSENDTOCHAN = 404
    NOORIGIN = 409
    UNKNOWNCOMMAND = 421
    NONICKNAMEGIVEN = 431
    ERRONEUSNICKNAME = 432
    NOTONCHANNEL = 442
    NOTREGISTERED = 451
    NEEDMOREPARAMS = 461
    ALREADYREGISTERED = 462
    CHANOPRIVSNEEDED = 482
    UMODEUNKNOWNFLAG = 501
    USERSDONTMATCH = 502


class IRCMessage:
    """Represents an RFC 1459/2681 message.

    Can be either initialized:
    * with its constructor using a command, params and (optionally) a source
    * given a preformatted string, using the from_message() class method

    Does not currently support IRCv3 features like message tags.
    """

    # Based on the RFC1459Message class from the mammon-ircd and goshuirc projects
    __copyright__ = "Copyright © 2014 William Pitcock <nenolod@dereferenced.org>"
    __license__ = """
    SPDX-License-Identifier: ISC

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
    """

    def __init__(self, command: str, params: Iterable[str], source: Optional[str] = None) -> None:
        self.command = command
        self.params = params
        self.source = source

    @classmethod
    def from_message(cls, message: str) -> IRCMessage:
        """Parse a previously formatted IRC message.

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
            # pylint: disable=no-else-continue,no-else-break
            # skip multiple spaces in middle of message, as per RFC 1459
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
        """Generate an RFC-compliant formatted string for the instance."""
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
        """Represent an IRCMessage; mainly used for debugging."""
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

    def add_member(self, client: IRCClient) -> None:
        """Add a client to the channel (race-free)."""
        with self._lock:
            self._clients.add(client)

    def remove_member(self, client: IRCClient) -> None:
        """Remove a client from a channel (race-free).

        No-op if they weren't there already.
        """
        with self._lock:
            try:
                self._clients.remove(client)
            except KeyError:
                pass

    def members(self) -> Iterable[IRCClient]:
        """List the clients in the channel."""
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

    log = structlog.get_logger("ircstream.client")
    server: IRCServer

    class Disconnect(BaseException):
        """Raised when we are about to be disconnected from the client."""

    def __init__(self, request: Any, client_address: Any, server: IRCServer) -> None:
        self.host, self.port = client_address[:2]
        # trim IPv4 mapped prefix
        if self.host.startswith("::ffff:"):
            self.host = self.host[len("::ffff:") :]

        self.log.new(ip=self.host, port=self.port)

        self.signon = datetime.datetime.utcnow()
        self.keepalive = (self.signon, False)  # (last_heard, ping_sent)
        self.buffer = b""
        self.user, self.realname, self.nick = "", "", ""
        self.send_queue: List[str] = []
        self.channels: Dict[str, IRCChannel] = {}

        super().__init__(request, client_address, server)  # type: ignore  # python/typeshed #3523

    def msg(self, command: Union[str, IRCNumeric], params: Union[List[str], str], sync: bool = False) -> None:
        """Prepare and queues a response to the client.

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
        """Handle one read/write cycle."""
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
        """Receive data from a client.

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
        """Handle a single line of input (i.e. a command and arguments)."""
        try:
            line = bline.decode("utf-8").strip()
            # ignore empty lines
            if not line:
                return
            self.log.debug("<-", message=line)
            msg = IRCMessage.from_message(line)

            whitelisted = ("CAP", "PASS", "USER", "NICK", "QUIT", "PING", "PONG")
            if not (self.nick and self.user) and msg.command not in whitelisted:
                raise IRCError(ERR.NOTREGISTERED, "You have not registered")

            handler = getattr(self, f"handle_{msg.command.lower()}", None)
            if not handler:
                self.log.info("No handler for command", command=msg.command, params=msg.params)
                raise IRCError(ERR.UNKNOWNCOMMAND, [msg.command, "Unknown command"])
            handler(msg.params)
        except IRCError as exc:
            self.msg(exc.command, exc.params)
        except UnicodeDecodeError:
            return
        except Exception as exc:  # pylint: disable=broad-except
            self.server.metrics["errors"].labels("ise").inc()
            self.msg("ERROR", f"Internal server error ({exc})")
            self.log.exception("Internal server error")

    def _send(self, msg: str) -> None:
        """Send a message to a connected client."""
        self.log.debug("->", message=msg)
        try:
            self.request.send(msg.encode("utf-8") + b"\r\n")
        except UnicodeEncodeError as exc:
            self.log.debug("Internal encoding error", error=exc)
        except socket.error as exc:
            if exc.errno == errno.EPIPE:
                raise self.Disconnect()
            raise

    def handle_cap(self, params: List[str]) -> None:  # pylint: disable=no-self-use
        """Stub for the CAP (capability) command.

        Ignore and do not send unknown command, per IRC v3.1/v3.2.
        """

    def handle_who(self, params: List[str]) -> None:
        """Stub for the WHO command."""
        try:
            mask = params[0]
        except IndexError:
            mask = "*"
        self.msg(RPL.ENDOFWHO, [mask, "End of /WHO list."])

    def handle_mode(self, params: List[str]) -> None:
        """Handle the MODE command, for both channel and user modes."""
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
            elif target == self.server.botname:
                raise IRCError(ERR.USERSDONTMATCH, "Can't change mode for other users")
            else:
                raise IRCError(ERR.NOSUCHNICK, [target, "No such nick/channel"])

    def handle_whois(self, params: List[str]) -> None:
        """Handle the WHOIS command."""
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
            self.msg(RPL.WHOISSERVER, [nick, self.server.servername, "IRCStream"])
            self.msg(RPL.WHOISIDLE, [nick, "0", str(int(signon.timestamp())), "seconds idle, signon time"])

        if nickmask == self.nick:
            whois_reply(self.nick, self.user, self.host, self.realname, self.signon)
        elif nickmask == self.server.botname:
            nick = user = realname = self.server.botname
            whois_reply(nick, user, self.server.servername, realname, self.server.boot_time)
        else:
            raise IRCError(ERR.NOSUCHNICK, [nickmask, "No such nick/channel"])

        # nicklist and not nickmask, on purpose
        self.msg(RPL.ENDOFWHOIS, [nicklist, "End of /WHOIS list"])

    def handle_nick(self, params: List[str]) -> None:
        """Handle the initial setting of the user's nickname and nick changes."""
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
        """Handle the USER command which identifies the user to the server."""
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
        """End the registration process.

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
                f"NETWORK={self.server.network}",
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
        self.log = self.log.bind(client_id=self.internal_ident)
        self.log.info("Client identified")

    def handle_motd(self, _: List[str]) -> None:
        """Handle the MOTD command."""
        self.msg(RPL.MOTDSTART, "- Message of the day -")
        for line in self.server.welcome_msg.strip().split("\n"):
            self.msg(RPL.MOTD, "- " + line)
        self.msg(RPL.ENDOFMOTD, "End of /MOTD command.")

    def handle_ping(self, params: List[str]) -> None:
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

    def handle_pong(self, _: List[str]) -> None:
        """Handle client PONG responses to keep the connection alive."""
        self.keepalive = (datetime.datetime.utcnow(), False)

    def handle_join(self, params: List[str]) -> None:
        """Handle the JOIN command."""
        try:
            channels = params[0]  # ignore param 1, i.e. channel keys
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["JOIN", "Not enough parameters"])

        for channel in channels.split(","):
            channel = channel.strip()
            # is this a valid channel name?
            if not re.match("^#([a-zA-Z0-9_.])+$", channel):
                raise IRCError(ERR.NOSUCHCHANNEL, [channel, "No such channel"])

            # add user to the channel (if the channel exists)
            try:
                channelobj = self.server.get_channel(channel)
            except KeyError:
                raise IRCError(ERR.NOSUCHCHANNEL, [channel, "No such channel"])
            channelobj.add_member(self)
            self.channels[channelobj.name] = channelobj  # add channel to user's channel list
            self.msg("JOIN", channel)  # send join message
            self.handle_topic([channel])
            self.handle_names([channel])
            self.log.info("User subscribed to feed", channel=channel)

    def handle_topic(self, params: List[str]) -> None:
        """Handle the TOPIC command.

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

        self.msg(RPL.TOPIC, [channel, self.server.topic_tmpl.format(channel=channel)])
        botid = self.server.botname + "!" + self.server.botname + "@" + self.server.servername
        self.msg(RPL.TOPICWHOTIME, [channel, botid, str(int(self.server.boot_time.timestamp()))])

    def handle_names(self, params: List[str]) -> None:
        """Handle the NAMES command.

        Every channel has the "bot" connected, plus, optionally, the connecting
        client.
        """
        try:
            channels = params[0]
        except IndexError:
            self.msg(RPL.ENDOFNAMES, ["*", "End of /NAMES list"])
            return

        # ignore queries for multiple channels (as many networks do)
        channel = channels.split(",")[0].strip()

        nicklist: Iterable[str]
        if channel in self.channels:
            nicklist = (self.nick, "@" + self.server.botname)
        else:
            nicklist = ("@" + self.server.botname,)

        self.msg(RPL.NAMREPLY, ["=", channel, " ".join(nicklist)])
        self.msg(RPL.ENDOFNAMES, [channel, "End of /NAMES list"])

    def handle_privmsg(self, params: List[str]) -> None:
        """Handle the PRIVMSG command, sending a message to a user or channel.

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
            elif target == self.server.botname:
                # bot ignores all messages
                pass
            elif target == self.nick:
                # echo back
                self.msg("PRIVMSG", [target, msg])
            else:
                self.msg(ERR.NOSUCHNICK, [target, "No such nick/channel"])

    def handle_part(self, params: List[str]) -> None:
        """Handle the PART command."""
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
                self.log.info("User unsubscribed from feed", channel=channel)
            else:
                # don't raise IRCError because this can be one of many channels
                self.msg(ERR.NOTONCHANNEL, [channel, "You're not on that channel"])

    def handle_list(self, params: List[str]) -> None:
        """Handle the LIST command."""
        channels: Iterable[str]
        try:
            given_channels = params[0]
            channels = set(self.server.channels) & set(given_channels.split(","))
        except IndexError:
            channels = self.server.channels

        for channel in sorted(channels):
            usercount = "2" if channel in self.channels else "1"  # bot, or us and the bot
            self.msg(RPL.LIST, [channel, usercount, self.server.topic_tmpl.format(channel=channel)])
        self.msg(RPL.LISTEND, "End of /LIST")

    def handle_quit(self, params: List[str]) -> None:
        """Handle the client breaking off the connection with a QUIT command."""
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
        """Return the client identifier as included in many command replies."""
        if not (self.nick and self.user):
            raise IRCError(ERR.NOTREGISTERED, "You have not registered")
        return f"{self.nick}!{self.user}@{self.server.servername}"

    @property
    def internal_ident(self) -> str:
        """Return the internal (non-wire-protocol) client identifier."""
        host_port = f"[{self.host}]:{self.port}"
        if not (self.nick and self.user):
            return f"unidentified/{host_port}"
        return f"{self.nick}!{self.user}/{host_port}"

    def finish(self) -> None:
        """Finish the client connection.

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
            pass  # was never added, e.g. if was never identified
        self.log.info("Connection finished")

    def __repr__(self) -> str:
        """Return a user-readable description of the client."""
        return f"<{self.__class__.__name__} {self.internal_ident}>"


class DualstackServerMixIn(socketserver.BaseServer):
    """BaseServer mix-in to support dual-stack servers.

    This forces AF_INET6 allowing addresses from both families to be given.  It
    also setsockopts(IPV6_V6ONLY, 0), essentially allowing an address of :: to
    capture both IPv4/IPv6 traffic with just one socket.
    """

    def __init__(self, server_address: Tuple[str, int], RequestHandlerClass: type) -> None:
        if ":" in server_address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(server_address, RequestHandlerClass)

    def server_bind(self) -> None:
        """Bind to an IP address.

        Override to set an opt to listen to both IPv4/IPv6 on the same socket.
        """
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class IRCServer(DualstackServerMixIn, socketserver.ThreadingTCPServer):
    # pylint: disable=too-many-instance-attributes
    """A socketserver TCPServer instance representing an IRC server."""

    daemon_threads = True
    allow_reuse_address = True
    log = structlog.get_logger("ircstream.irc")

    def __init__(self, config: configparser.SectionProxy, RequestHandlerClass: type) -> None:
        self.servername = config.get("servername", "irc.example.org")
        self.botname = config.get("botname", "example-bot")
        self.network = config.get("network", "Example")
        self.topic_tmpl = config.get("topic_tmpl", "Stream for topic {channel}")
        self.welcome_msg = config.get("welcome_msg", "Welcome!")

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

        listen_address = config.get("listen_address", fallback="::")
        listen_port = config.getint("listen_port", fallback=6667)
        self.log.info("Listening for IRC clients", listen_address=listen_address, listen_port=listen_port)
        super().__init__((listen_address, listen_port), RequestHandlerClass)

    def get_channel(self, name: str, create: bool = False) -> IRCChannel:
        """Return an IRCChannel instance for the given channel name.

        Creates one if asked and if necessary, in a race-free way.
        """
        # pylint: disable=no-else-return
        if create:
            # setdefault() is thread-safe, cf. issue 13521
            return self._channels.setdefault(name, IRCChannel(name))
        else:
            # can raise KeyError
            return self._channels[name]

    @property
    def channels(self) -> Iterable[str]:
        """Return a list of all the server channel names."""
        return self._channels.keys()

    def add_client(self, client: IRCClient) -> None:
        """Add a client to the client list (race-free)."""
        with self._clients_lock:
            self._clients.add(client)

    def remove_client(self, client: IRCClient) -> None:
        """Remove a client from the client list (race-free)."""
        with self._clients_lock:
            self._clients.remove(client)

    def broadcast(self, target: str, msg: str) -> None:
        """Broadcast a message to all clients that have joined a channel.

        The source of the message is the bot's name.
        """
        botid = self.botname + "!" + self.botname + "@" + self.servername
        message = IRCMessage("PRIVMSG", [target, msg], source=botid)

        channel = self.get_channel(target, create=True)
        for client in channel.members():
            try:
                client.send_queue.append(str(message))
            except Exception:  # pylint: disable=broad-except
                self.metrics["errors"].labels("broadcast").inc()
                # ignore exceptions, to catch races and other corner cases
                continue
        self.metrics["messages"].inc()


class EchoServer(DualstackServerMixIn, socketserver.UDPServer):
    """A socketserver implementing the Echo protocol, as used by MediaWiki."""

    log = structlog.get_logger("ircstream.echo")
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, config: configparser.SectionProxy, RequestHandlerClass: type, ircserver: IRCServer) -> None:
        self.ircserver = ircserver
        listen_address = config.get("listen_address", fallback="::")
        listen_port = config.getint("listen_port", fallback=9390)
        self.log.info("Listening for Echo", echo_address=listen_address, echo_port=listen_port)
        super().__init__((listen_address, listen_port), RequestHandlerClass)


class EchoHandler(socketserver.BaseRequestHandler):
    """A socketserver handler implementing the Echo protocol, as used by MediaWiki."""

    log = structlog.get_logger("ircstream.echo")
    server: EchoServer

    def handle(self) -> None:
        """Receive a new Echo message and broadcast to all clients."""
        data = self.request[0]
        try:
            data = data.decode("utf-8")
            channel, text = data.split("\t", maxsplit=1)
            channel = channel.strip()
            text = text.lstrip().replace("\r", "").replace("\n", "")
        except Exception:  # pylint: disable=broad-except
            self.server.ircserver.metrics["errors"].labels("echo-parsing").inc()
            return
        self.log.debug("Broadcasting message", channel=channel, message=text)
        self.server.ircserver.broadcast(channel, text)


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    """Parse and return the parsed command line arguments."""
    parser = argparse.ArgumentParser(
        prog="ircstream",
        description="Wikimedia RecentChanges → IRC gateway",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="configfile",
        default="/etc/ircstream.conf",
        type=argparse.FileType("r"),
        help="Path to configuration file",
    )
    log_levels = ("DEBUG", "INFO", "WARNING", "ERROR")  # no public method to get a list from logging :(
    parser.add_argument("--log-level", dest="log_level", default="INFO", choices=log_levels, help="Set log level")
    log_formats = ("plain", "json")
    parser.add_argument("--log-format", dest="log_format", default="plain", choices=log_formats, help="Set log format")

    return parser.parse_args(argv)


def configure_logging(log_level: str, log_format: str = "plain") -> None:
    """Configure logging parameters."""
    logging.basicConfig(format="%(message)s", level=log_level)
    default_processors = structlog.get_config()["processors"]
    structlog.configure(
        processors=[structlog.stdlib.add_log_level] + default_processors,
        context_class=structlog.threadlocal.wrap_dict(dict),
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
    )

    if log_format == "json":
        structlog.configure(
            processors=[
                structlog.stdlib.add_logger_name,  # adds a "logger" key
                structlog.stdlib.add_log_level,  # adds a "level" key (string, not int)
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer(sort_keys=True),
            ],
        )


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Entry point."""
    options = parse_args(argv)
    config = configparser.ConfigParser()
    config.read_file(options.configfile)

    configure_logging(options.log_level, options.log_format)
    log = structlog.get_logger("ircstream")
    log.info("Starting IRCStream")

    try:
        if "irc" in config:
            ircserver = IRCServer(config["irc"], IRCClient)
            irc_thread = threading.Thread(target=ircserver.serve_forever, daemon=True)
            irc_thread.start()
        else:
            log.error("Invalid configuration, missing section", section="irc")
            raise SystemExit(-1)

        if "echo" in config:
            echoserver = EchoServer(config["echo"], EchoHandler, ircserver)
            echo_thread = threading.Thread(target=echoserver.serve_forever, daemon=True)
            echo_thread.start()
        else:
            log.warning("Echo is not enabled in the config; server usefuless may be limited")

        if "prometheus" in config:
            prom_port = config["prometheus"].getint("listen_port", fallback=9200)
            prometheus_client.start_http_server(prom_port)
            log.info("Listening to HTTP (Prometheus)", prometheus_port=prom_port)

        input()
    except KeyboardInterrupt:
        return
    except socket.error as exc:
        log.error(repr(exc))
        raise SystemExit(-2)


if __name__ == "__main__":
    main()
