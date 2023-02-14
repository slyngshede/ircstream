#!/usr/bin/env python3
"""IRCStream — MediaWiki RecentChanges → IRC gateway.

IRCStream is a simple gateway to the MediaWiki recent changes feed, from the
IRC protocol. It was written mainly for compatibility reasons, as there are a
number of legacy clients in the wild relying on this interface.
"""

from __future__ import annotations

__version__ = "0.11.0-dev0"
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
import asyncio
import configparser
import dataclasses
import datetime
import enum
import errno
import http.server
import logging
import re
import socket
import sys
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
from prometheus_client import Counter, Gauge

import structlog


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
    ENDOFWHOWAS = 369
    MOTD = 372
    MOTDSTART = 375
    ENDOFMOTD = 376


@enum.unique
class ERR(IRCNumeric):
    """Erroneous IRC ERR_* replies, as defined in RFCs."""

    WASNOSUCHNICK = 406
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


@dataclasses.dataclass
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

    command: str
    params: Sequence[str]
    source: Optional[str] = None

    @classmethod
    def from_message(cls, message: str) -> IRCMessage:
        """Parse a previously formatted IRC message. Returns an instance of IRCMessage."""
        parts = message.split(" ")

        source = None
        if parts[0].startswith(":"):
            source = parts[0][1:]
            parts = parts[1:]

        try:
            command = parts[0].upper()
        except IndexError:
            raise ValueError("Invalid IRC message (no command specified)") from None

        original_params = parts[1:]
        params = []

        while original_params:
            # skip multiple spaces in middle of message, as per RFC 1459
            if original_params[0] == "" and len(original_params) > 1:
                original_params.pop(0)
                continue
            elif original_params[0].startswith(":"):
                arg = " ".join(original_params)[1:]
                params.append(arg)
                break
            elif original_params[0]:
                params.append(original_params.pop(0))
            else:
                original_params.pop(0)

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


class IRCError(Exception):
    """Exception thrown by IRC command handlers to notify client of a server/client error."""

    def __init__(self, command: Union[str, IRCNumeric], params: Union[List[str], str]) -> None:
        super().__init__()
        self.command = command
        self.params = params


class IRCClient:
    """IRC client connect and command handling.

    Client connection is handled by the ``handle`` method which sets up a
    two-way communication with the client.  It then handles commands sent by
    the client by dispatching them to the ``handle_`` methods.
    """

    log = structlog.get_logger("ircstream.client")

    def __init__(self, server: IRCServer, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.server = server
        self.reader = reader
        self.writer = writer

        self.signon = datetime.datetime.utcnow()
        self.last_heard = self.signon
        self.ping_sent = False
        self.buffer = b""
        self.user, self.realname, self.nick = "", "", ""
        self.channels: Set[str] = set()
        self.host: str = ""
        self.port: int = 0
        self._periodic_ping_task: Optional[asyncio.Task[Any]] = None

    async def connect(self) -> None:
        """Handle a new connection from a client."""
        client_address = self.writer.get_extra_info("peername")
        self.host, self.port = client_address[:2]
        # trim IPv4 mapped prefix
        if self.host.startswith("::ffff:"):
            self.host = self.host[len("::ffff:") :]

        self.log.new(ip=self.host, port=self.port)
        self.log.info("Client connected")
        self.server.metrics["clients"].inc()
        self._periodic_ping_task = asyncio.create_task(self._periodic_ping())

        await self._handle_forever()

    async def terminate(self) -> None:
        """Terminates the connection."""
        try:
            self.writer.write_eof()
            await self.writer.drain()
        except OSError as exc:
            if exc.errno != errno.ENOTCONN:
                self.log.debug("Unknown error in terminate", errno=exc.errno)
        self.writer.close()
        await self.writer.wait_closed()

    async def _periodic_ping(self) -> None:
        while True:
            await asyncio.sleep(self.server.client_timeout / 2)
            timeout = self.server.client_timeout
            # if we haven't heard from the client in N seconds, disconnect
            delta = datetime.datetime.utcnow() - self.last_heard
            if delta > datetime.timedelta(seconds=timeout):
                await self.msg("ERROR", "Closing Link: (Ping timeout)")
                await self.terminate()

            # if it's N/2 seconds since the last PONG, send a PING
            if delta > datetime.timedelta(seconds=timeout / 2) and not self.ping_sent and self.registered:
                await self.msg("PING", self.server.servername)
                self.ping_sent = True

    async def msg(self, command: Union[str, IRCNumeric], params: Union[List[str], str]) -> None:
        """Prepare and sends a response to the client.

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
        await self.send(str(msg))

    async def _handle_forever(self) -> None:
        """Receive data from a client.

        Do some basic checking, then call _handle_line()
        """
        while True:
            try:
                line = await self.reader.readline()
            except ValueError:
                self.log.debug("Line exceeded max length, ignoring")
                continue
            except OSError:
                break

            if self.reader.at_eof():
                break

            line = line.rstrip(b"\n").rstrip(b"\r")
            line = line[:510]  # 512 including CRLF; RFC 2813, section 3.3
            await self._handle_line(line)
        await self.finish()

    async def _handle_line(self, bline: bytes) -> None:
        """Handle a single line of input (i.e. a command and arguments)."""
        try:
            line = bline.decode("utf8").strip()
            # ignore empty lines
            if not line:
                return
            self.log.debug("Data received", message=line)

            try:
                msg = IRCMessage.from_message(line)
            except ValueError:
                # ignore unparseable commands
                return

            whitelisted = ("CAP", "PASS", "USER", "NICK", "QUIT", "PING", "PONG")
            if not self.registered and msg.command not in whitelisted:
                raise IRCError(ERR.NOTREGISTERED, "You have not registered")

            handler = getattr(self, f"handle_{msg.command.lower()}", None)
            if not handler:
                self.log.info("No handler for command", command=msg.command, params=msg.params)
                raise IRCError(ERR.UNKNOWNCOMMAND, [msg.command, "Unknown command"])
            await handler(msg.params)
        except IRCError as exc:
            await self.msg(exc.command, exc.params)
        except UnicodeDecodeError:
            return
        except Exception as exc:  # pylint: disable=broad-except
            self.server.metrics["errors"].labels("ise").inc()
            await self.msg("ERROR", f"Internal server error ({exc})")
            self.log.exception("Internal server error")

    async def send(self, msg: str) -> None:
        """Send a message to a connected client."""
        msg = msg[:510]  # 512 including CRLF; RFC 2813, section 3.3
        if self.writer.is_closing():
            self.log.debug("Data not sent (conn closed)", message=msg)
            return
        self.log.debug("Data sent", message=msg)
        try:
            self.writer.write(msg.encode("utf8") + b"\r\n")
            await self.writer.drain()
        except UnicodeEncodeError as exc:
            self.log.debug("Internal encoding error", error=exc)
        except (ConnectionResetError, BrokenPipeError):
            pass

    async def handle_cap(self, params: List[str]) -> None:  # pylint: disable=no-self-use
        """Stub for the CAP (capability) command.

        Ignore and do not send unknown command, per IRC v3.1/v3.2.
        """

    async def handle_pass(self, _: List[str]) -> None:
        """Stub for the PASS command."""
        if self.registered:
            raise IRCError(ERR.ALREADYREGISTERED, "You may not reregister")

    async def handle_who(self, params: List[str]) -> None:
        """Stub for the WHO command."""
        try:
            mask = params[0]
        except IndexError:
            mask = "*"
        await self.msg(RPL.ENDOFWHO, [mask, "End of /WHO list."])

    async def handle_mode(self, params: List[str]) -> None:
        """Handle the MODE command, for both channel and user modes."""
        try:
            target = params[0]
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["MODE", "Not enough parameters"]) from None

        modestring: Optional[str]
        try:
            modestring = params[1]
        except IndexError:
            modestring = None

        if target.startswith("#"):
            # channel modes
            if modestring is None:
                await self.msg(RPL.CHANNELMODEIS, [target, "+mts"])
            elif modestring == "b":
                await self.msg(RPL.ENDOFBANLIST, [target, "End of channel ban list"])
            else:
                raise IRCError(ERR.CHANOPRIVSNEEDED, [target, "You're not a channel operator"])
        else:
            # user modes
            if modestring:
                # could raise ERR.UMODEUNKNOWNFLAG/"Unknown MODE flag" here
                # but common clients send a MODE at startup, making this noisy
                pass
            elif target == self.nick:
                await self.msg(RPL.UMODEIS, "+i")
            elif target == self.server.botname:
                raise IRCError(ERR.USERSDONTMATCH, "Can't change mode for other users")
            else:
                raise IRCError(ERR.NOSUCHNICK, [target, "No such nick/channel"])

    async def handle_whois(self, params: List[str]) -> None:
        """Handle the WHOIS command."""
        if len(params) == 2:
            nicklist = params[1]
        elif len(params) == 1:
            nicklist = params[0]
        else:
            raise IRCError(ERR.NONICKNAMEGIVEN, "No nickname given")

        # ignore queries for multiple users (as some networks do)
        nickmask = nicklist.split(",")[0]

        async def whois_reply(nick: str, user: str, host: str, realname: str, signon: datetime.datetime) -> None:
            # "<host> CANNOT start with a colon as this would get parsed as a
            # trailing parameter – IPv6 addresses such as "::1" are prefixed
            # with a zero to ensure this."
            if host.startswith(":"):
                host = "0" + host
            await self.msg(RPL.WHOISUSER, [nick, user, host, "*", realname])
            await self.msg(RPL.WHOISSERVER, [nick, self.server.servername, "IRCStream"])
            await self.msg(RPL.WHOISIDLE, [nick, "0", str(int(signon.timestamp())), "seconds idle, signon time"])

        if nickmask == self.nick:
            await whois_reply(self.nick, self.user, self.host, self.realname, self.signon)
        elif nickmask == self.server.botname:
            nick = user = realname = self.server.botname
            await whois_reply(nick, user, self.server.servername, realname, self.server.boot_time)
        else:
            raise IRCError(ERR.NOSUCHNICK, [nickmask, "No such nick/channel"])

        # nicklist and not nickmask, on purpose
        await self.msg(RPL.ENDOFWHOIS, [nicklist, "End of /WHOIS list"])

    async def handle_whowas(self, params: List[str]) -> None:
        """Handle the WHOWAS command."""
        try:
            nick = params[0]
        except IndexError:
            raise IRCError(ERR.NONICKNAMEGIVEN, "No nickname given") from None

        await self.msg(ERR.WASNOSUCHNICK, [nick, "There was no such nickname"])
        await self.msg(RPL.ENDOFWHOWAS, [nick, "End of WHOWAS"])

    async def handle_nick(self, params: List[str]) -> None:
        """Handle the initial setting of the user's nickname and nick changes."""
        try:
            nick = params[0]
        except IndexError:
            raise IRCError(ERR.NONICKNAMEGIVEN, "No nickname given") from None

        # is this a valid nickname?
        if not re.fullmatch(r"[\w\d\-\[\]'`\^{}_]+", nick) or len(nick) < 2 or len(nick) > 30:
            raise IRCError(ERR.ERRONEUSNICKNAME, [nick, "Erroneous nickname"])

        if not self.registered:
            self.nick = nick
            if self.user:
                await self.end_registration()
        else:
            # existing registration, but changing nicks
            await self.msg("NICK", [nick])
            self.nick = nick

    async def handle_user(self, params: List[str]) -> None:
        """Handle the USER command which identifies the user to the server."""
        try:
            user, _, _, realname = params[:4]
        except ValueError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["USER", "Not enough parameters"]) from None

        if self.user:
            raise IRCError(ERR.ALREADYREGISTERED, "You may not reregister")

        self.user = user
        self.realname = realname

        # we have both USER and NICK, end registration
        if self.nick:
            await self.end_registration()

    async def end_registration(self) -> None:
        """End the registration process.

        Called after both USER and NICK have been given. Responds with a whole
        chain of replies, as appropriate.
        """
        cmodes = ("b", "k", "l", "mtns")  # channel modes, types A-D

        await self.msg(RPL.WELCOME, "Welcome to IRCStream")
        await self.msg(RPL.YOURHOST, f"Your host is {self.server.servername}, running version {__version__}")
        await self.msg(RPL.CREATED, f"This server was created {self.server.boot_time:%c}")
        await self.msg(RPL.MYINFO, f"{self.server.servername} {__version__} i {''.join(cmodes)}")
        await self.msg(
            RPL.ISUPPORT,
            [
                f"NETWORK={self.server.network}",
                "CASEMAPPING=rfc1459",
                "CHANLIMIT=#:2000",
                f"CHANMODES={','.join(cmodes)}",
                "NICKLEN=30",
                "CHANNELLEN=50",
                "CHANTYPES=#",
                "PREFIX=",
                "SAFELIST",
                "are available on this server",
            ],
        )
        await self.msg(RPL.UMODEIS, "+i")
        await self.handle_motd([])

        self.log = self.log.bind(client_id=self.internal_ident)
        self.log.info("Client registered")

    async def handle_motd(self, _: List[str]) -> None:
        """Handle the MOTD command."""
        await self.msg(RPL.MOTDSTART, "- Message of the day -")
        for line in self.server.welcome_msg.strip().split("\n"):
            await self.msg(RPL.MOTD, "- " + line)
        await self.msg(RPL.ENDOFMOTD, "End of /MOTD command.")

    async def handle_ping(self, params: List[str]) -> None:
        """Handle client PING requests to keep the connection alive."""
        try:
            origin = params[0]
        except IndexError:
            raise IRCError(ERR.NOORIGIN, "No origin specified") from None

        try:
            destination = params[1]
        except IndexError:
            destination = self.server.servername
        await self.msg("PONG", [destination, origin])

    async def handle_pong(self, _: List[str]) -> None:
        """Handle client PONG responses to keep the connection alive."""
        self.last_heard = datetime.datetime.utcnow()
        self.ping_sent = False

    async def handle_join(self, params: List[str]) -> None:
        """Handle the JOIN command."""
        try:
            channels = params[0]  # ignore param 1, i.e. channel keys
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["JOIN", "Not enough parameters"]) from None

        for channel in channels.split(","):
            channel = channel.strip()

            # is this a valid channel name?
            if not re.fullmatch(r"#([\w\d_\.-])+", channel) or len(channel) > 50:
                await self.msg(ERR.NOSUCHCHANNEL, [channel, "No such channel"])
                continue

            # check if channel already exists (clients cannot create channels)
            if channel not in self.server.channels:
                await self.msg(ERR.NOSUCHCHANNEL, [channel, "No such channel"])
                continue

            self.server.subscribe(channel, self)  # add to the server's (global) list
            self.channels.add(channel)  # add channel to client's own channel list

            # send join message
            await self.msg("JOIN", channel)
            await self.handle_topic([channel])
            await self.handle_names([channel])

            self.log.info("User subscribed to feed", channel=channel)

    async def handle_topic(self, params: List[str]) -> None:
        """Handle the TOPIC command.

        Shows a hardcoded topic message when asked for one, and always deny
        setting the topic, as this is not supported.
        """
        try:
            channel = params[0]
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["TOPIC", "Not enough parameters"]) from None

        if channel not in self.channels:
            raise IRCError(ERR.NOTONCHANNEL, [channel, "You're not on that channel"])

        # if a new topic was given...
        if len(params) > 1:
            raise IRCError(ERR.CHANOPRIVSNEEDED, [channel, "You're not a channel operator"])

        await self.msg(RPL.TOPIC, [channel, self.server.topic_tmpl.format(channel=channel)])
        botid = self.server.botname + "!" + self.server.botname + "@" + self.server.servername
        await self.msg(RPL.TOPICWHOTIME, [channel, botid, str(int(self.server.boot_time.timestamp()))])

    async def handle_names(self, params: List[str]) -> None:
        """Handle the NAMES command.

        Every channel has the "bot" connected, plus, optionally, the connecting
        client.
        """
        try:
            channels = params[0]
        except IndexError:
            await self.msg(RPL.ENDOFNAMES, ["*", "End of /NAMES list"])
            return

        # ignore queries for multiple channels (as many networks do)
        channel = channels.split(",")[0].strip()

        nicklist: Iterable[str]
        if channel in self.channels:
            nicklist = (self.nick, "@" + self.server.botname)
        else:
            nicklist = ("@" + self.server.botname,)

        await self.msg(RPL.NAMREPLY, ["=", channel, " ".join(nicklist)])
        await self.msg(RPL.ENDOFNAMES, [channel, "End of /NAMES list"])

    async def handle_privmsg(self, params: List[str]) -> None:
        """Handle the PRIVMSG command, sending a message to a user or channel.

        Almost no-op in our case, as we only allow the bot to message users.
        """
        try:
            targets, msg = params[:2]
        except ValueError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["PRIVMSG", "Not enough parameters"]) from None

        for target in targets.split(","):
            target = target.strip()
            if target.startswith("#"):
                await self.msg(ERR.CANNOTSENDTOCHAN, [target, "Cannot send to channel"])
            elif target == self.server.botname:
                pass  # bot ignores all messages
            elif target == self.nick:
                await self.msg("PRIVMSG", [target, msg])  # echo back
            else:
                await self.msg(ERR.NOSUCHNICK, [target, "No such nick/channel"])

    async def handle_notice(self, params: List[str]) -> None:
        """Handle the NOTICE command, sending a notice to a user or channel.

        We only allow self-notices, and per RFC, do not return any errors.
        """
        try:
            targets, msg = params[:2]
        except ValueError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["NOTICE", "Not enough parameters"]) from None

        if self.nick in targets.split(","):
            await self.msg("NOTICE", [self.nick, msg])  # echo back

    async def handle_part(self, params: List[str]) -> None:
        """Handle the PART command."""
        try:
            channels = params[0]
        except IndexError:
            raise IRCError(ERR.NEEDMOREPARAMS, ["PART", "Not enough parameters"]) from None

        for channel in channels.split(","):
            channel = channel.strip()
            if channel in self.channels:
                self.channels.remove(channel)  # remove from client's own channel list
                self.server.unsubscribe(channel, self)  # unsubscribe from the server's (global) list
                await self.msg("PART", channel)
                self.log.info("User unsubscribed from feed", channel=channel)
            else:
                # don't raise IRCError because this can be one of many channels
                await self.msg(ERR.NOTONCHANNEL, [channel, "You're not on that channel"])

    async def handle_list(self, params: List[str]) -> None:
        """Handle the LIST command."""
        channels: Iterable[str]
        try:
            given_channels = params[0]
            channels = set(self.server.channels) & set(given_channels.split(","))
        except IndexError:
            channels = self.server.channels

        for channel in sorted(channels):
            usercount = "2" if channel in self.channels else "1"  # bot, or us and the bot
            await self.msg(RPL.LIST, [channel, usercount, self.server.topic_tmpl.format(channel=channel)])
        await self.msg(RPL.LISTEND, "End of /LIST")

    async def handle_quit(self, params: List[str]) -> None:
        """Handle the client breaking off the connection with a QUIT command."""
        try:
            reason = params[0]
        except IndexError:
            reason = "No reason"
        await self.msg("ERROR", f"Closing Link: (Quit: {reason})")
        await self.terminate()

    @property
    def registered(self) -> bool:
        """Return True if a user is registered; False otherwise."""
        return bool(self.nick and self.user)

    @property
    def client_ident(self) -> str:
        """Return the client identifier as included in many command replies."""
        if not self.registered:
            raise IRCError(ERR.NOTREGISTERED, "You have not registered")
        return f"{self.nick}!{self.user}@{self.server.servername}"

    @property
    def internal_ident(self) -> str:
        """Return the internal (non-wire-protocol) client identifier."""
        host_port = f"[{self.host}]:{self.port}"
        if not self.registered:
            return f"anonymous/{host_port}"
        return f"{self.nick}!{self.user}/{host_port}"

    async def finish(self) -> None:
        """Finish the client connection.

        Do some cleanup to ensure that the client doesn't linger around in any
        channel or the client list, in case the client didn't properly close
        the connection with PART and QUIT.
        """
        for channel in self.channels:
            self.server.unsubscribe(channel, self)
        if self._periodic_ping_task:
            try:
                self._periodic_ping_task.cancel()
                await self._periodic_ping_task  # give a chance to the task to cancel
            except asyncio.CancelledError:
                pass
            self._periodic_ping_task = None
        self.server.metrics["clients"].dec()
        self.log.info("Client disconnected")

    def __repr__(self) -> str:
        """Return a user-readable description of the client."""
        return f"<{self.__class__.__name__} {self.internal_ident}>"


class IRCServer:
    """A server class representing an IRC server."""

    log = structlog.get_logger("ircstream.irc")

    def __init__(self, config: configparser.SectionProxy) -> None:
        self.servername = config.get("servername", "irc.example.org")
        self.botname = config.get("botname", "example-bot")
        self.network = config.get("network", "Example")
        self.topic_tmpl = config.get("topic_tmpl", "Stream for topic {channel}")
        self.welcome_msg = config.get("welcome_msg", "Welcome!")

        self.boot_time = datetime.datetime.utcnow()
        self._channels: Dict[str, Set[IRCClient]] = {}
        self.client_timeout = 120

        # set up a few Prometheus metrics
        registry = prometheus_client.CollectorRegistry()
        self.metrics = {
            "clients": Gauge("ircstream_clients", "Number of IRC clients", registry=registry),
            "channels": Gauge("ircstream_channels", "Number of IRC channels", registry=registry),
            "messages": Counter("ircstream_messages", "Count of RC messages broadcasted", registry=registry),
            "errors": Counter("ircstream_errors", "Count of errors and exceptions", ["type"], registry=registry),
        }
        self.metrics["channels"].set_function(lambda: len(self._channels))
        self.metrics_registry = registry

        self.address = config.get("listen_address", fallback="::")
        self.port = config.getint("listen_port", fallback=6667)

    async def serve(self) -> None:
        """Create a new socket, listen to it and serve requests."""
        # initialize the socket ourselves, because we want to use V6ONLY that asyncio disables…
        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind((self.address, self.port))

        # specs say length is 512 (including CRLF) - set limit to handle more, as implementations vary
        server = await asyncio.start_server(lambda r, w: IRCClient(self, r, w).connect(), sock=sock, limit=512 * 2)

        if server.sockets:
            local_addr = server.sockets[0].getsockname()[:2]
            self.address, self.port = local_addr  # update address/port based on what bind() returned
        self.log.info("Listening for IRC clients", listen_address=self.address, listen_port=self.port)
        await server.serve_forever()

    def subscribe(self, channel: str, client: IRCClient) -> None:
        """Subscribe a client to broadcasts for a particular channel."""
        self._channels[channel].add(client)

    def unsubscribe(self, channel: str, client: IRCClient) -> None:
        """Unsubscribe a client from broadcasts for a particular channel."""
        self._channels[channel].remove(client)

    @property
    def channels(self) -> Iterable[str]:
        """Return a list of all the channel names known to the server."""
        return list(self._channels)

    async def broadcast(self, target: str, msg: str) -> None:
        """Broadcast a message to all clients that have joined a channel.

        The source of the message is the bot's name.
        """
        botid = self.botname + "!" + self.botname + "@" + self.servername
        message = str(IRCMessage("PRIVMSG", [target, msg], source=botid))

        clients = self._channels.setdefault(target, set())
        for client in clients:
            try:
                await client.send(message)
            except Exception:  # pylint: disable=broad-except
                self.metrics["errors"].labels("broadcast").inc()
                self.log.debug("Unable to broadcast", exc_info=True)
                continue  # ignore exceptions, to catch corner cases
        self.metrics["messages"].inc()


class RC2UDPHandler(asyncio.Protocol):
    """A handler implementing the RC2UDP protocol, as used by MediaWiki."""

    log = structlog.get_logger("ircstream.rc2udp")

    def __init__(self, server: RC2UDPServer) -> None:
        self.server = server

    def datagram_received(self, data: bytes, _: Tuple[str, int]) -> None:
        """Receive a new RC2UDP message and broadcast to all clients."""
        try:
            decoded = data.decode("utf8")
            channel, text = decoded.split("\t", maxsplit=1)
            channel = channel.strip()
            text = text.lstrip().replace("\r", "").replace("\n", "")
        except Exception:  # pylint: disable=broad-except
            self.server.ircserver.metrics["errors"].labels("rc2udp-parsing").inc()
            return

        self.log.debug("Broadcasting message", channel=channel, message=text)
        asyncio.create_task(self.server.ircserver.broadcast(channel, text))


class RC2UDPServer:  # pylint: disable=too-few-public-methods
    """A server implementing the RC2UDP protocol, as used by MediaWiki."""

    log = structlog.get_logger("ircstream.rc2udp")

    def __init__(self, config: configparser.SectionProxy, ircserver: IRCServer) -> None:
        self.ircserver = ircserver
        self.address = config.get("listen_address", fallback="::")
        self.port = config.getint("listen_port", fallback=9390)

    async def serve(self) -> None:
        """Create a new socket, listen to it and serve requests."""
        loop = asyncio.get_running_loop()
        local_addr = (self.address, self.port)
        transport, _ = await loop.create_datagram_endpoint(lambda: RC2UDPHandler(self), local_addr=local_addr)
        local_addr = transport.get_extra_info("sockname")[:2]
        self.address, self.port = local_addr  # update address/port based on what bind() returned
        self.log.info("Listening for RC2UDP broadcast", listen_address=self.address, listen_port=self.port)


class PrometheusServer(http.server.ThreadingHTTPServer):
    """A Prometheus HTTP server."""

    log = structlog.get_logger("ircstream.prometheus")
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        config: configparser.SectionProxy,
        registry: prometheus_client.CollectorRegistry = prometheus_client.REGISTRY,
    ) -> None:
        listen_address = config.get("listen_address", fallback="::")
        if ":" in listen_address:
            self.address_family = socket.AF_INET6
        listen_port = config.getint("listen_port", fallback=9200)
        super().__init__((listen_address, listen_port), prometheus_client.MetricsHandler.factory(registry))
        self.address, self.port = self.server_address[:2]  # update address/port based on what bind() returned
        self.log.info("Listening for Prometheus HTTP", listen_address=self.address, listen_port=self.port)

    def server_bind(self) -> None:
        """Bind to an IP address.

        Override to set an opt to listen to both IPv4/IPv6 on the same socket.
        """
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    """Parse and return the parsed command line arguments."""
    parser = argparse.ArgumentParser(
        prog="ircstream",
        description="MediaWiki RecentChanges → IRC gateway",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--config-file", "-c", default="/etc/ircstream.conf", help="Path to configuration file")

    log_levels = ("DEBUG", "INFO", "WARNING", "ERROR")  # no public method to get a list from logging :(
    parser.add_argument("--log-level", default="INFO", choices=log_levels, type=str.upper, help="Log level")
    log_formats = ("plain", "console", "json")
    log_dflt = "console" if sys.stdout.isatty() else "plain"
    parser.add_argument("--log-format", default=log_dflt, choices=log_formats, help="Log format")
    return parser.parse_args(argv)


def configure_logging(log_format: str = "plain") -> None:
    """Configure logging parameters."""
    logging.basicConfig(format="%(message)s", level=logging.WARNING)

    processors: List[structlog.types.Processor] = [
        structlog.stdlib.filter_by_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if log_format == "plain":
        processors += [structlog.dev.ConsoleRenderer(colors=False)]
    elif log_format == "console":
        processors = [structlog.stdlib.add_log_level] + structlog.get_config()["processors"]
    elif log_format == "json":
        processors += [
            structlog.stdlib.add_logger_name,  # adds a "logger" key
            structlog.stdlib.add_log_level,  # adds a "level" key (string, not int)
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(sort_keys=True),
        ]
    else:
        raise ValueError(f"Invalid logging format specified: {log_format}")

    structlog.configure(
        processors=processors,
        context_class=structlog.threadlocal.wrap_dict(dict),
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
    )


async def start_servers(config: configparser.ConfigParser) -> None:
    """Start all servers in asyncio tasks or threads and then busy-loop."""
    log = structlog.get_logger("ircstream.main")
    loop = asyncio.get_running_loop()

    try:
        if "irc" in config:
            ircserver = IRCServer(config["irc"])
            irc_coro = ircserver.serve()
            irc_task = asyncio.create_task(irc_coro)
        else:
            log.critical('Invalid configuration, missing section "irc"')
            raise SystemExit(-1)

        if "rc2udp" in config:
            rc2udp_coro = RC2UDPServer(config["rc2udp"], ircserver).serve()
            asyncio.create_task(rc2udp_coro)
        else:
            log.warning("RC2UDP is not enabled in the config; server usefulness may be limited")

        if "prometheus" in config:
            prom_server = PrometheusServer(config["prometheus"], ircserver.metrics_registry)
            prom_server.socket.setblocking(False)
            loop.add_reader(prom_server.socket, prom_server.handle_request)

        await asyncio.wait_for(irc_task, timeout=None)  # run forever
    except OSError as exc:
        log.critical(f"System error: {exc.strerror}", errno=errno.errorcode[exc.errno])
        raise SystemExit(-2) from exc


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Entry point."""
    options = parse_args(argv)

    configure_logging(options.log_format)
    # only set e.g. INFO or DEBUG for our own loggers
    structlog.get_logger("ircstream").setLevel(options.log_level)
    log = structlog.get_logger("ircstream.main")
    log.info("Starting IRCStream", config_file=options.config_file, version=__version__)

    config = configparser.ConfigParser(strict=True)
    try:
        with open(options.config_file, encoding="utf-8") as config_fh:
            config.read_file(config_fh)
    except OSError as exc:
        log.critical(f"Cannot open configuration file: {exc.strerror}", errno=errno.errorcode[exc.errno])
        raise SystemExit(-1) from exc
    except configparser.Error as exc:
        msg = repr(exc).replace("\n", " ")  # configparser exceptions sometimes include newlines
        log.critical(f"Invalid configuration, {msg}")
        raise SystemExit(-1) from exc

    try:
        asyncio.run(start_servers(config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
