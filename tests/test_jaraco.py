"""Test an instance of our IRCServer, using a Python IRC client."""

from __future__ import annotations

from typing import Generator

import ircstream

import pytest

from .ircclient import IRCClientThread

BOTNAME = "testsuite-bot"


@pytest.fixture(name="ircclient", scope="module")
def ircclient_instance(ircserver: ircstream.IRCServer) -> Generator[IRCClientThread, None, None]:
    """Fixture for an instance of an IRCClient."""
    ircclient = IRCClientThread()
    ircclient.start()
    ircclient.connect(ircserver.address, ircserver.port, BOTNAME)

    yield ircclient

    ircclient.connection.quit()
    assert ircclient.expect("error")

    ircclient.shutdown()
    ircclient.join()


@pytest.mark.usefixtures("ircserver")
def test_ping(ircclient: IRCClientThread) -> None:
    """Test the PING command."""
    ircclient.connection.ping("there")
    assert ircclient.expect("pong", arguments=["there"])
    ircclient.connection.ping("")
    assert ircclient.expect("noorigin")


@pytest.mark.usefixtures("ircserver")
def test_pong(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test the PONG command (a server-side ping)."""
    # save the old timeout
    default_timeout = ircserver.client_timeout

    # set timeout to a (much) smaller value, to avoid long waits while testing
    ircserver.client_timeout = 2
    wait_for = (ircserver.client_timeout / 2) + 1
    ircclient.connection.ping("break the event loop")
    assert ircclient.expect("ping", timeout=wait_for)

    # restore it to the default value
    ircserver.client_timeout = default_timeout


@pytest.mark.usefixtures("ircserver")
def test_who(ircclient: IRCClientThread) -> None:
    """Test the WHO command."""
    ircclient.connection.who(BOTNAME)
    assert ircclient.expect("endofwho")

    ircclient.connection.who()
    assert ircclient.expect("endofwho")


@pytest.mark.usefixtures("ircserver")
def test_mode(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test the MODE command."""
    # channel modes
    ircclient.connection.mode("", "")
    assert ircclient.expect("needmoreparams")

    ircclient.connection.mode("#one-channel", "")
    assert ircclient.expect("channelmodeis")

    ircclient.connection.mode("#one-channel", "b")
    assert ircclient.expect("endofbanlist")

    ircclient.connection.mode("#one-channel", "o")
    assert ircclient.expect("chanoprivsneeded")

    # user modes
    ircclient.connection.mode(BOTNAME, "")
    assert ircclient.expect("umodeis")

    ircclient.connection.mode(BOTNAME, "+r")
    # (no response expected)

    ircclient.connection.mode(ircserver.botname, "")
    assert ircclient.expect("usersdontmatch")

    ircclient.connection.mode("nonexistent", "")
    assert ircclient.expect("nosuchnick")


@pytest.mark.usefixtures("ircserver")
def test_whois(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test the WHOIS command."""
    ircclient.connection.whois([ircserver.botname])
    assert ircclient.expect("whoisuser")
    assert ircclient.expect("whoisserver")
    assert ircclient.expect("whoisidle")

    ircclient.connection.whois([BOTNAME])
    assert ircclient.expect("whoisuser")
    assert ircclient.expect("whoisserver")
    assert ircclient.expect("whoisidle")

    ircclient.connection.whois(["nonexistent"])
    assert ircclient.expect("nosuchnick")

    ircclient.connection.whois("")
    assert ircclient.expect("nonicknamegiven")


@pytest.mark.usefixtures("ircserver")
def test_whowas(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test the WHOWAS command."""
    ircclient.connection.whowas(ircserver.botname)
    assert ircclient.expect("wasnosuchnick")
    assert ircclient.expect("endofwhowas")

    ircclient.connection.whowas(BOTNAME)
    assert ircclient.expect("wasnosuchnick")
    assert ircclient.expect("endofwhowas")

    ircclient.connection.whowas("")
    assert ircclient.expect("nonicknamegiven")


@pytest.mark.usefixtures("ircserver")
def test_nick(ircclient: IRCClientThread) -> None:
    """Test the NICK command."""
    ircclient.connection.nick("")
    assert ircclient.expect("nonicknamegiven")

    ircclient.connection.nick("i")
    assert ircclient.expect("erroneusnickname")

    # change our nickname
    ircclient.connection.nick("new-nick")
    assert ircclient.expect("nick", target="new-nick")

    # make sure the internal state of the server has also changed
    ircclient.connection.whois([BOTNAME])
    assert ircclient.expect("nosuchnick")

    # change our nickname back (be nice to other tests)
    ircclient.connection.nick(BOTNAME)
    assert ircclient.expect("nick", target=BOTNAME)


@pytest.mark.usefixtures("ircserver")
def test_user(ircclient: IRCClientThread) -> None:
    """Test the USER command."""
    ircclient.connection.user("", "")
    assert ircclient.expect("needmoreparams")

    ircclient.connection.user("new-nick", "new-realname")
    assert ircclient.expect("alreadyregistered")


@pytest.mark.usefixtures("ircserver")
def test_join(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test the JOIN command."""
    ircclient.connection.join("")
    assert ircclient.expect("needmoreparams")

    ircclient.connection.join("invalid")
    assert ircclient.expect("nosuchchannel")

    ircclient.connection.join("#nonexistent")
    assert ircclient.expect("nosuchchannel")

    # join a valid channel
    ircserver.broadcast("#one-channel", "create the channel")
    ircclient.connection.join("#one-channel")
    assert ircclient.expect("join", target="#one-channel")

    # also part the channel, to reset state and be nice to other tests
    ircclient.connection.part("#one-channel")
    assert ircclient.expect("part", target="#one-channel")


@pytest.mark.usefixtures("ircserver")
def test_part(ircclient: IRCClientThread) -> None:
    """Test the PART command."""
    ircclient.connection.part("")
    assert ircclient.expect("needmoreparams")

    ircclient.connection.part("#nonexistent")
    assert ircclient.expect("notonchannel")

    ircclient.connection.part("#one-channel")
    assert ircclient.expect("notonchannel")

    # actual part tested in the JOIN test


@pytest.mark.usefixtures("ircserver")
def test_topic(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test the TOPIC command."""
    ircclient.connection.topic("")
    assert ircclient.expect("needmoreparams")

    ircclient.connection.topic("#nonexistent", "new topic")
    assert ircclient.expect("notonchannel")

    ircserver.broadcast("#one-channel", "create the channel")
    ircclient.connection.join("#one-channel")
    assert ircclient.expect("join", target="#one-channel")

    ircclient.connection.topic("#one-channel")
    assert ircclient.expect("currenttopic", arguments=["#one-channel", "Test topic for #one-channel"])
    assert ircclient.expect("topicinfo")

    ircclient.connection.topic("#one-channel", "new topic")
    assert ircclient.expect("chanoprivsneeded")

    # also part the channel, to reset state and be nice to other tests
    ircclient.connection.part("#one-channel")
    assert ircclient.expect("part", target="#one-channel")


@pytest.mark.usefixtures("ircserver")
def test_names(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test the NAMES command."""
    ircclient.connection.names("")
    assert ircclient.expect("endofnames")

    ircserver.broadcast("#another-channel", "create another channel")
    ircclient.connection.names("#another-channel")
    assert ircclient.expect("endofnames")


@pytest.mark.usefixtures("ircserver")
def test_privmsg(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test the PRIVMSG command."""
    ircclient.connection.privmsg("", "")
    assert ircclient.expect("needmoreparams")

    # channel messages
    ircclient.connection.privmsg("#one-channel", "message")
    assert ircclient.expect("cannotsendtochan")

    # private messages
    ircclient.connection.privmsg(BOTNAME, "message")
    assert ircclient.expect("privmsg")

    ircclient.connection.privmsg("nonexistent", "message")
    assert ircclient.expect("nosuchnick")

    ircclient.connection.privmsg(ircserver.botname, "message")
    # (no response expected)


@pytest.mark.usefixtures("ircserver")
def test_notice(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test the NOTICE command."""
    ircclient.connection.notice("", "")
    assert ircclient.expect("needmoreparams")

    # private messages
    ircclient.connection.notice(BOTNAME, "message")
    assert ircclient.expect("privnotice")

    ircclient.connection.privmsg(ircserver.botname, "message")
    ircclient.connection.notice("nonexistent", "message")
    # (no response expected)


@pytest.mark.usefixtures("ircserver")
def test_list(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test the LIST command."""
    ircclient.connection.list()
    assert ircclient.expect("listend")

    ircserver.broadcast("#one-channel", "create the channel")
    ircclient.connection.list()
    assert ircclient.expect("listend")

    ircclient.connection.list(["#one-channel"])
    assert ircclient.expect("list")
    assert ircclient.expect("listend")


@pytest.mark.usefixtures("ircserver")
def test_nonexistent(ircclient: IRCClientThread) -> None:
    """Test a non-existent command."""
    ircclient.connection.send_raw("NONEXISTENT :nonarg")
    assert ircclient.expect("unknowncommand")


@pytest.mark.usefixtures("ircserver")
def test_conversation(ircserver: ircstream.IRCServer, ircclient: IRCClientThread) -> None:
    """Test a scenario of a hypothetic real client/conversation."""
    ircserver.broadcast("#one-channel", "create the channel")

    ircclient.connection.join("#one-channel")
    assert ircclient.expect("join", target="#one-channel")

    ircserver.broadcast("#one-channel", "this is another message")
    assert ircclient.expect("pubmsg", target="#one-channel", arguments=["this is another message"])
