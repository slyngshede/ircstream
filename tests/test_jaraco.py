"""Test an instance of our IRCServer, using a Python IRC client."""

import pytest  # type: ignore

from .ircclient import IRCClient


@pytest.fixture(name="ircclient", scope="module")
def ircclient_instance(ircserver):
    """Fixture for an instance of an IRCClient."""
    ircclient = IRCClient()
    ircclient.start()
    ircclient.connect(ircserver.address, ircserver.port, "testsuite-bot")

    yield ircclient

    # quit
    ircclient.connection.quit()
    assert ircclient.expect("error")

    ircclient.shutdown()
    ircclient.join()


@pytest.mark.usefixtures("ircserver")
def test_ping(ircclient):
    """Test the PING command."""
    ircclient.connection.ping("there")
    assert ircclient.expect("pong", arguments=["there"])
    ircclient.connection.ping("")
    assert ircclient.expect("noorigin")


@pytest.mark.usefixtures("ircserver")
def test_pong(ircserver, ircclient):
    """Test the PONG command (a server-side ping)."""
    # save the old timeout
    default_timeout = ircserver.client_timeout

    # set timeout to a (much) smaller value, to avoid long waits while testing
    ircserver.client_timeout = 4
    wait_for = (ircserver.client_timeout / 4) + 1
    assert ircclient.expect("ping", timeout=wait_for)

    # restore it to the default value
    ircserver.client_timeout = default_timeout


@pytest.mark.usefixtures("ircserver")
def test_who(ircclient):
    """Test the WHO command."""
    ircclient.connection.who("testsuite-bot")
    assert ircclient.expect("endofwho")

    ircclient.connection.who()
    assert ircclient.expect("endofwho")


@pytest.mark.usefixtures("ircserver")
def test_mode(ircserver, ircclient):
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
    ircclient.connection.mode("testsuite-bot", "")
    assert ircclient.expect("umodeis")

    ircclient.connection.mode("testsuite-bot", "+r")
    # (no response expected)

    ircclient.connection.mode(ircserver.botname, "")
    assert ircclient.expect("usersdontmatch")

    ircclient.connection.mode("nonexistent", "")
    assert ircclient.expect("nosuchnick")


@pytest.mark.usefixtures("ircserver")
def test_whois(ircserver, ircclient):
    """Test the WHOIS command."""
    ircclient.connection.whois([ircserver.botname])
    assert ircclient.expect("whoisuser")
    assert ircclient.expect("whoisserver")
    assert ircclient.expect("whoisidle")

    ircclient.connection.whois(["testsuite-bot"])
    assert ircclient.expect("whoisuser")
    assert ircclient.expect("whoisserver")
    assert ircclient.expect("whoisidle")

    ircclient.connection.whois(["nonexistent"])
    assert ircclient.expect("nosuchnick")

    ircclient.connection.whois("")
    assert ircclient.expect("nonicknamegiven")


@pytest.mark.usefixtures("ircserver")
def test_nick(ircclient):
    """Test the NICK command."""
    ircclient.connection.nick("")
    assert ircclient.expect("nonicknamegiven")

    ircclient.connection.nick("i")
    assert ircclient.expect("erroneusnickname")

    # change our nickname
    ircclient.connection.nick("new-nick")
    assert ircclient.expect("nick", target="new-nick")

    # make sure the internal state of the server has also changed
    ircclient.connection.whois(["testsuite-bot"])
    assert ircclient.expect("nosuchnick")

    # change our nickname back (be nice to other tests)
    ircclient.connection.nick("testsuite-bot")
    assert ircclient.expect("nick", target="testsuite-bot")


@pytest.mark.usefixtures("ircserver")
def test_user(ircclient):
    """Test the USER command."""
    ircclient.connection.user("", "")
    assert ircclient.expect("needmoreparams")

    ircclient.connection.user("new-nick", "new-realname")
    assert ircclient.expect("alreadyregistered")


@pytest.mark.usefixtures("ircserver")
def test_join(ircserver, ircclient):
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
def test_part(ircclient):
    """Test the PART command."""
    ircclient.connection.part("")
    assert ircclient.expect("needmoreparams")

    ircclient.connection.part("#nonexistent")
    assert ircclient.expect("notonchannel")

    ircclient.connection.part("#one-channel")
    assert ircclient.expect("notonchannel")

    # actual part tested in the JOIN test


@pytest.mark.usefixtures("ircserver")
def test_topic(ircserver, ircclient):
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
def test_names(ircserver, ircclient):
    """Test the NAMES command."""
    ircclient.connection.names("")
    assert ircclient.expect("endofnames")

    ircserver.broadcast("#another-channel", "create another channel")
    ircclient.connection.names("#another-channel")
    assert ircclient.expect("endofnames")


@pytest.mark.usefixtures("ircserver")
def test_privmsg(ircserver, ircclient):
    """Test the PRIVMSG command."""
    ircclient.connection.privmsg("", "")
    assert ircclient.expect("needmoreparams")

    # channel messages
    ircclient.connection.privmsg("#one-channel", "message")
    assert ircclient.expect("cannotsendtochan")

    # private messages
    ircclient.connection.privmsg("testsuite-bot", "message")
    assert ircclient.expect("privmsg")

    ircclient.connection.privmsg("nonexistent", "message")
    assert ircclient.expect("nosuchnick")

    ircclient.connection.privmsg(ircserver.botname, "message")
    # (no response expected)


@pytest.mark.usefixtures("ircserver")
def test_list(ircserver, ircclient):
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
def test_nonexistent(ircclient):
    """Test a non-existent command."""
    ircclient.connection.send_raw("NONEXISTENT :nonarg")
    assert ircclient.expect("unknowncommand")


@pytest.mark.usefixtures("ircserver")
def test_conversation(ircserver, ircclient):
    """Test a scenario of a hypothetic real client/conversation."""
    ircserver.broadcast("#one-channel", "create the channel")

    ircclient.connection.join("#one-channel")
    assert ircclient.expect("join", target="#one-channel")

    ircserver.broadcast("#one-channel", "this is another message")
    assert ircclient.expect("pubmsg", target="#one-channel", arguments=["this is another message"])
