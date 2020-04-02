"""Test an instance of our IRCServer, using the Python irc library."""

import configparser
import queue
import threading
import time

import irc.client  # type: ignore

import ircstream

import prometheus_client

import pytest  # type: ignore

import pytest_structlog

import structlog


@pytest.fixture(name="log", scope="module")
def log_fixture():
    """Fixture providing access to captured structlog events.

    This is almost identical to pytest_structlog, but modified to support
    scoping it as a module. Reported upstream as wimglenn/pytest-structlog #9.
    """
    # save settings for later
    processors = structlog.get_config().get("processors", [])
    configure = structlog.configure

    # redirect logging to log capture
    cap = pytest_structlog.StructuredLogCapture()
    structlog.configure(processors=[cap.process])
    yield cap

    # back to normal behavior
    configure(processors=processors)


@pytest.fixture(name="ircconfig", scope="module")
def ircconfig_instance():
    """Fixture representing an example configuration."""
    ircconfig = configparser.ConfigParser()
    ircconfig.read_string(
        """
        [irc]
        # only listen to localhost
        listen_address = 127.0.0.1
        # pick a random free port (not 6667!)
        listen_port = 0
        servername = irc.example.org
        network = Example
        botname = rc-bot
        topic_tmpl = Test topic for {channel}
        welcome_msg =
          *******************************************************
          This is a test instance IRC instance
          *******************************************************
          Sending messages to channels is not allowed.
        """
    )
    yield ircconfig


@pytest.fixture(name="ircserver", scope="module")
def ircserver_instance(ircconfig, log):
    """Fixture for an instance of an IRCServer.

    This spawns a thread to run the server. It yields the IRCServer instance,
    *not* the thread, however.
    """
    ircserver = ircstream.IRCServer(ircconfig["irc"], ircstream.IRCClient)
    ircserver_thread = threading.Thread(name="ircserver", target=ircserver.serve_forever, daemon=True)
    ircserver_thread.start()

    for _ in range(50):
        if log.has("Listening for IRC clients"):
            break
        time.sleep(0.1)

    yield ircserver

    ircserver.shutdown()
    ircserver_thread.join()
    ircserver.server_close()

    # hack: cleanup prometheus_client's registry, to avoid Duplicated timeseries messages when reusing
    prometheus_client.REGISTRY.__init__()


class IRCClient(threading.Thread, irc.client.SimpleIRCClient):
    """Basic IRC Client, used for testing.

    This runs as a thread, and is thus processing events "asynchronously".

    The IRC implementation is third-party, but as far as this server goes,
    it's pretty dummy: it just shoves incoming events into a queue, and
    provides a method to consume from the queue.
    """

    def __init__(self):
        threading.Thread.__init__(self, name="ircclient", daemon=True)
        irc.client.SimpleIRCClient.__init__(self)
        self.events = queue.SimpleQueue()
        self._shutdown_request = False

    def run(self):
        """Run the thread."""
        while not self._shutdown_request:
            try:
                process_fn = self.reactor.process_once  # pylint: disable=no-member
            except AttributeError:
                # compatibility with older versions
                process_fn = self.ircobj.process_once  # pylint: disable=no-member
            process_fn(0.2)

    def shutdown(self):
        """Shutdown the client.

        Sets a shutdown request signal, that makes the server stop processing
        events. Does not gracefully disconnect for now).
        """
        self._shutdown_request = True

    def _dispatcher(self, _, event: irc.client.Event):
        """Handle callbacks for all events.

        Just shoves incoming events into a simple queue.
        """
        # print(f"{event.type}, source={event.source}, target={event.target}, arguments={event.arguments}")
        self.events.put(event)

    def expect(self, typ: str, timeout=2, **kwargs):
        """Groks events until the expect one is found.

        If the matching event is not found within a timeout, returns None.
        otherwise, the matching event.
        """
        found = None
        while True:  # grok events until the queue is empty
            try:
                # break if no messages have been received for a given timeout
                event = self.events.get(block=True, timeout=timeout)
            except queue.Empty:
                break

            # match the given type + other criteria (source, target, arguments)
            matched = event.type == typ
            for name, value in kwargs.items():
                matched &= getattr(event, name) == value

            if matched:
                found = event
                break
        return found


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
def test_mode(ircclient, ircconfig):
    """Test the MODE command."""
    other_bot_name = ircconfig["irc"]["botname"]

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

    ircclient.connection.mode(other_bot_name, "")
    assert ircclient.expect("usersdontmatch")

    ircclient.connection.mode("nonexistent", "")
    assert ircclient.expect("nosuchnick")


@pytest.mark.usefixtures("ircserver")
def test_whois(ircclient, ircconfig):
    """Test the WHOIS command."""
    other_bot_name = ircconfig["irc"]["botname"]

    ircclient.connection.whois([other_bot_name])
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
def test_privmsg(ircclient, ircconfig):
    """Test the PRIVMSG command."""
    other_bot_name = ircconfig["irc"]["botname"]

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

    ircclient.connection.privmsg(other_bot_name, "message")
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
