"""Testing initialization."""

import configparser

import ircstream

import prometheus_client  # type: ignore

import pytest  # type: ignore

import structlog  # type: ignore


@pytest.fixture(autouse=True)
def fixture_configure_structlog() -> None:
    """Fixture to configure structlog. Currently just silences it entirely."""

    def dummy_processor(logger, name, event_dict):
        raise structlog.exceptions.DropEvent

    structlog.configure(processors=[dummy_processor])


@pytest.fixture(name="config", scope="module")
def fixture_config():
    """Fixture representing an example configuration."""
    config = configparser.ConfigParser()
    config.read_string(
        """
        [irc]
        listen_address = ::
        # pick a random free port (not 6667!)
        listen_port = 0
        servername = irc.example.org
        network = Example
        botname = rc-bot
        topic_tmpl = Test topic for {channel}
        welcome_msg =
          *******************************************************
          This is a test IRC instance
          *******************************************************
          Sending messages to channels is not allowed.

        [rc2udp]
        listen_address = ::
        listen_port = 0

        [prometheus]
        listen_address = ::
        listen_port = 0
        """
    )
    yield config


@pytest.fixture(name="ircserver", scope="module")
def fixture_ircserver(config):
    """Fixture for an instance of an IRCServer.

    This spawns a thread to run the server. It yields the IRCServer instance,
    *not* the thread, however.
    """
    server, thread = ircstream.start(ircstream.IRCServer, config["irc"])

    yield server

    server.shutdown()
    thread.join()
    server.server_close()

    # hack: cleanup prometheus_client's registry, to avoid Duplicated timeseries messages when reusing
    prometheus_client.REGISTRY.__init__()
