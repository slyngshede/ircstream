"""Testing initialization."""

from __future__ import annotations

import configparser
import logging
import socketserver
import threading
from typing import (
    Any,
    Generator,
    List,
    Type,
    TypeVar,
)

import ircstream

import prometheus_client  # type: ignore

import pytest

import structlog


BaseServerCls = TypeVar("BaseServerCls", bound=socketserver.BaseServer)


def start_server_in_thread(
    cls: Type[BaseServerCls], config: configparser.SectionProxy, *args: Any
) -> Generator[BaseServerCls, None, None]:
    """Start a socketserver in a thread, yield, and cleanly shut it down."""
    server = cls(config, *args)
    thread = threading.Thread(name=config.name, target=server.serve_forever)
    thread.start()

    yield server

    server.shutdown()
    thread.join()
    server.server_close()


@pytest.fixture(autouse=True)
def fixture_configure_structlog() -> None:
    """Fixture to configure structlog. Currently just silences it entirely."""

    def dummy_processor(
        logger: logging.Logger, name: str, event_dict: structlog.types.EventDict
    ) -> structlog.types.EventDict:
        raise structlog.exceptions.DropEvent

    structlog.configure(processors=[dummy_processor])


@pytest.fixture(name="config", scope="module")
def fixture_config() -> Generator[configparser.ConfigParser, None, None]:
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
def fixture_ircserver(config: configparser.ConfigParser) -> Generator[ircstream.IRCServer, None, None]:
    """Fixture for an instance of an IRCServer.

    This spawns a thread to run the server. It yields the IRCServer instance,
    *not* the thread, however.
    """
    # hack: cleanup prometheus_client's registry, to avoid Duplicated timeseries messages when reusing
    prometheus_client.REGISTRY.__init__()

    # set up a fake EXCEPTION command handler, that raises an exception
    # useful to test whether exceptions are actually being caught!
    def handle_raiseexc(self: ircstream.IRCClient, _: List[str]) -> None:
        raise Exception("Purposefully triggered exception")

    ircstream.IRCClient.handle_raiseexc = handle_raiseexc  # type: ignore
    yield from start_server_in_thread(ircstream.IRCServer, config["irc"])
