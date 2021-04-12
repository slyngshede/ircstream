"""Testing initialization."""

from __future__ import annotations

import asyncio
import configparser
import logging
from typing import (
    AsyncGenerator,
    Generator,
    List,
)

import ircstream

import prometheus_client  # type: ignore

import pytest

import structlog


@pytest.fixture(autouse=True)
def fixture_configure_structlog() -> None:
    """Fixture to configure structlog. Currently just silences it entirely."""

    def dummy_processor(
        logger: logging.Logger, name: str, event_dict: structlog.types.EventDict
    ) -> structlog.types.EventDict:
        raise structlog.exceptions.DropEvent

    structlog.configure(processors=[dummy_processor])


@pytest.fixture(name="config", scope="module", params=["127.0.0.1", "::1"])
def fixture_config(request: pytest.FixtureRequest) -> Generator[configparser.ConfigParser, None, None]:
    """Fixture representing an example configuration."""
    listen_address = request.param  # type: ignore # pytest bug?
    config = configparser.ConfigParser()
    config.read_string(
        f"""
        [irc]
        listen_address = {listen_address}
        # pick a random free port (not 6667!)
        listen_port = 0
        servername = irc.example.org
        network = Example
        botname = rc-bot
        topic_tmpl = Test topic for {{channel}}
        welcome_msg =
          *******************************************************
          This is a test IRC instance
          *******************************************************
          Sending messages to channels is not allowed.

        [rc2udp]
        listen_address = {listen_address}
        listen_port = 0

        [prometheus]
        listen_address = {listen_address}
        listen_port = 0
        """
    )
    yield config


@pytest.fixture(name="event_loop", scope="module")
def fixture_event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Override for pytest-asyncio's event_loop fixture to scope it as module."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(name="ircserver", scope="module")
async def fixture_ircserver(config: configparser.ConfigParser) -> AsyncGenerator[ircstream.IRCServer, None]:
    """Fixture for an instance of an IRCServer.

    This spawns a task to run the server. It yields the IRCServer instance,
    *not* the task, however.
    """
    # hack: cleanup prometheus_client's registry, to avoid Duplicated timeseries messages when reusing
    prometheus_client.REGISTRY.__init__()

    # set up a fake EXCEPTION command handler, that raises an exception
    # useful to test whether exceptions are actually being caught!
    def handle_raiseexc(self: ircstream.IRCClient, _: List[str]) -> None:
        raise Exception("Purposefully triggered exception")

    ircstream.IRCClient.handle_raiseexc = handle_raiseexc  # type: ignore

    ircserver = ircstream.IRCServer(config["irc"])
    irc_task = asyncio.create_task(ircserver.serve())
    yield ircserver
    irc_task.cancel()


@pytest.fixture(name="ircserver_short_timeout")
async def fixture_ircserver_short_timeout(ircserver: ircstream.IRCServer) -> AsyncGenerator[ircstream.IRCServer, None]:
    """Return an IRCServer modified to run with a very short timeout.

    This is a separate fixture to make sure that the default value is restored
    e.g. if the test fails.
    """
    # save the old timeout
    default_timeout = ircserver.client_timeout
    # set timeout to a (much) smaller value, to avoid long waits while testing
    ircserver.client_timeout = 2
    yield ircserver
    # restore it to the default value
    ircserver.client_timeout = default_timeout
