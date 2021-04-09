"""Tests for the RC2UDP protocol server."""

from __future__ import annotations

import configparser
import socket
import threading
from typing import (
    Generator,
    List,
    Tuple,
)

import ircstream

import prometheus_client  # type: ignore

import pytest

from .conftest import start_server_in_thread


class MockIRCServer:
    """Mocks the IRCServer object.

    Provide only a few functions that the RC2UDPServer expects.
    """

    def __init__(self) -> None:
        self._event = threading.Event()  # set when a broadcast event has been sent
        self.data: List[Tuple[str, str]] = []  # accumulates parsed broadcast messages received
        self.metrics = {  # emulates the prometheus interface
            "errors": prometheus_client.Counter("mock_errors", "Count of mocked errors", ["type"]),
        }

    def broadcast(self, target: str, msg: str) -> None:
        """Mock IRCServer's broadcast method."""
        self.data.append((target, msg))
        self._event.set()

    def wait(self, timeout: float = 0.2) -> bool:
        """Wait until the event triggers."""
        return self._event.wait(timeout)

    def clear(self) -> None:
        """Clear accumulated messages and the associated event."""
        self.data.clear()
        self._event.clear()


@pytest.fixture(name="mock_ircserver", scope="module")
def fixture_mock_ircserver() -> MockIRCServer:
    """Fixture for an instance of MockIRCServer."""
    return MockIRCServer()


@pytest.fixture(name="rc2udp_server", scope="module")
def fixture_rc2udp_server(
    config: configparser.ConfigParser,
    mock_ircserver: MockIRCServer,
) -> Generator[ircstream.RC2UDPServer, None, None]:
    """Fixture for an instance of an RC2UDPServer.

    This spawns a thread to run the server. It yields the instance.
    """
    yield from start_server_in_thread(ircstream.RC2UDPServer, config["rc2udp"], mock_ircserver)


def send_datagram(address: str, port: int, data: bytes) -> None:
    """Small helper to send UDP datagrams."""
    if ":" in address:
        afi = socket.AF_INET6
    else:
        afi = socket.AF_INET
    sock = socket.socket(afi, socket.SOCK_DGRAM)
    sock.sendto(data, (address, port))


@pytest.mark.parametrize("message", ["my message", "#lookslikeachannel", "onetab\tsecond tab"])
def test_rc2udp_valid(mock_ircserver: MockIRCServer, rc2udp_server: ircstream.RC2UDPServer, message: str) -> None:
    """Test that valid RC2UDP messages are received and parsed correctly."""
    mock_ircserver.clear()
    data = ("#channel", message)
    rawdata = "\t".join(data).encode()
    send_datagram(rc2udp_server.address, rc2udp_server.port, rawdata)
    assert mock_ircserver.wait()
    assert mock_ircserver.data == [data]


@pytest.mark.parametrize("data", [b"#nomessage", b"#channel\tinvalid utf8\x80"])
def test_rc2udp_invalid(mock_ircserver: MockIRCServer, rc2udp_server: ircstream.RC2UDPServer, data: bytes) -> None:
    """Test that invalid RC2UDP are dropped gracefully."""
    mock_ircserver.clear()
    send_datagram(rc2udp_server.address, rc2udp_server.port, data)
    assert not mock_ircserver.wait()
    assert len(mock_ircserver.data) == 0
