"""Tests for the RC2UDP protocol server."""

import socket
import threading
from typing import List, Tuple

import ircstream

import prometheus_client  # type: ignore

import pytest  # type: ignore


class MockIRCServer:
    """Mocks the IRCServer object.

    Provide gonly a few functions that the RC2UDPServer expects.
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


@pytest.fixture(name="rc2udp_server", scope="module")
def fixture_rc2udp_server(config):
    """Fixture for an instance of an RC2UDPServer.

    This spawns a thread to run the server. It yields the instance.
    """
    mock_ircserver = MockIRCServer()
    rc2udp_server = ircstream.RC2UDPServer(config["rc2udp"], ircstream.RC2UDPHandler, mock_ircserver)  # type: ignore
    rc2udp_thread = threading.Thread(name="rc2udp", target=rc2udp_server.serve_forever, daemon=True)
    rc2udp_thread.start()

    yield rc2udp_server

    rc2udp_server.shutdown()
    rc2udp_thread.join()
    rc2udp_server.server_close()


def send_datagram(address: str, port: int, data: bytes) -> None:
    """Small helper to send UDP datagrams."""
    if ":" in address:
        afi = socket.AF_INET6
    else:
        afi = socket.AF_INET
    sock = socket.socket(afi, socket.SOCK_DGRAM)
    sock.sendto(data, (address, port))


@pytest.mark.parametrize("message", ["my message", "#lookslikeachannel", "onetab\tsecond tab"])
def test_rc2udp_valid(rc2udp_server, message):
    """Test that valid RC2UDP messages are received and parsed correctly."""
    rc2udp_server.ircserver.clear()
    data = ("#channel", message)
    rawdata = "\t".join(data).encode()
    send_datagram(rc2udp_server.address, rc2udp_server.port, rawdata)
    assert rc2udp_server.ircserver.wait()
    assert rc2udp_server.ircserver.data == [data]


@pytest.mark.parametrize("data", [b"#nomessage", b"#channel\tinvalid utf8\x80"])
def test_rc2udp_invalid(rc2udp_server, data):
    """Test that invalid RC2UDP are dropped gracefully."""
    rc2udp_server.ircserver.clear()
    send_datagram(rc2udp_server.address, rc2udp_server.port, data)
    assert not rc2udp_server.ircserver.wait()
    assert len(rc2udp_server.ircserver.data) == 0
