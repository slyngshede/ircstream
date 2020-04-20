"""Test our server implementation for exceptional behavior.

Most IRC clients or libraries don't typically allow the flexibility to send
invalid commands, not respond to PING etc., so emulate the IRC protocol
manually, using a raw socket.
"""

import socket
import time
from typing import Sequence

import pytest  # type: ignore


class BareClient:  # pylint: disable=too-few-public-methods
    """Bare client around socket operations to support a line-based protocol."""

    def __init__(self, address: str, port: int) -> None:
        """Initialize the socket *and connect*."""
        self.sock = socket.create_connection((address, port), 0.2)
        self.close = self.sock.close
        self.sendall = self.sock.sendall

    def readlines(self) -> Sequence[bytes]:
        """Read and return all lines in input, until a timeout occurs."""
        output = b""
        # read all output until timed out
        while True:
            try:
                msg = self.sock.recv(1024)
                if not msg:  # EOF
                    break
            except socket.timeout:
                break
            output += msg
        return output.splitlines()


@pytest.fixture(name="clientsock")
def clientsock_fixture(ircserver) -> BareClient:
    """Return an instance of our fake/raw IRC client."""
    return BareClient(ircserver.address, ircserver.port)


def test_premature_close(clientsock):
    """Test the handling of a premature close, right after connecting."""
    clientsock.close()


def test_premature_close2(clientsock):
    """Test the handling of a premature close, with the send buffer full."""
    clientsock.sendall(b"NICK nick\n")
    clientsock.sendall(b"USER one two three four\n")
    # close before we recv() on the socket, thus when the server is blocked on send()
    clientsock.close()


@pytest.fixture(name="ircserver_short_timeout")
def fixture_ircserver_short_timeout(ircserver):
    """Return an IRCServer modified to run with a very short timeout.

    This is a separate fixture to make sure that the default value is restored
    e.g. if the test fails.
    """
    # save the old timeout
    default_timeout = ircserver.client_timeout
    # set timeout to a (much) smaller value, to avoid long waits while testing
    ircserver.client_timeout = 1

    yield ircserver

    # restore it to the default value
    ircserver.client_timeout = default_timeout


def test_ping_timeout(ircserver_short_timeout, clientsock):
    """Test a PING timeout condition."""
    # wait at least until the ping timeout interval
    time.sleep(ircserver_short_timeout.client_timeout)

    # try another 5 times for a total of another interval
    ping_timedout = False
    for _ in range(0, 5):
        data = clientsock.readlines()
        if not data:
            continue
        elif b"ERROR :Closing Link: (Ping timeout)" in data[0]:
            ping_timedout = True
            break
        else:
            assert False  # another unexpected message

    assert ping_timedout


def test_preregister_command(clientsock):
    """Test sending a command that is not valid before registration."""
    clientsock.sendall(b"WHOIS noone\n")
    data = clientsock.readlines()
    assert len(data) == 1
    assert b"451 * :You have not registered" in data[0]


def test_erroneous(clientsock):
    """Test erroneous parameters."""
    clientsock.sendall(b"USER one two three four\n")

    clientsock.sendall(b"NICK /invalid\n")
    data = clientsock.readlines()
    assert any([b"432 *" in response for response in data])

    clientsock.sendall(b"NICK " + b"a" * 100 + b"\n")
    data = clientsock.readlines()
    assert any([b"432 *" in response for response in data])

    clientsock.sendall(b":NOCOMMAND\n")
    data = clientsock.readlines()
    assert data == []


def test_unicodeerror(ircserver, clientsock):
    """Test for UnicodeError handling in both directions."""
    clientsock.sendall(b"USER one two three four\n")
    clientsock.sendall(b"NICK nick\n")
    data = clientsock.readlines()
    assert any([b"001 nick" in response for response in data])

    clientsock.sendall(b"WHOIS \x80\n")  # 0x80 is invalid unicode
    data = clientsock.readlines()
    assert data == []

    ircserver.broadcast("#channel", "create the channel")
    clientsock.sendall(b"JOIN #channel\n")
    data = clientsock.readlines()
    assert any([b"JOIN #channel" in response for response in data])

    # this creates a string that will fail .encode("utf8")
    unencodeable_utf8 = "unencodeable " + b"\x80".decode("utf8", "surrogateescape")
    ircserver.broadcast("#channel", unencodeable_utf8)
    data = clientsock.readlines()
    assert data == []


def test_redundant(clientsock):
    """Test redundant parameters in commands that allow it."""
    # five arguments for USER
    clientsock.sendall(b"PASS password\n")
    clientsock.sendall(b"USER one two three four redundant\n")
    clientsock.sendall(b"NICK nick\n")
    data = clientsock.readlines()
    assert any([b"001 nick" in response for response in data])

    clientsock.sendall(b"PASS password\n")
    data = clientsock.readlines()
    assert any([b"462 nick :You may not reregister" in response for response in data])

    # two arguments for WHOIS
    clientsock.sendall(b"WHOIS nick second\n")
    data = clientsock.readlines()
    assert any([b"401 nick second :No such nick/channel" in response for response in data])
