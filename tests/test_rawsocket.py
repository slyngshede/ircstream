"""Test our server implementation for exceptional behavior.

Most IRC clients or libraries don't typically allow the flexibility to send
invalid commands, not respond to PING etc., so emulate the IRC protocol
manually, using a raw socket.
"""

import socket
import time
from typing import Sequence

import pytest  # type: ignore


class LineSocket(socket.socket):
    """Light wrapper around a socket."""

    def __init__(self, address: str, port: int) -> None:
        """Initialize the socket *and connect* (this is a bit hacky)."""
        if ":" in address:
            afi = socket.AF_INET6
        else:
            afi = socket.AF_INET
        super().__init__(afi, socket.SOCK_STREAM)
        self.connect((address, port))
        self.settimeout(0.2)

    def readlines(self) -> Sequence[bytes]:
        """Read and return all lines in input, until a timeout occurs."""
        output = b""
        # read all output until timed out
        while True:
            try:
                msg = self.recv(1024)
                if not msg:  # EOF
                    break
            except socket.timeout:
                break
            output += msg
        return output.splitlines()


@pytest.fixture(name="clientsock")
def clientsock_fixture(ircserver) -> LineSocket:
    """Return an instance of our fake/raw IRC client."""
    return LineSocket(ircserver.address, ircserver.port)


def test_premature_close(clientsock):
    """Test the handling of a premature close, right after connecting."""
    clientsock.close()


def test_premature_close2(clientsock):
    """Test the handling of a premature close, with the send buffer full."""
    clientsock.sendall(b"NICK nick\n")
    clientsock.sendall(b"USER one two three four\n")
    # close before we recv() on the socket, thus when the server is blocked on send()
    clientsock.close()


@pytest.mark.usefixtures("ircserver")
def test_ping_timeout(ircserver, clientsock):
    """Test a PING timeout condition."""
    # save the old timeout
    default_timeout = ircserver.client_timeout

    # set timeout to a (much) smaller value, to avoid long waits while testing
    ircserver.client_timeout = 1

    # connect
    clientsock = LineSocket(ircserver.address, ircserver.port)

    # wait at least until the ping timeout interval
    time.sleep(ircserver.client_timeout)

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

    # restore it to the default value
    ircserver.client_timeout = default_timeout


def test_preregister_command(clientsock):
    """Test sending a command that is not valid before registration."""
    clientsock.sendall(b"WHOIS noone\n")
    data = clientsock.readlines()
    assert len(data) == 1
    assert b"451 * :You have not registered" in data[0]


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
    clientsock.sendall(b"USER one two three four redundant\n")
    clientsock.sendall(b"NICK nick\n")
    data = clientsock.readlines()
    assert any([b"001 nick" in response for response in data])

    # two arguments for WHOIS
    clientsock.sendall(b"WHOIS nick second\n")
    data = clientsock.readlines()
    assert any([b"401 nick second :No such nick/channel" in response for response in data])
