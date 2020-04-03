"""Test our server implementation using irctk."""

import subprocess

import pytest  # type: ignore


def test_irctk(ircserver) -> None:
    """Test a simple conversation using irctk."""
    hostport = f"{ircserver.address}:{ircserver.port}"
    if ircserver.address == "::":
        # irctk does not support IPv6, assume IPv4 localhost
        hostport = f"127.0.0.1:{ircserver.port}"
    elif ":" in ircserver.address:
        pytest.skip("irctk does not support IPv6")

    try:
        miscargs = "--event-to-message --interval=0 --interval-end=1".split()
        proc = subprocess.Popen(
            ["irctk", *miscargs, hostport],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="ascii",
        )
    except FileNotFoundError:
        pytest.skip("irctk not found")

    # help typing realize these are not None
    assert proc.stdin is not None and proc.stdout is not None

    # be careful of interprocess deadlocks!
    def comm(msg: str) -> str:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(msg + "\n")
        proc.stdin.flush()
        return proc.stdout.readline().strip()

    assert comm("/join #channel") == "irctk: Cannot join #channel: no such channel."

    ircserver.broadcast("#channel", "create the channel")
    assert comm("/join #channel") == "[#channel] -!- irctk has joined #channel"

    ircserver.broadcast("#channel", "a message")
    assert proc.stdout.readline().strip() == f"[#channel] <{ircserver.botname}> a message"

    assert comm("/quit bye") == "irctk: [error] Error from server: Closing Link: (Quit: bye)"

    proc.stdin.close()
    proc.kill()
