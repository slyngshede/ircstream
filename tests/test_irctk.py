"""Test our server implementation using irctk."""

import subprocess

import pytest  # type: ignore

from .test_server import ircserver_instance, ircconfig_instance, log_fixture


@pytest.mark.usefixtures("ircserver")
def test_irctk(ircserver) -> None:
    """Test a simple conversation using irctk."""
    hostport = f"{ircserver.address}:{ircserver.port}"
    try:
        proc = subprocess.Popen(
            ["irctk", "-m", hostport],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="ascii",
        )
    except FileNotFoundError:
        pytest.skip("irctk not found")

    # be careful of interprocess deadlocks!
    def comm(msg: str) -> str:
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
