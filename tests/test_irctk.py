"""Test our server implementation using irctk."""

from __future__ import annotations

import asyncio

import ircstream

import pytest


@pytest.mark.asyncio
async def test_irctk(ircserver: ircstream.IRCServer) -> None:
    """Test a simple conversation using irctk."""
    hostport = f"{ircserver.address}:{ircserver.port}"
    if ircserver.address == "::":
        # irctk does not support IPv6, assume IPv4 localhost
        hostport = f"127.0.0.1:{ircserver.port}"
    elif ":" in ircserver.address:
        pytest.skip("irctk does not support IPv6")

    try:
        miscargs = "--event-to-message --interval=0 --interval-end=1".split()
        proc = await asyncio.create_subprocess_exec(
            "irctk",
            *miscargs,
            hostport,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError:
        pytest.skip("irctk not found")

    # help typing realize these are not None
    assert proc.stdin is not None and proc.stdout is not None

    # be careful of interprocess deadlocks!
    async def comm(msg: str) -> str:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(msg.encode("ascii") + b"\n")
        return (await proc.stdout.readline()).strip().decode("ascii")

    assert await comm("/join #channel") == "irctk: Cannot join #channel: no such channel."

    await ircserver.broadcast("#channel", "create the channel")
    assert await comm("/join #channel") == "[#channel] -!- irctk has joined #channel"

    await ircserver.broadcast("#channel", "a message")
    assert (await proc.stdout.readline()).strip().decode("ascii") == f"[#channel] <{ircserver.botname}> a message"

    assert await comm("/quit bye") == "irctk: [error] Error from server: Closing Link: (Quit: bye)"

    proc.stdin.close()

    try:
        proc.kill()
    except ProcessLookupError:
        pass
