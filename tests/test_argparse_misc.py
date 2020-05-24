"""Argument parse tests."""

from __future__ import annotations

import json
import pathlib
from typing import Any
from unittest.mock import Mock

import ircstream

import pytest

import structlog


def test_parse_args_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Test whether --help returns usage and exits."""
    with pytest.raises(SystemExit) as exc:
        ircstream.parse_args(["--help"])

    assert exc.value.code == 0
    out, _ = capsys.readouterr()
    assert "usage: " in out


def test_configure_logging_plain(caplog: pytest.LogCaptureFixture) -> None:
    """Test that the plain logging configuration works."""
    ircstream.configure_logging("plain")
    log = structlog.get_logger("testlogger")
    caplog.clear()
    log.warn("this is a test log")
    assert ["this is a test log"] == [rec.message for rec in caplog.records]


def test_configure_logging_console(caplog: pytest.LogCaptureFixture) -> None:
    """Test that the console logging configuration works."""
    ircstream.configure_logging("plain")  # needed to override the default noop config in testing
    ircstream.configure_logging("console")
    log = structlog.get_logger("testlogger")
    caplog.clear()
    log.warn("this is a test log")
    assert ["[warning  ] this is a test log"] == [rec.message for rec in caplog.records]


def test_configure_logging_json(caplog: pytest.LogCaptureFixture) -> None:
    """Test that the json logging configuration works."""
    ircstream.configure_logging("json")
    log = structlog.get_logger("testlogger")
    caplog.clear()
    log.warn("this is a json log", key="value")

    parsed_logs = [json.loads(rec.message) for rec in caplog.records]
    assert ["this is a json log"] == [rec["event"] for rec in parsed_logs]
    assert ["value"] == [rec["key"] for rec in parsed_logs]


def test_configure_logging_invalid() -> None:
    """Test that an invalid logging configuration does not work."""
    with pytest.raises(ValueError):
        ircstream.configure_logging("invalid")


def test_main(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture) -> None:
    """Test the main/entry point function."""
    tmp_config = tmp_path / "ircstream-regular.conf"
    tmp_config.write_text(
        """
        [irc]
        [rc2udp]
        """
    )
    args = ("--config", str(tmp_config))

    # regular start; ensure that at least the IRC server is being run

    # replace with AsyncMock when Python >= 3.8
    mocked_serve_sync = Mock()

    async def mocked_serve(self: Any) -> None:
        mocked_serve_sync(type(self))

    monkeypatch.setattr(ircstream.IRCServer, "serve", mocked_serve)
    monkeypatch.setattr(ircstream.RC2UDPServer, "serve", mocked_serve)
    ircstream.main((args))

    mocked_serve_sync.assert_any_call(ircstream.IRCServer)
    mocked_serve_sync.assert_any_call(ircstream.RC2UDPServer)

    # ensure the Ctrl+C handler works and does not raise any exceptions
    mocked_serve_keyboardinterrupt_sync = Mock(side_effect=KeyboardInterrupt)

    async def mocked_serve_keyboardinterrupt(_: Any) -> None:
        mocked_serve_keyboardinterrupt_sync()

    monkeypatch.setattr(ircstream.IRCServer, "serve", mocked_serve_keyboardinterrupt)
    ircstream.main((args))  # does not raise an exception

    # ensure that OS errors (e.g. if the socket is bound already) are handled
    mocked_serve_socket_sync = Mock(side_effect=OSError(98, "Address already in use"))

    async def mocked_serve_socket(_: Any) -> None:
        mocked_serve_socket_sync()

    monkeypatch.setattr(ircstream.IRCServer, "serve", mocked_serve_socket)
    caplog.clear()

    with pytest.raises(SystemExit) as exc:
        ircstream.main((args))

    assert exc.value.code < 0
    assert "Address already in use" in caplog.records[-1].message


def test_main_config_nonexistent(caplog: pytest.LogCaptureFixture) -> None:
    """Test with non-existing configuration."""
    args = ("--config", "/nonexistent")

    caplog.clear()
    with pytest.raises(SystemExit) as exc:
        ircstream.main((args))

    assert exc.value.code < 0
    assert "No such file or directory" in caplog.records[-1].message


@pytest.mark.parametrize("test_config", ["[rc2udp]\n[prometheus]\n", "invalid config"])
def test_main_config_invalid(
    tmp_path: pathlib.Path,
    caplog: pytest.LogCaptureFixture,
    test_config: str,
) -> None:
    """Test the main/entry point function (without an IRC config)."""
    tmp_config = tmp_path / "ircstream-invalid.conf"
    tmp_config.write_text(test_config)
    args = ("--config", str(tmp_config))

    caplog.clear()
    with pytest.raises(SystemExit) as exc:
        ircstream.main((args))

    assert exc.value.code < 0
    assert "Invalid configuration" in caplog.records[-1].message


def test_main_section_no_optional(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the main/entry point function (without optional config)."""
    tmp_config = tmp_path / "ircstream-nooptional.conf"
    tmp_config.write_text(
        """
        [irc]
        """
    )
    args = ("--config", str(tmp_config))

    # ensure that the IRC server and only the IRC server is being run

    # replace with AsyncMock when Python >= 3.8
    mocked_serve_sync = Mock()

    async def mocked_serve(self: Any) -> None:
        mocked_serve_sync(type(self))

    monkeypatch.setattr(ircstream.IRCServer, "serve", mocked_serve)
    monkeypatch.setattr(ircstream.RC2UDPServer, "serve", mocked_serve)
    ircstream.main((args))

    mocked_serve_sync.assert_any_call(ircstream.IRCServer)
    with pytest.raises(AssertionError):
        mocked_serve_sync.assert_any_call(ircstream.RC2UDPServer)
