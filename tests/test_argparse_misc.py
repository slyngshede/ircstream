"""Argument parse tests."""

from __future__ import annotations

import json
import pathlib
from unittest.mock import patch

import ircstream

import pytest

import structlog


def test_parse_args_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Test whether --help returns usage and exits."""
    with pytest.raises(SystemExit) as exc:
        ircstream.parse_args(["--help"])

    exit_status = int(exc.value.code) if exc.value.code is not None else 0
    assert exit_status == 0
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


def test_main(tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture) -> None:
    """Test the main/entry point function."""
    tmp_config = tmp_path / "ircstream-regular.conf"
    tmp_config.write_text(
        """
        [irc]
        [rc2udp]
        """
    )
    args = ("--config", str(tmp_config))

    # regular start; ensure that the intended servers are being run
    with patch.object(ircstream.IRCServer, "serve", autospec=True) as mocked_irc_serve:
        with patch.object(ircstream.RC2UDPServer, "serve", autospec=True) as mocked_rc2udp_serve:
            ircstream.main(args)
            mocked_irc_serve.assert_awaited()
            mocked_rc2udp_serve.assert_awaited()

    # ensure the Ctrl+C handler works and does not raise any exceptions
    with patch.object(ircstream.IRCServer, "serve", side_effect=KeyboardInterrupt):
        ircstream.main(args)  # does not raise an exception

    # ensure that OS errors (e.g. if the socket is bound already) are handled
    with patch.object(ircstream.IRCServer, "serve", side_effect=OSError(98, "Address already in use")):
        caplog.clear()
        with pytest.raises(SystemExit) as exc:
            ircstream.main(args)  # does not raise an exception

        exit_status = int(exc.value.code) if exc.value.code is not None else 0

        assert exit_status < 0
        assert "Address already in use" in caplog.records[-1].message


def test_main_config_nonexistent(caplog: pytest.LogCaptureFixture) -> None:
    """Test with non-existing configuration."""
    args = ("--config", "/nonexistent")

    caplog.clear()
    with pytest.raises(SystemExit) as exc:
        ircstream.main(args)

    exit_status = int(exc.value.code) if exc.value.code is not None else 0
    assert exit_status < 0
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
        ircstream.main(args)

    exit_status = int(exc.value.code) if exc.value.code is not None else 0
    assert exit_status < 0
    assert "Invalid configuration" in caplog.records[-1].message


def test_main_section_no_optional(tmp_path: pathlib.Path) -> None:
    """Test the main/entry point function (without optional config)."""
    tmp_config = tmp_path / "ircstream-nooptional.conf"
    tmp_config.write_text(
        """
        [irc]
        """
    )
    args = ("--config", str(tmp_config))

    with patch.object(ircstream.IRCServer, "serve", autospec=True) as mocked_irc_serve:
        with patch.object(ircstream.RC2UDPServer, "serve", autospec=True) as mocked_rc2udp_serve:
            ircstream.main(args)
            mocked_irc_serve.assert_awaited()
            mocked_rc2udp_serve.assert_not_awaited()
