"""Argument parse tests."""

import ircstream

import pytest  # type: ignore


def test_parse_args_help(capsys):
    """Test whether --help returns usage and exits."""
    with pytest.raises(SystemExit) as exc:
        ircstream.parse_args(["--help"])

    out, _ = capsys.readouterr()
    assert exc.value.code == 0
    assert "usage: " in out


def test_config_nonexistent(capsys):
    """Test with non-existing configuration directories."""
    not_a_file = "/nonexistent"
    with pytest.raises(SystemExit) as exc:
        ircstream.parse_args(["--config-file", not_a_file])

    _, err = capsys.readouterr()
    assert exc.value.code == 2
    assert "No such file or directory" in err
