"""Test the IRCNumeric class, including RPL and ERR."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Set

from ircstream import ERR, RPL

import yaml

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader  # type: ignore

TEST_NUMERICS_YAML = Path("tests") / Path("data") / "numerics.yaml"


def test_numeric() -> None:
    """Test RPL and ERR (and their base class, IRCNumeric) against irc-defs.

    This checks that the names and values match the one from
    https://github.com/ircdocs/irc-defs/

    Our list is not exhaustive, nor it tries to be, so we only check that our
    definitions are valid, and not that we have the complete list.
    """
    # build a name->(numeric, numeric, ...) dictionary, e.g. RPL_WELCOME -> (001,)
    with TEST_NUMERICS_YAML.open(encoding="utf-8") as yamlfile:
        yamldata = yaml.load(yamlfile.read(), Loader=SafeLoader)
    numerics: Dict[str, Set[str]] = {}
    for value in yamldata["values"]:
        # numerics are not necessarily unique and vary by implementation.
        # e.g. RPL_WHOISHOST is both 378 and 616, and 378 can also be RPL_BANEXPIRED
        #
        # collect the set of all those values.
        name, numeric = value["name"], value["numeric"]
        if name not in numerics:
            numerics[name] = {numeric}
        else:
            numerics[name].add(numeric)

    for value in (*RPL, *ERR):
        assert str(value) in numerics[repr(value)]
