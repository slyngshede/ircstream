"""Test the validity of our IRCMessage parser/builder."""

from pathlib import Path

from ircstream import IRCMessage

import yaml

TEST_DATA_DIR = Path("tests") / Path("data")


def pytest_generate_tests(metafunc):
    """Generate test data fixtures from irc-parser-tests YAML files.

    Load the YAML files from the irc-parser-tests project, and create one
    fixture for each of the tests in there, to avoid lumping all of them
    together in one big test.
    """
    fixtures = {
        "data_msg_split": "msg-split.yaml",
        "data_msg_join": "msg-join.yaml",
    }

    for fixture, filename in fixtures.items():
        filename = TEST_DATA_DIR / Path(filename)
        if fixture in metafunc.fixturenames:
            yamldata = yaml.safe_load(open(filename).read())
            metafunc.parametrize(fixture, yamldata["tests"])


def test_msg_split(data_msg_split):
    """Test an msg-split test fixture.

    Parse a raw, wire protocol message, and check whether all of the
    deconstructed atoms (verb, params, source) are how they should be.
    """
    raw = data_msg_split["input"]
    atoms = data_msg_split["atoms"]
    parsed = IRCMessage.from_message(raw)

    if "tags" in atoms:
        return  # tags not supported here

    if "verb" in atoms:
        assert parsed.command.lower() == atoms["verb"].lower()
    else:
        assert parsed.command == ""

    if "params" in atoms:
        atom_params = list(atoms["params"])
        assert len(atom_params) > 0

        for param in parsed.params:
            assert param == atom_params.pop(0)
    else:
        assert len(parsed.params) == 0

    if "source" in atoms:
        assert parsed.source == atoms["source"]
    else:
        assert parsed.source is None


def test_msg_join(data_msg_join):
    """Test an msg-join test fixture.

    Take the individual atoms, build a wire protocol message and check whether
    it matches at least one of the expected results.
    """
    atoms = data_msg_join["atoms"]
    matches = data_msg_join["matches"]

    if "tags" in atoms:
        return  # tags not supported here

    constructed = IRCMessage(atoms["verb"], atoms.get("params"), atoms.get("source"))
    assert str(constructed) in matches
