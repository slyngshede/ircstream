"""Tests for the Prometheus server."""

from __future__ import annotations

import configparser
import http.client
from typing import Generator

import ircstream

import pytest

from .conftest import start_server_in_thread


@pytest.fixture(name="prometheus_server", scope="module")
def fixture_prometheus_server(config: configparser.ConfigParser) -> Generator[ircstream.PrometheusServer, None, None]:
    """Fixture for an instance of a PrometheusServer.

    This spawns a thread to run the server. It yields the instance.
    """
    yield from start_server_in_thread(ircstream.PrometheusServer, config["prometheus"])


def test_prometheus_server(prometheus_server: ircstream.PrometheusServer) -> None:
    """Test that the Prometheus server works."""
    conn = http.client.HTTPConnection(prometheus_server.address, prometheus_server.port)
    conn.request("GET", "/metrics")
    response = conn.getresponse()
    assert response.status == 200
