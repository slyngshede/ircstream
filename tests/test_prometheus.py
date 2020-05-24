"""Tests for the Prometheus server."""

from __future__ import annotations

import configparser
import http.client
import threading
from typing import Generator

import ircstream

import pytest


@pytest.fixture(name="prometheus_server", scope="module")
def fixture_prometheus_server(config: configparser.ConfigParser) -> Generator[ircstream.PrometheusServer, None, None]:
    """Fixture for an instance of a PrometheusServer.

    This spawns a thread to run the server. It yields the instance.
    """
    server = ircstream.PrometheusServer(config["prometheus"])
    thread = threading.Thread(name="prometheus", target=server.serve_forever)
    thread.start()

    yield server

    server.shutdown()
    thread.join()
    server.server_close()


def test_prometheus_server(prometheus_server: ircstream.PrometheusServer) -> None:
    """Test that the Prometheus server works."""
    conn = http.client.HTTPConnection(prometheus_server.address, prometheus_server.port)
    conn.request("GET", "/metrics")
    response = conn.getresponse()
    assert response.status == 200
