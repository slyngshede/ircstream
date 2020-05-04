"""Tests for the Prometheus server."""

import http.client

import ircstream

import pytest  # type: ignore

from .conftest import start_server_in_thread


@pytest.fixture(name="prometheus_server", scope="module")
def fixture_prometheus_server(config):
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
