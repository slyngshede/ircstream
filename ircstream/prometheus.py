"""Prometheus instrumentation component.

Responsible for spawning an HTTP server to expose various application-level
metrics on a Prometheus/OpenMetrics-compatible /metrics endpoint.

Note that there is a terminology clash: Prometheus calls this a "client", and
the Python module is called "prometheus_client", but this is definitely an HTTP
server, and as such we call the class here PrometheusServer.
"""

# SPDX-FileCopyrightText: Faidon Liambotis
# SPDX-FileCopyrightText: Wikimedia Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import configparser
import http.server
import socket

import prometheus_client
import structlog


class PrometheusServer(http.server.ThreadingHTTPServer):
    """A Prometheus HTTP server."""

    log = structlog.get_logger("ircstream.prometheus")
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        config: configparser.SectionProxy,
        registry: prometheus_client.CollectorRegistry = prometheus_client.REGISTRY,
    ) -> None:
        listen_address = config.get("listen_address", fallback="::")
        if ":" in listen_address:
            self.address_family = socket.AF_INET6
        listen_port = config.getint("listen_port", fallback=9200)
        super().__init__((listen_address, listen_port), prometheus_client.MetricsHandler.factory(registry))
        # update address/port based on what bind() returned
        self.address, self.port = str(self.server_address[0]), self.server_address[1]
        self.log.info("Listening for Prometheus HTTP", listen_address=self.address, listen_port=self.port)

    def server_bind(self) -> None:
        """Bind to an IP address.

        Override to set an opt to listen to both IPv4/IPv6 on the same socket.
        """
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
