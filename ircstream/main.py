"""Command-line executable component.

Responsible for parsing the command-line arguments, the configuration file, and
conditionally running servers imported from other components. Spaws the main
event loop.

Provides a run() function, used by __main__ or directly.
"""

# SPDX-FileCopyrightText: Faidon Liambotis
# SPDX-FileCopyrightText: Wikimedia Foundation
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import asyncio
import configparser
import errno
import logging
import pathlib
import sys
from collections.abc import Sequence

import structlog

from ._version import __version__
from .ircserver import IRCServer
from .prometheus import PrometheusServer
from .rc2udp import RC2UDPServer

logger = structlog.get_logger()

# holder for strong references to pending tasks; remove when the minimum CPython version is one with PR#121264
background_tasks = set()


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse and return the parsed command line arguments."""
    parser = argparse.ArgumentParser(
        prog="ircstream",
        description="MediaWiki RecentChanges → IRC gateway",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    cfg_dflt = pathlib.Path("ircstream.conf")
    if not cfg_dflt.exists():
        cfg_dflt = pathlib.Path("/etc/ircstream.conf")
    parser.add_argument("--config-file", "-c", type=pathlib.Path, default=cfg_dflt, help="Path to configuration file")

    log_levels = ("DEBUG", "INFO", "WARNING", "ERROR")  # no public method to get a list from logging :(
    parser.add_argument("--log-level", default="INFO", choices=log_levels, type=str.upper, help="Log level")
    log_formats = ("plain", "console", "json")
    log_dflt = "console" if sys.stdout.isatty() else "plain"
    parser.add_argument("--log-format", default=log_dflt, choices=log_formats, help="Log format")
    return parser.parse_args(argv)


def configure_logging(log_format: str = "plain") -> None:
    """Configure logging parameters."""
    logging.basicConfig(format="%(message)s", level=logging.WARNING)

    processors: list[structlog.types.Processor] = [
        structlog.stdlib.filter_by_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if log_format == "plain":
        processors += [structlog.dev.ConsoleRenderer(colors=False)]
    elif log_format == "console":
        # >= 20.2.0 has this in the default config
        processors = [structlog.stdlib.add_log_level] + structlog.get_config()["processors"]
    elif log_format == "json":
        processors += [
            structlog.stdlib.add_logger_name,  # adds a "logger" key
            structlog.stdlib.add_log_level,  # adds a "level" key (string, not int)
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(sort_keys=True),
        ]
    else:
        raise ValueError(f"Invalid logging format specified: {log_format}")

    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
    )


async def start_servers(config: configparser.ConfigParser) -> None:
    """Start all servers in asyncio tasks or threads and then busy-loop."""
    loop = asyncio.get_running_loop()

    try:
        if "irc" in config:
            ircserver = IRCServer(config["irc"])
            irc_coro = ircserver.serve()
            irc_task = asyncio.create_task(irc_coro)
            background_tasks.add(irc_task)
            irc_task.add_done_callback(background_tasks.discard)
        else:
            logger.critical('Invalid configuration, missing section "irc"')
            raise SystemExit(-1)

        if "rc2udp" in config:
            rc2udp_coro = RC2UDPServer(config["rc2udp"], ircserver).serve()
            rc2udp_task = asyncio.create_task(rc2udp_coro)
            background_tasks.add(rc2udp_task)
            rc2udp_task.add_done_callback(background_tasks.discard)
        else:
            logger.warning("RC2UDP is not enabled in the config; server usefulness may be limited")

        if "prometheus" in config:
            prom_server = PrometheusServer(config["prometheus"], ircserver.metrics_registry)
            prom_server.socket.setblocking(False)
            loop.add_reader(prom_server.socket, prom_server.handle_request)

        await asyncio.wait_for(irc_task, timeout=None)  # run forever
    except OSError as exc:
        logger.critical(f"System error: {exc.strerror}", errno=errno.errorcode[exc.errno])
        raise SystemExit(-2) from exc


def run(argv: Sequence[str] | None = None) -> None:
    """Entry point."""
    options = parse_args(argv)

    configure_logging(options.log_format)
    # only set e.g. INFO or DEBUG for our own loggers
    structlog.get_logger("ircstream").setLevel(options.log_level)
    logger.info("Starting IRCStream", config_file=str(options.config_file), version=__version__)

    config = configparser.ConfigParser(strict=True)
    try:
        with options.config_file.open(encoding="utf-8") as config_fh:
            config.read_file(config_fh)
    except OSError as exc:
        logger.critical(f"Cannot open configuration file: {exc.strerror}", errno=errno.errorcode[exc.errno])
        raise SystemExit(-1) from exc
    except configparser.Error as exc:
        msg = repr(exc).replace("\n", " ")  # configparser exceptions sometimes include newlines
        logger.critical(f"Invalid configuration, {msg}")
        raise SystemExit(-1) from exc

    try:
        asyncio.run(start_servers(config))
    except KeyboardInterrupt:
        pass
