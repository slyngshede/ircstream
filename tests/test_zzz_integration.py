"""Test as much of the functionality as possible at a high-level."""

import http.client
import multiprocessing
import multiprocessing.synchronize
import socket
import threading
import time

import irc.client  # type: ignore
import irc.connection  # type: ignore

import ircstream

import prometheus_client  # type: ignore

import pytest  # type: ignore


SERVER_IP = "127.0.0.1"
PORTS = {
    "irc": 6667,
    "rc2udp": 9390,
    "prometheus": 9200,
}


class IRCMessageCounter(irc.client.SimpleIRCClient):
    """Basic IRC Client, used for counting received messages.

    This connects, identifies, joins a channel, and then counts incoming events
    into a multiprocessing Value. It's used for testing, and verifying the
    right number of messages were received.
    """

    def __init__(self, channel: str, received: multiprocessing.Value, ready: multiprocessing.synchronize.Event) -> None:
        self.channel = channel
        self.ready = ready
        self.received = received
        super().__init__()

    def connect(self, *args, **kwargs):
        """Override the method to add transparent IPv6 support."""
        if args and ":" in args[0]:
            kwargs["connect_factory"] = irc.connection.Factory(ipv6=True)
        super().connect(*args, **kwargs)

    def on_welcome(self, connection, _):
        """Join the channel immediately after identifying."""
        connection.join(self.channel)

    def on_join(self, _, __):
        """Set the ready event after a channel was joined."""
        self.ready.set()

    def on_pubmsg(self, _, __):
        """Increase the received counter after a message was received."""
        with self.received.get_lock():
            self.received.value += 1


@pytest.fixture(name="main")
def fixture_main():
    """Fixture for ircstream.main, running it in a thread."""
    # hack: cleanup prometheus_client's registry, to avoid Duplicated timeseries messages when reusing
    prometheus_client.REGISTRY.__init__()

    args = ("--config", "ircstream.conf")  # stock config, listens to 6667 etc.
    main = threading.Thread(target=ircstream.main, args=(args,), daemon=True)
    main.start()
    time.sleep(0.1)
    if not main.is_alive():
        pytest.skip("Main thread died, likely cannot bind to default ports; skipping test")
    yield main


def prometheus_metric(metric: str) -> float:
    """Fetch a Prometheus metrics from the wire.

    This fetches from Prometheus on every call!
    """
    conn = http.client.HTTPConnection(SERVER_IP, PORTS["prometheus"])
    conn.request("GET", "/metrics")
    response = conn.getresponse()
    assert response.status == 200

    content = response.read().decode().splitlines()
    for line in content:
        if line.startswith("#"):
            continue
        key, value = line.split(" ", maxsplit=1)

        if key == metric:
            return float(value)
    return 0.0


def spawn_client_process(channel: str, counter: multiprocessing.Value) -> multiprocessing.Process:
    """Spawn an IRC message counter client into a separate process."""
    ready_to_receive = multiprocessing.Event()

    def spawn_client():
        ircclient = IRCMessageCounter(channel, counter, ready_to_receive)
        ircclient.connect(SERVER_IP, PORTS["irc"], "rc-bot")
        ircclient.start()

    ircclient_process = multiprocessing.Process(target=spawn_client)
    ircclient_process.start()
    ready_to_receive.wait()
    return ircclient_process


def send_to_rc2udp(channel: str, count: int, message: str = "message") -> None:
    """Send one or multiple messages RC2UDP.

    Runs into a separate process just in case, but waits until the process is
    finished before returning.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rawdata = f"{channel}\t{message}".encode()

    def send_in_process():
        for _ in range(0, count):
            sock.sendto(rawdata, (SERVER_IP, PORTS["rc2udp"]))

    proc = multiprocessing.Process(target=send_in_process)
    proc.start()
    proc.join()


@pytest.mark.usefixtures("main")
def test_out_of_the_box():
    """Tests the out-of-the-box experience of the server.

    Tests the server with multiple clients and multiple messages being passed
    to all of them, verifying that they were received, and with the right
    metrics recorded in Prometheus.
    """
    client_count = 10
    message_count = 50
    received_counter = multiprocessing.Value("h")

    # send one message, to create the channel
    assert prometheus_metric("ircstream_channels") == 0
    send_to_rc2udp("#channel", 1)
    assert prometheus_metric("ircstream_channels") == 1

    # connect a number of different clients
    assert prometheus_metric("ircstream_clients") == 0
    ircclients = []
    for _ in range(0, client_count):
        ircclient = spawn_client_process("#channel", received_counter)
        ircclients.append(ircclient)
    assert prometheus_metric("ircstream_clients") == float(client_count)

    # send a burst of RC2UDP messages and wait a bit to make sure they're processed
    send_to_rc2udp("#channel", message_count)
    time.sleep(message_count * 0.01)  # 10ms per message ought to be enough

    # verify whether they were sent by the server
    messages_total = message_count + 1  # +1 for the channel creation
    assert prometheus_metric("ircstream_messages_total") == float(messages_total)

    # verify whether they were received by the clients
    assert received_counter.value == client_count * message_count

    # check again to verify no new channels were created and no clients were dropped
    assert prometheus_metric("ircstream_clients") == float(client_count)
    assert prometheus_metric("ircstream_channels") == 1

    # terminate all the clients (abruptly)
    for ircclient in ircclients:
        ircclient.terminate()
    time.sleep(0.1)

    # verify a) client count dropped to zero b) the channel did not disappear
    assert prometheus_metric("ircstream_clients") == 0
    assert prometheus_metric("ircstream_channels") == 1
