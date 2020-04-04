"""Basic IRC Client implementation, used for testing."""

import queue
import threading

import irc.client  # type: ignore
import irc.connection  # type: ignore


class IRCClientThread(threading.Thread, irc.client.SimpleIRCClient):
    """Basic IRC Client, used for testing.

    This is a subclass of Thread, processing events "asynchronously".

    The IRC implementation is third-party, but as far as this client goes,
    it's pretty dummy: it just shoves incoming events into a queue, and
    provides a method to consume from the queue.
    """

    def __init__(self):
        threading.Thread.__init__(self, name="ircclient", daemon=True)
        irc.client.SimpleIRCClient.__init__(self)
        self.events = queue.SimpleQueue()
        self._shutdown_request = False

    def connect(self, *args, **kwargs):
        """Override the method to add transparent IPv6 support."""
        if args and ":" in args[0]:
            kwargs["connect_factory"] = irc.connection.Factory(ipv6=True)
        super().connect(*args, **kwargs)

    def run(self):
        """Run the thread."""
        while not self._shutdown_request:
            try:
                process_fn = self.reactor.process_once  # pylint: disable=no-member
            except AttributeError:
                # compatibility with older versions
                process_fn = self.ircobj.process_once  # pylint: disable=no-member
            process_fn(0.2)

    def shutdown(self):
        """Shutdown the client.

        Sets a shutdown request signal, that makes the server stop processing
        events. Does not gracefully disconnect for now).
        """
        self._shutdown_request = True

    def _dispatcher(self, _, event: irc.client.Event):
        """Handle callbacks for all events.

        Just shoves incoming events into a simple queue.
        """
        # print(f"{event.type}, source={event.source}, target={event.target}, arguments={event.arguments}")
        self.events.put(event)

    def expect(self, typ: str, timeout=2, **kwargs):
        """Groks events until the expect one is found.

        If the matching event is not found within a timeout, returns None.
        otherwise, the matching event.
        """
        found = None
        while True:  # grok events until the queue is empty
            try:
                # break if no messages have been received for a given timeout
                event = self.events.get(block=True, timeout=timeout)
            except queue.Empty:
                break

            # match the given type + other criteria (source, target, arguments)
            matched = event.type == typ
            for name, value in kwargs.items():
                matched &= getattr(event, name) == value

            if matched:
                found = event
                break
        return found
