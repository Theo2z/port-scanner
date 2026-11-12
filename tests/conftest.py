"""Shared pytest fixtures.

Fixtures are reusable setup functions. A test asks for one by naming it
as a parameter, and pytest runs the setup before the test and the
cleanup (the code after `yield`) afterwards, even if the test fails.

Every network test here talks only to 127.0.0.1, on ports the OS picks
for us (binding to port 0), so tests never clash with real services and
never touch another machine.
"""

from __future__ import annotations

import socket
import threading
from typing import Callable, Iterator

import pytest


@pytest.fixture
def listener() -> Iterator[Callable[[bytes], int]]:
    """Factory: start a local TCP service that sends `greeting` to each client.

    Returns the port number. Pass b"" for a service that stays silent.
    """
    sockets: list[socket.socket] = []

    def start(greeting: bytes = b"") -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))  # port 0 = "any free port"
        srv.listen()
        sockets.append(srv)

        def serve() -> None:
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:  # socket closed during cleanup
                    return
                with conn:
                    if greeting:
                        conn.sendall(greeting)
                    conn.settimeout(1)
                    try:
                        conn.recv(64)  # wait for the client to hang up
                    except OSError:
                        pass

        threading.Thread(target=serve, daemon=True).start()
        return srv.getsockname()[1]

    yield start
    for s in sockets:
        s.close()


@pytest.fixture
def unused_port() -> int:
    """A port with nothing listening (bound briefly to reserve, then freed)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
