"""Shared pytest configuration: no test may use the network."""

import socket

import pytest
from helpers import NetworkAccessBlocked


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every attempt to open a network connection fail, in every test.

    The error is not an ``OSError``, so the download retries never treat it as
    a network glitch: the test fails at once.
    """

    def blocked(*args: object, **kwargs: object) -> None:
        raise NetworkAccessBlocked("tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
