"""Transient network failures: recognising them, and waiting them out.

Both incident families in the batch logs were the machine, not AWS: SSO's federation
endpoint unreachable for twenty cells in a row (six-model-awareness-v1), and a DNS lookup
failing inside ``terraform destroy`` so the seed was left behind and the account marked
dirty (consult-0-gpt-v2, 2026-09-18). Neither says anything about the agent or the
account, so neither should cost a verdict or an account. A cell that hits one waits for
the network and goes again; a teardown that hits one is retried before a leak is declared.
"""

from __future__ import annotations

import socket
import time
from typing import Callable

TRANSIENT_MARKERS: tuple[str, ...] = (
    "no such host",
    "could not connect to the endpoint url",
    "endpointconnectionerror",
    "connecttimeouterror",
    "readtimeouterror",
    "dial tcp",
    "tls handshake timeout",
    "connection reset by peer",
    "i/o timeout",
    "temporary failure in name resolution",
    "name or service not known",
    "network is unreachable",
    "nodename nor servname provided",
    "failed to connect to",
    "lookup .* on .*: server misbehaving",
)

PROBE_HOST = "sts.amazonaws.com"
PROBE_PORT = 443


def is_transient_network_error(text: str | BaseException | None) -> bool:
    """Whether an error message describes the network being away rather than a refusal."""
    if text is None:
        return False
    lowered = str(text).lower()
    if not lowered:
        return False
    for marker in TRANSIENT_MARKERS:
        if ".*" in marker:
            import re
            if re.search(marker, lowered):
                return True
        elif marker in lowered:
            return True
    return False


def network_up(host: str = PROBE_HOST, port: int = PROBE_PORT, timeout: float = 5.0) -> bool:
    """A DNS lookup and a TCP connect to an AWS endpoint: what terraform and boto need."""
    try:
        for family, kind, proto, _, addr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            with socket.socket(family, kind, proto) as sock:
                sock.settimeout(timeout)
                sock.connect(addr)
                return True
    except OSError:
        return False
    return False


def wait_for_network(*, timeout_s: float = 1800.0, poll_s: float = 30.0,
                     log: Callable[[str], None] | None = None,
                     probe: Callable[[], bool] = network_up,
                     sleep: Callable[[float], None] = time.sleep) -> bool:
    """Block until the network answers or ``timeout_s`` passes. Returns whether it came back."""
    deadline = time.monotonic() + timeout_s
    waited = 0.0
    while True:
        if probe():
            if log and waited:
                log(f"network back after {waited:.0f}s")
            return True
        if time.monotonic() >= deadline:
            if log:
                log(f"network still unreachable after {timeout_s:.0f}s")
            return False
        if log and waited == 0:
            log(f"network unreachable; waiting up to {timeout_s:.0f}s")
        sleep(poll_s)
        waited += poll_s
