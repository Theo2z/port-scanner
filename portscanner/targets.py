"""Turn user input into concrete hosts and ports.

This module knows nothing about sockets. It only parses and validates
strings, so it is easy to test and keeps bad input from ever reaching
the network code.

Targets:  "192.168.1.10"     a single IPv4 address
          "scanme.nmap.org"  a hostname (resolved later, when scanned)
          "192.168.1.0/28"   a CIDR range, expanded to its usable hosts
          "a,b,c"            any comma-separated mix of the above

Ports:    "80"                 one port
          "1-1024"             an inclusive range
          "22,80,443,8000-8100" any comma-separated mix
"""

from __future__ import annotations

import ipaddress

MIN_PORT, MAX_PORT = 1, 65535
# Safety limit: a typo like /8 instead of /28 would mean 16 million hosts.
MAX_HOSTS = 65536


class TargetError(ValueError):
    """Raised for any target or port specification we can't use."""


def parse_targets(spec: str) -> list[str]:
    """Expand a target spec into a de-duplicated list of hosts, in order."""
    hosts: list[str] = []
    for part in _split(spec, "target"):
        if "/" in part:
            hosts.extend(_expand_cidr(part))
        else:
            hosts.append(part)  # IP or hostname; DNS happens at scan time
        if len(hosts) > MAX_HOSTS:
            raise TargetError(f"too many hosts (limit {MAX_HOSTS})")
    # dict.fromkeys keeps the first occurrence of each host, in order.
    return list(dict.fromkeys(hosts))


def _expand_cidr(cidr: str) -> list[str]:
    """Expand CIDR notation, e.g. 10.0.0.0/30 -> ['10.0.0.1', '10.0.0.2'].

    CIDR "a.b.c.d/n" means "the first n bits are the network part". A /24
    leaves 8 host bits, so 2**8 = 256 addresses. hosts() skips the
    network address (all host bits 0) and the broadcast address (all
    host bits 1), which aren't real machines. For /31 and /32 there are
    no such reserved addresses and hosts() returns every address.
    """
    try:
        # strict=False accepts "192.168.1.77/24" and treats it as
        # 192.168.1.0/24, which is what people usually mean.
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise TargetError(f"invalid CIDR range {cidr!r}: {exc}") from None
    if network.version != 4:
        raise TargetError(f"only IPv4 is supported, got {cidr!r}")
    if network.num_addresses > MAX_HOSTS:
        raise TargetError(
            f"{cidr} has {network.num_addresses} addresses (limit {MAX_HOSTS})"
        )
    return [str(ip) for ip in network.hosts()]


def parse_ports(spec: str) -> list[int]:
    """Expand a port spec into a sorted, de-duplicated list of ports."""
    ports: set[int] = set()
    for part in _split(spec, "port"):
        if "-" in part:
            low_s, _, high_s = part.partition("-")
            low, high = _port(low_s), _port(high_s)
            if low > high:
                raise TargetError(f"port range {part!r} is backwards")
            ports.update(range(low, high + 1))
        else:
            ports.add(_port(part))
    return sorted(ports)


def _port(text: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise TargetError(f"{text!r} is not a port number") from None
    if not MIN_PORT <= port <= MAX_PORT:
        raise TargetError(f"port {port} is outside {MIN_PORT}-{MAX_PORT}")
    return port


def _split(spec: str, what: str) -> list[str]:
    """Split on commas, trim whitespace, and reject empty input."""
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not parts:
        raise TargetError(f"no {what} given")
    return parts
