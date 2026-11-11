"""Core TCP connect scanning.

A "connect scan" asks the operating system to complete a full TCP
three-way handshake with each port:

    scanner  --SYN-->      target
    scanner  <--SYN/ACK--  target   (port OPEN: something is listening)
    scanner  --ACK-->      target

If nothing is listening, the target's OS usually answers the SYN with a
RST packet, which Python raises as ConnectionRefusedError (port CLOSED).
If a firewall silently drops the SYN, no answer ever comes, so we wait
until our timeout expires (port FILTERED).

Connect scans need no special privileges, because the OS builds every
packet for us. The cost is that each completed handshake is a real
connection, so the target can log it. That makes this scan "noisy"
compared with a raw-packet SYN scan like `nmap -sS`.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field

# Port states, named the way Nmap names them so the output is familiar.
OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"

DEFAULT_TIMEOUT = 1.0  # seconds to wait for each connection attempt


@dataclass
class PortResult:
    """The outcome of probing one port."""

    port: int
    state: str


@dataclass
class ScanReport:
    """Everything one host scan produced."""

    target: str  # what the user typed (hostname or IP)
    ip: str  # the address we actually connected to
    results: list[PortResult] = field(default_factory=list)
    elapsed: float = 0.0  # wall-clock seconds for the whole scan

    @property
    def open_ports(self) -> list[int]:
        return [r.port for r in self.results if r.state == OPEN]


def resolve(target: str) -> str:
    """Turn a hostname into an IPv4 address, once.

    Resolving up front means we do one DNS lookup per host instead of one
    per port, and every probe goes to the same address. If the name does
    not exist, socket.gaierror ("get address info error") is raised.
    """
    return socket.gethostbyname(target)


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Try a TCP handshake with ip:port and classify the port.

    Returns OPEN, CLOSED or FILTERED.

    Platform note: Linux and macOS report a refused connection as soon as
    the RST arrives. Windows retries the SYN after an RST and only gives
    up after about 2 seconds. On Windows, a timeout below ~2.1s therefore
    reports closed ports as FILTERED. Open ports are unaffected, because
    the SYN/ACK comes back right away.
    """
    # AF_INET = IPv4, SOCK_STREAM = TCP. The `with` block guarantees the
    # socket is closed, so a long scan doesn't leak file descriptors.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Without a timeout, connect() to a filtered port can block for a
        # long time (the OS keeps resending the SYN). The timeout is the
        # main speed vs. accuracy knob: too low and slow hosts look
        # filtered, too high and every filtered port wastes time.
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            return OPEN
        except ConnectionRefusedError:
            # The target replied with RST: reachable, but nothing listens.
            return CLOSED
        except (socket.timeout, TimeoutError):
            # No reply before the deadline: most likely a firewall drop.
            return FILTERED
        except OSError:
            # Other network errors (e.g. "host unreachable"). We can't tell
            # whether the port is open, so report it as filtered.
            return FILTERED


def scan_host(
    target: str,
    ports: list[int] | range,
    timeout: float = DEFAULT_TIMEOUT,
) -> ScanReport:
    """Scan the given ports on one host, one at a time.

    This sequential version is the baseline. Phase 2 makes it concurrent
    and benchmarks the difference.
    """
    ip = resolve(target)
    report = ScanReport(target=target, ip=ip)

    # perf_counter is a monotonic, high-resolution clock meant for
    # measuring durations, unlike time.time(), which can jump.
    start = time.perf_counter()
    for port in ports:
        report.results.append(PortResult(port, scan_port(ip, port, timeout)))
    report.elapsed = time.perf_counter() - start
    return report


def format_report(report: ScanReport) -> str:
    """Render a scan report as plain text that lists only open ports."""
    lines = [f"Scan report for {report.target} ({report.ip})"]
    open_results = [r for r in report.results if r.state == OPEN]
    if open_results:
        lines.append(f"{'PORT':<10}STATE")
        lines.extend(f"{f'{r.port}/tcp':<10}{r.state}" for r in open_results)
    else:
        lines.append("No open ports found.")

    closed = sum(r.state == CLOSED for r in report.results)
    filtered = sum(r.state == FILTERED for r in report.results)
    lines.append(
        f"Scanned {len(report.results)} ports in {report.elapsed:.2f}s "
        f"({len(open_results)} open, {closed} closed, {filtered} filtered)"
    )
    return "\n".join(lines)
