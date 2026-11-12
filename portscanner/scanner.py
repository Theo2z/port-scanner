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

import queue
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .banner import DEFAULT_BANNER_TIMEOUT, detect_service, grab_banner

# Port states, named the way Nmap names them so the output is familiar.
OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"

DEFAULT_TIMEOUT = 1.0  # seconds to wait for each connection attempt
DEFAULT_THREADS = 100  # concurrent connection attempts


@dataclass
class PortResult:
    """The outcome of probing one port."""

    port: int
    state: str
    service: str = ""  # e.g. "ssh"; only filled in for open ports
    method: str = ""  # "banner" (matched a signature) or "port" (guess)
    banner: str = ""  # sanitized banner text, '' if the service was silent


@dataclass
class ScanReport:
    """Everything one host scan produced."""

    target: str  # what the user typed (hostname or IP)
    ip: str  # the address we actually connected to
    results: list[PortResult] = field(default_factory=list)
    elapsed: float = 0.0  # wall-clock seconds for the whole scan
    started_at: str = ""  # UTC start time, ISO 8601

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
    threads: int = DEFAULT_THREADS,
    grab_banners: bool = True,
    banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
) -> ScanReport:
    """Scan the given ports on one host with a pool of worker threads.

    Why threads help even with Python's GIL: the Global Interpreter Lock
    lets only one thread run Python bytecode at a time, but a thread
    *releases* it while blocked in a system call such as connect(). A scan
    spends almost all its time waiting on the network, so 100 threads can
    have 100 handshakes in flight at once. For CPU-bound work (hashing,
    parsing) threads would not help; you would use processes instead.

    Design: a producer/consumer "worker pool".
      * One queue.Queue holds every port still to scan (the work).
      * N worker threads each loop: take a port, probe it, record result.
      * When the queue is empty the workers exit and we join() them.
    Threads are created once and reused, instead of one thread per port,
    which keeps memory use and thread-creation cost fixed no matter how
    many ports are scanned. threads=1 gives a plain sequential scan.

    If grab_banners is True, each open port gets a second connection to
    read its banner, done by the same worker so it also runs in parallel.
    Opening a fresh connection keeps scan_port() simple; the cost is one
    extra connection per open port, which the target can also log.
    """
    if threads < 1:
        raise ValueError("threads must be at least 1")

    ip = resolve(target)
    report = ScanReport(
        target=target,
        ip=ip,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    # queue.Queue is thread-safe: its own internal lock guarantees that two
    # workers can never pull the same port.
    work: queue.Queue[int] = queue.Queue()
    for port in ports:
        work.put(port)

    # The results list is shared by all workers, so writes go through a
    # Lock. (list.append happens to be atomic in CPython, but relying on
    # that is an implementation detail; the lock states the intent.)
    results_lock = threading.Lock()

    def worker() -> None:
        while True:
            try:
                # get_nowait() raises queue.Empty instead of blocking. All
                # work is queued before any worker starts, so "empty" means
                # "done" and the worker can simply return.
                port = work.get_nowait()
            except queue.Empty:
                return
            result = PortResult(port, scan_port(ip, port, timeout))
            if result.state == OPEN and grab_banners:
                result.banner = grab_banner(ip, port, banner_timeout)
                result.service, result.method = detect_service(port, result.banner)
            with results_lock:
                report.results.append(result)

    # Never start more threads than there are ports; extras would exit
    # straight away and only cost creation time.
    pool_size = min(threads, work.qsize()) or 1

    # perf_counter is a monotonic, high-resolution clock meant for
    # measuring durations, unlike time.time(), which can jump.
    start = time.perf_counter()
    # daemon=True: if the main thread dies (e.g. an unhandled error), these
    # threads won't keep the process alive. Clean Ctrl+C handling comes in
    # Phase 6.
    pool = [threading.Thread(target=worker, daemon=True) for _ in range(pool_size)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()  # wait until every worker has finished
    report.elapsed = time.perf_counter() - start

    # Workers finish in whatever order the network answers, so sort to make
    # the output deterministic.
    report.results.sort(key=lambda r: r.port)
    return report
