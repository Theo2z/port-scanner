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
from typing import Callable, Iterable, TypeVar

from .banner import DEFAULT_BANNER_TIMEOUT, detect_service, grab_banner

T = TypeVar("T")

# Port states, named the way Nmap names them so the output is familiar.
OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"

DEFAULT_TIMEOUT = 1.0  # seconds to wait for each connection attempt
DEFAULT_THREADS = 100  # concurrent connection attempts

# Host discovery: ports that almost every live host answers on, either
# open (SYN/ACK) or closed (RST). Either answer proves the host is up.
DISCOVERY_PORTS = (80, 443, 22, 445, 3389, 21, 25, 135, 139, 8080)
# Above the ~2s Windows takes to report a refused connection, so a live
# host with every discovery port closed is still seen as up.
DISCOVERY_TIMEOUT = 2.5
DISCOVERY_THREADS = 32  # hosts checked at once


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
    interrupted: bool = False  # True if Ctrl+C stopped the scan early

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


def run_pool(
    items: Iterable[T],
    task: Callable[[T], None],
    threads: int,
    stop: threading.Event | None = None,
) -> bool:
    """Run task(item) for every item on a pool of worker threads.

    Returns True if the run was interrupted (Ctrl+C or `stop` set) before
    every item was processed.

    Why threads help even with Python's GIL: the Global Interpreter Lock
    lets only one thread run Python bytecode at a time, but a thread
    *releases* it while blocked in a system call such as connect(). A scan
    spends almost all its time waiting on the network, so 100 threads can
    have 100 handshakes in flight at once. For CPU-bound work (hashing,
    parsing) threads would not help; you would use processes instead.

    Design: a producer/consumer "worker pool".
      * One queue.Queue holds every item still to process (the work).
      * N worker threads each loop: take an item, run the task.
      * When the queue is empty the workers exit.
    Threads are created once and reused, instead of one thread per item,
    which keeps memory use and thread-creation cost fixed. threads=1 gives
    a plain sequential run.

    Ctrl+C: Python delivers KeyboardInterrupt only to the main thread. If
    the main thread sat in a plain join(), on some platforms (notably
    Windows) the interrupt would wait until that join returned. So we
    join with a short timeout in a loop, which gives Python a chance to
    raise KeyboardInterrupt between waits. When it arrives we set a stop
    flag (a threading.Event), the workers notice it before taking their
    next item, and we wait for the probes already in flight to finish.
    You keep the partial results instead of losing the whole scan.
    """
    if threads < 1:
        raise ValueError("threads must be at least 1")
    stop = stop or threading.Event()

    # queue.Queue is thread-safe: its own internal lock guarantees that two
    # workers can never take the same item.
    work: queue.Queue[T] = queue.Queue()
    for item in items:
        work.put(item)

    def worker() -> None:
        while not stop.is_set():
            try:
                # get_nowait() raises queue.Empty instead of blocking. All
                # work is queued before any worker starts, so "empty" means
                # "done" and the worker can simply return.
                item = work.get_nowait()
            except queue.Empty:
                return
            task(item)

    # Never start more threads than there are items; extras would exit
    # straight away and only cost creation time.
    pool_size = min(threads, work.qsize()) or 1
    # daemon=True: if the main thread exits (e.g. a second Ctrl+C), these
    # threads won't keep the process alive.
    pool = [threading.Thread(target=worker, daemon=True) for _ in range(pool_size)]
    for t in pool:
        t.start()

    try:
        _wait_for(pool)
    except KeyboardInterrupt:
        stop.set()
        # Let in-flight probes finish (at most one timeout each). A second
        # Ctrl+C here propagates and ends the program immediately.
        _wait_for(pool)
    return stop.is_set() and not work.empty()


def _wait_for(pool: list[threading.Thread]) -> None:
    """Join every thread, waking up regularly so Ctrl+C is handled promptly."""
    for t in pool:
        while t.is_alive():
            t.join(timeout=0.2)


def scan_host(
    target: str,
    ports: list[int] | range,
    timeout: float = DEFAULT_TIMEOUT,
    threads: int = DEFAULT_THREADS,
    grab_banners: bool = True,
    banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
    ip: str | None = None,
    stop: threading.Event | None = None,
) -> ScanReport:
    """Scan the given ports on one host.

    `ip` skips DNS when the caller has already resolved the target. If the
    scan is interrupted, the report holds the ports finished so far and
    report.interrupted is True.

    If grab_banners is True, each open port gets a second connection to
    read its banner, done by the same worker so it also runs in parallel.
    Opening a fresh connection keeps scan_port() simple; the cost is one
    extra connection per open port, which the target can also log.
    """
    if threads < 1:
        raise ValueError("threads must be at least 1")

    ip = ip or resolve(target)
    report = ScanReport(
        target=target,
        ip=ip,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    # The results list is shared by all workers, so writes go through a
    # Lock. (list.append happens to be atomic in CPython, but relying on
    # that is an implementation detail; the lock states the intent.)
    results_lock = threading.Lock()

    def probe(port: int) -> None:
        result = PortResult(port, scan_port(ip, port, timeout))
        if result.state == OPEN and grab_banners:
            result.banner = grab_banner(ip, port, banner_timeout)
            result.service, result.method = detect_service(port, result.banner)
        with results_lock:
            report.results.append(result)

    # perf_counter is a monotonic, high-resolution clock meant for
    # measuring durations, unlike time.time(), which can jump.
    start = time.perf_counter()
    report.interrupted = run_pool(ports, probe, threads, stop)
    report.elapsed = time.perf_counter() - start

    # Workers finish in whatever order the network answers, so sort to make
    # the output deterministic.
    report.results.sort(key=lambda r: r.port)
    return report


def is_host_up(
    ip: str,
    timeout: float = DISCOVERY_TIMEOUT,
    ports: Iterable[int] = DISCOVERY_PORTS,
) -> bool:
    """Guess whether a host is online, using only TCP connects.

    Nmap's default discovery uses ICMP ping, but sending ICMP needs raw
    sockets (admin/root), and many networks block ping anyway. A TCP-based
    check works unprivileged: if ANY of a few common ports answers, open
    (SYN/ACK) or closed (RST), a machine is there. If they all time out,
    the host is probably down or behind a firewall that drops everything,
    so scanning thousands of ports would only produce timeouts.

    Probes run in parallel, and we return as soon as one port answers.
    """
    answered = threading.Event()

    def probe(port: int) -> None:
        if scan_port(ip, port, timeout) != FILTERED:
            answered.set()

    probes = [threading.Thread(target=probe, args=(p,), daemon=True) for p in ports]
    for t in probes:
        t.start()
    deadline = time.monotonic() + timeout + 0.5
    while not answered.is_set() and time.monotonic() < deadline:
        if not any(t.is_alive() for t in probes):
            break
        answered.wait(0.1)  # short waits keep Ctrl+C responsive
    return answered.is_set()


def discover_hosts(
    ips: list[str],
    timeout: float = DISCOVERY_TIMEOUT,
    threads: int = DISCOVERY_THREADS,
) -> tuple[set[str], bool]:
    """Check many hosts at once. Returns (ips that are up, interrupted)."""
    up: set[str] = set()
    lock = threading.Lock()

    def check(ip: str) -> None:
        if is_host_up(ip, timeout):
            with lock:
                up.add(ip)

    interrupted = run_pool(ips, check, threads)
    return up, interrupted
