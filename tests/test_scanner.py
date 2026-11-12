"""Tests for the scanning engine: port states, the worker pool, discovery."""

import _thread
import socket
import threading
import time

import pytest

from portscanner import scanner
from portscanner.scanner import (
    CLOSED,
    FILTERED,
    OPEN,
    discover_hosts,
    is_host_up,
    run_pool,
    scan_host,
    scan_port,
)

LOCALHOST = "127.0.0.1"


# --- scan_port(): real sockets ---------------------------------------------

def test_open_port_detected(listener):
    assert scan_port(LOCALHOST, listener(), timeout=1) == OPEN


def test_closed_port_detected(unused_port):
    # 3s timeout: Windows takes ~2s to report a refused connection.
    assert scan_port(LOCALHOST, unused_port, timeout=3) == CLOSED


# --- scan_port(): simulated network conditions ------------------------------
# A firewall that silently drops packets can't be reproduced on localhost,
# so we swap in a fake socket whose connect() raises what the OS would.

class FakeSocket:
    def __init__(self, error):
        self.error = error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        raise self.error


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ConnectionRefusedError(), CLOSED),  # RST received
        (socket.timeout(), FILTERED),  # no answer: firewall drop
        (OSError(10065, "No route to host"), FILTERED),  # unreachable network
    ],
)
def test_scan_port_classifies_errors(monkeypatch, error, expected):
    # monkeypatch undoes the replacement automatically after the test.
    monkeypatch.setattr(scanner.socket, "socket", lambda *a, **k: FakeSocket(error))
    assert scan_port("192.0.2.1", 80, timeout=0.1) == expected


# --- scan_host() --------------------------------------------------------------

def test_scan_host_results_independent_of_thread_count(listener, unused_port):
    open_ports = sorted([listener(), listener()])
    ports = sorted(open_ports + [unused_port])
    single = scan_host(LOCALHOST, ports, timeout=0.3, threads=1, grab_banners=False)
    multi = scan_host(LOCALHOST, ports, timeout=0.3, threads=20, grab_banners=False)
    assert single.open_ports == multi.open_ports == open_ports
    assert [r.port for r in multi.results] == ports  # sorted, nothing lost


def test_scan_host_grabs_banners_for_open_ports(listener):
    port = listener(b"SSH-2.0-UnitTest\r\n")
    report = scan_host(LOCALHOST, [port], timeout=1, banner_timeout=2)
    (result,) = report.results
    assert (result.state, result.service, result.method) == (OPEN, "ssh", "banner")
    assert result.banner == "SSH-2.0-UnitTest"


def test_scan_host_records_metadata(listener):
    report = scan_host("localhost", [listener()], timeout=1, grab_banners=False)
    assert report.target == "localhost" and report.ip == LOCALHOST
    assert report.started_at.endswith("+00:00")  # UTC timestamp
    assert report.elapsed > 0 and not report.interrupted


def test_scan_host_rejects_zero_threads():
    with pytest.raises(ValueError):
        scan_host(LOCALHOST, [80], threads=0, ip=LOCALHOST)


def test_scan_host_stop_event_set_beforehand():
    stop = threading.Event()
    stop.set()
    report = scan_host(LOCALHOST, range(1, 100), ip=LOCALHOST, stop=stop)
    assert report.interrupted and report.results == []


# --- run_pool(): the worker pool itself ---------------------------------------

def test_run_pool_processes_every_item_once():
    seen, lock = [], threading.Lock()

    def task(item):
        with lock:
            seen.append(item)

    assert run_pool(range(500), task, threads=16) is False
    assert sorted(seen) == list(range(500))


def test_run_pool_ctrl_c_keeps_partial_results():
    done = []

    def slow(item):
        time.sleep(0.1)
        done.append(item)

    # interrupt_main() raises KeyboardInterrupt in the main thread, exactly
    # what pressing Ctrl+C does. 100 items x 0.1s / 2 threads = ~5s of work.
    threading.Timer(0.35, _thread.interrupt_main).start()
    start = time.perf_counter()
    interrupted = run_pool(range(100), slow, threads=2)
    assert interrupted is True
    assert 0 < len(done) < 100  # partial work kept, the rest skipped
    assert time.perf_counter() - start < 2  # stopped promptly


# --- host discovery -------------------------------------------------------------

def test_is_host_up_when_a_port_answers(listener):
    assert is_host_up(LOCALHOST, timeout=1, ports=[listener()]) is True


def test_is_host_down_when_everything_times_out(monkeypatch):
    monkeypatch.setattr(scanner, "scan_port", lambda ip, port, timeout: FILTERED)
    assert is_host_up("192.0.2.1", timeout=0.2) is False


def test_discover_hosts_returns_only_live_hosts(monkeypatch):
    monkeypatch.setattr(scanner, "is_host_up", lambda ip, timeout: ip.endswith(".1"))
    up, interrupted = discover_hosts(["10.0.0.1", "10.0.0.2", "10.0.1.1"])
    assert up == {"10.0.0.1", "10.0.1.1"} and interrupted is False
