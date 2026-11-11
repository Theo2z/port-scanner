"""Benchmark the scanner at different thread counts.

Runs only against 127.0.0.1. It opens a few listening sockets of its own
so there are known open ports, scans the same port range at each thread
count, checks that every run found exactly the same open ports, and
prints a Markdown table of the timings.

Usage:  python benchmarks/benchmark.py [--ports N] [--timeout S] [--threads 1 10 50 ...]
"""

from __future__ import annotations

import argparse
import socket
from contextlib import ExitStack

from portscanner.scanner import scan_host

HOST = "127.0.0.1"
BASE_PORT = 20000  # high, normally unused range, away from system services


def open_listeners(stack: ExitStack, ports: list[int]) -> None:
    """Listen on each port so the scanner has known open ports to find."""
    for port in ports:
        s = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        s.bind((HOST, port))
        s.listen()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ports", type=int, default=200, help="how many ports to scan")
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--threads", type=int, nargs="+", default=[1, 10, 50, 100, 200])
    args = parser.parse_args()

    port_range = range(BASE_PORT, BASE_PORT + args.ports)
    # Spread three listeners through the range.
    planted = [port_range[i] for i in (0, len(port_range) // 2, len(port_range) - 1)]

    rows = []
    with ExitStack() as stack:
        open_listeners(stack, planted)
        for n in args.threads:
            report = scan_host(HOST, port_range, timeout=args.timeout, threads=n)
            # A faster scan is worthless if it is less accurate.
            assert report.open_ports == planted, (
                f"threads={n}: expected {planted}, got {report.open_ports}"
            )
            rows.append((n, report.elapsed))
            print(f"threads={n:<4} {report.elapsed:7.2f}s", flush=True)

    baseline = rows[0][1]
    print(f"\n{args.ports} ports on {HOST}, timeout {args.timeout}s, "
          f"open ports found every run: {planted}\n")
    print("| Threads | Time (s) | Speed-up |")
    print("|--------:|---------:|---------:|")
    for n, elapsed in rows:
        print(f"| {n} | {elapsed:.2f} | {baseline / elapsed:.1f}x |")


if __name__ == "__main__":
    main()
