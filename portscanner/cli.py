"""Command-line interface.

argparse turns sys.argv into a validated namespace and generates --help
and usage errors for free. Each option's `type=` is a function that
converts the raw string; raising argparse.ArgumentTypeError inside it
makes argparse print a clean usage error (exit code 2) instead of a
traceback.
"""

from __future__ import annotations

import argparse
import socket
import sys

from . import __version__
from .banner import DEFAULT_BANNER_TIMEOUT
from .output import format_table, write_csv, write_json
from .scanner import DEFAULT_THREADS, DEFAULT_TIMEOUT, scan_host
from .targets import TargetError, parse_ports, parse_targets

MAX_THREADS = 1000  # beyond this, OS socket limits and target load bite

EPILOG = """\
examples:
  portscanner 127.0.0.1
  portscanner scanme.nmap.org -p 22,80,443 --timeout 2
  portscanner 192.168.1.0/28 -p 1-1024 -t 200
  portscanner localhost -p 8000-8100 --no-banners
  portscanner scanme.nmap.org -p 1-100 --csv results/scan.csv --json results/scan.json

Only scan systems you own or have explicit permission to test.
"""


def _targets(text: str) -> list[str]:
    try:
        return parse_targets(text)
    except TargetError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _ports(text: str) -> list[int]:
    try:
        return parse_ports(text)
    except TargetError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _threads(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if not 1 <= value <= MAX_THREADS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_THREADS}")
    return value


def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def _compact_ports(ports: list[int]) -> str:
    """[1, 2, 3, 80] -> "1-3,80", so JSON doesn't list 65,535 numbers."""
    spans: list[str] = []
    start = prev = ports[0]
    for p in ports[1:] + [None]:  # None flushes the last span
        if p is not None and p == prev + 1:
            prev = p
            continue
        spans.append(str(start) if start == prev else f"{start}-{prev}")
        if p is not None:
            start = prev = p
    return ",".join(spans)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description="Multithreaded TCP connect scanner with banner grabbing.",
        epilog=EPILOG,
        # Keep the epilog's line breaks instead of re-wrapping it.
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets", type=_targets, metavar="TARGET",
        help="IP, hostname or CIDR range; comma-separate several",
    )
    parser.add_argument(
        "-p", "--ports", type=_ports, default=parse_ports("1-1024"),
        help="ports to scan, e.g. 80 | 1-1024 | 22,80,8000-8100 (default: 1-1024)",
    )
    parser.add_argument(
        "-t", "--threads", type=_threads, default=DEFAULT_THREADS,
        help=f"concurrent connections per host (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--timeout", type=_seconds, default=DEFAULT_TIMEOUT,
        help=f"seconds to wait per connection (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--no-banners", dest="banners", action="store_false",
        help="skip banner grabbing and service detection",
    )
    parser.add_argument(
        "--banner-timeout", type=_seconds, default=DEFAULT_BANNER_TIMEOUT,
        help=f"seconds to wait for a banner (default: {DEFAULT_BANNER_TIMEOUT})",
    )
    parser.add_argument(
        "--csv", metavar="FILE", help="also write open ports to a CSV file",
    )
    parser.add_argument(
        "--json", metavar="FILE", help="also write full results to a JSON file",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns the process exit code."""
    args = build_parser().parse_args(argv)

    print(
        f"Scanning {len(args.targets)} host(s), {len(args.ports)} port(s) each, "
        f"{args.threads} threads, {args.timeout}s timeout\n"
    )

    failures = 0
    reports = []
    for host in args.targets:
        try:
            report = scan_host(
                host, args.ports, timeout=args.timeout, threads=args.threads,
                grab_banners=args.banners, banner_timeout=args.banner_timeout,
            )
        except socket.gaierror:
            # DNS lookup failed. Report it and move on to the next host.
            print(f"error: could not resolve {host!r}\n", file=sys.stderr)
            failures += 1
            continue
        reports.append(report)
        # flush=True so results appear as each host finishes, even when
        # stdout is piped to a file or another program.
        print(format_table(report) + "\n", flush=True)

    # Exports are written once, after all hosts, so each file holds the
    # whole scan.
    if args.csv:
        rows = write_csv(reports, args.csv)
        print(f"Wrote {rows} open port(s) to {args.csv}")
    if args.json:
        settings = {
            "targets": args.targets, "ports": _compact_ports(args.ports),
            "threads": args.threads, "timeout": args.timeout,
            "banners": args.banners, "banner_timeout": args.banner_timeout,
        }
        write_json(reports, args.json, settings)
        print(f"Wrote JSON results to {args.json}")

    # Non-zero exit status if any host failed, so scripts can detect it.
    return 1 if failures else 0
