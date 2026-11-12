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
from .scanner import (
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    discover_hosts,
    resolve,
    scan_host,
)
from .targets import TargetError, parse_ports, parse_targets

MAX_THREADS = 1000  # beyond this, OS socket limits and target load bite
EXIT_INTERRUPTED = 130

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
        "-Pn", "--skip-discovery", dest="discovery", action="store_false",
        help="scan every target even if it looks down (like nmap -Pn)",
    )
    parser.add_argument(
        "--csv", metavar="FILE", help="also write open ports to a CSV file",
    )
    parser.add_argument(
        "--json", metavar="FILE", help="also write full results to a JSON file",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _error(message: str) -> None:
    # Errors go to stderr, so `portscanner ... > out.txt` keeps the results
    # file clean while problems still show up on screen.
    print(f"error: {message}", file=sys.stderr, flush=True)


def _resolve_all(targets: list[str]) -> tuple[dict[str, str], int]:
    """Resolve every target up front. Returns ({target: ip}, failure count)."""
    resolved: dict[str, str] = {}
    failures = 0
    for target in targets:
        try:
            resolved[target] = resolve(target)
        except (socket.gaierror, UnicodeError):
            # gaierror: the name doesn't exist or DNS is unreachable.
            # UnicodeError: the name is malformed (e.g. a label over 63 chars).
            _error(f"could not resolve {target!r}, skipping")
            failures += 1
    return resolved, failures


def _write_exports(args: argparse.Namespace, reports: list) -> int:
    """Write the requested files. Returns the number of failures."""
    failures = 0
    if args.csv:
        try:
            rows = write_csv(reports, args.csv)
            print(f"Wrote {rows} open port(s) to {args.csv}")
        except OSError as exc:  # permission denied, path is a folder, disk full...
            _error(f"could not write {args.csv}: {exc.strerror or exc}")
            failures += 1
    if args.json:
        settings = {
            "targets": args.targets, "ports": _compact_ports(args.ports),
            "threads": args.threads, "timeout": args.timeout,
            "banners": args.banners, "banner_timeout": args.banner_timeout,
            "discovery": args.discovery,
        }
        try:
            write_json(reports, args.json, settings)
            print(f"Wrote JSON results to {args.json}")
        except OSError as exc:
            _error(f"could not write {args.json}: {exc.strerror or exc}")
            failures += 1
    return failures


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns the process exit code.

    Exit codes follow Unix convention, so scripts can react to them:
      0    success
      1    some targets could not be resolved, or an export failed
      2    invalid command-line arguments (raised by argparse)
      130  stopped with Ctrl+C (128 + SIGINT's signal number, 2)
    """
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except KeyboardInterrupt:
        # Ctrl+C outside a scan (e.g. during a slow DNS lookup).
        print("\nAborted.", file=sys.stderr)
        return EXIT_INTERRUPTED


def _run(args: argparse.Namespace) -> int:
    resolved, failures = _resolve_all(args.targets)
    if not resolved:
        return 1

    # Several names can point to the same address; scan each address once.
    unique_ips = list(dict.fromkeys(resolved.values()))
    if args.discovery:
        print(f"Checking which of {len(unique_ips)} host(s) are up...", flush=True)
        up, interrupted = discover_hosts(unique_ips)
        if interrupted:
            print("\nInterrupted during host discovery; nothing scanned.", file=sys.stderr)
            return EXIT_INTERRUPTED
        for target, ip in resolved.items():
            if ip not in up:
                print(f"{target} ({ip}) appears down or blocks all probes; skipped. "
                      f"Use --skip-discovery to scan it anyway.")
    else:
        up = set(unique_ips)

    # Keep the first name given for each live address.
    to_scan: list[tuple[str, str]] = []
    seen: set[str] = set()
    for target, ip in resolved.items():
        if ip in up and ip not in seen:
            seen.add(ip)
            to_scan.append((target, ip))
    if not to_scan:
        return 1 if failures else 0
    print(
        f"\nScanning {len(to_scan)} host(s), {len(args.ports)} port(s) each, "
        f"{args.threads} threads, {args.timeout}s timeout\n",
        flush=True,
    )

    reports = []
    interrupted = False
    for target, ip in to_scan:
        report = scan_host(
            target, args.ports, timeout=args.timeout, threads=args.threads,
            grab_banners=args.banners, banner_timeout=args.banner_timeout, ip=ip,
        )
        reports.append(report)
        # flush=True so results appear as each host finishes, even when
        # stdout is piped to a file or another program.
        print(format_table(report) + "\n", flush=True)
        if report.interrupted:
            interrupted = True
            print(f"Interrupted: showing partial results for {target}; "
                  f"remaining hosts skipped.\n", file=sys.stderr)
            break

    # Exports are written even after Ctrl+C, so partial work isn't lost.
    failures += _write_exports(args, reports)

    if interrupted:
        return EXIT_INTERRUPTED
    return 1 if failures else 0
