"""Entry point for `python -m portscanner`.

Phase 1 uses bare positional arguments. Phase 4 replaces this with a
proper argparse CLI.

Usage: python -m portscanner HOST [FIRST_PORT LAST_PORT] [TIMEOUT] [THREADS]
"""

import sys

from .scanner import DEFAULT_THREADS, DEFAULT_TIMEOUT, format_report, scan_host


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.strip().splitlines()[-1])
        return 2

    host = argv[0]
    first, last = (int(argv[1]), int(argv[2])) if len(argv) >= 3 else (1, 1024)
    timeout = float(argv[3]) if len(argv) >= 4 else DEFAULT_TIMEOUT
    threads = int(argv[4]) if len(argv) >= 5 else DEFAULT_THREADS

    report = scan_host(host, range(first, last + 1), timeout, threads)
    print(format_report(report))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
