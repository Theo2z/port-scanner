"""Entry point for `python -m portscanner` (same as the `portscanner` command)."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
