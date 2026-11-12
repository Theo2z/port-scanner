"""End-to-end tests of the command-line interface.

main() takes an argv list and returns an exit code, so tests call it
directly instead of starting a subprocess. capsys captures what it prints.
Slow or external steps (DNS, discovery) are replaced with monkeypatch
where the test is about the CLI's behavior, not the network.
"""

import json
import socket

import pytest

from portscanner import cli
from portscanner.scanner import ScanReport


def run(argv, capsys):
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


@pytest.mark.parametrize(
    "argv",
    [
        [],  # target is required
        ["127.0.0.1", "-p", "0"],
        ["127.0.0.1", "-t", "0"],
        ["127.0.0.1", "--timeout", "-1"],
        ["10.0.0.0/8"],
    ],
)
def test_invalid_arguments_exit_with_code_2(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_scan_localhost_end_to_end(listener, capsys):
    port = listener(b"SSH-2.0-CliTest\r\n")
    code, out, _ = run(["127.0.0.1", "-p", str(port), "-Pn"], capsys)
    assert code == 0
    assert f"{port}/tcp" in out and "SSH-2.0-CliTest" in out


def test_exports_written(listener, tmp_path, capsys):
    port = listener()
    csv_path, json_path = tmp_path / "s.csv", tmp_path / "s.json"
    code, _, _ = run(
        ["127.0.0.1", "-p", str(port), "-Pn", "--no-banners",
         "--csv", str(csv_path), "--json", str(json_path)],
        capsys,
    )
    assert code == 0
    assert str(port) in csv_path.read_text(encoding="utf-8")
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    assert doc["settings"]["ports"] == str(port)


def test_unresolvable_host_is_skipped_with_exit_1(monkeypatch, capsys):
    def fail(name):
        raise socket.gaierror("not found")

    monkeypatch.setattr(cli, "resolve", fail)
    code, _, err = run(["no-such-host.invalid"], capsys)
    assert code == 1 and "could not resolve" in err


def test_down_host_is_skipped(monkeypatch, capsys):
    monkeypatch.setattr(cli, "discover_hosts", lambda ips: (set(), False))
    code, out, _ = run(["192.0.2.1", "-p", "80"], capsys)
    assert code == 0 and "appears down" in out


def test_export_failure_exit_1(listener, tmp_path, capsys):
    # A directory can't be opened as a file: write fails with OSError.
    code, _, err = run(
        ["127.0.0.1", "-p", str(listener()), "-Pn", "--no-banners", "--csv", str(tmp_path)],
        capsys,
    )
    assert code == 1 and "could not write" in err


def test_interrupted_scan_exit_130_and_still_exports(monkeypatch, tmp_path, capsys):
    def interrupted_scan(target, ports, **kwargs):
        return ScanReport(target, kwargs["ip"], interrupted=True)

    monkeypatch.setattr(cli, "scan_host", interrupted_scan)
    json_path = tmp_path / "partial.json"
    code, _, err = run(["127.0.0.1", "-Pn", "--json", str(json_path)], capsys)
    assert code == cli.EXIT_INTERRUPTED == 130
    assert "Interrupted" in err
    assert json.loads(json_path.read_text())["hosts"][0]["interrupted"] is True


def test_compact_ports():
    assert cli._compact_ports([1, 2, 3, 80, 443, 444]) == "1-3,80,443-444"
