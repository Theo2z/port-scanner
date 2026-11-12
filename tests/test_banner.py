"""Tests for banner sanitizing, service detection and live banner grabs."""

import pytest

from portscanner.banner import (
    MAX_BANNER_CHARS,
    _http_summary,
    detect_service,
    grab_banner,
    sanitize,
)


# --- sanitize(): banners are untrusted input -------------------------------

def test_sanitize_strips_ansi_escape_sequences():
    hostile = b"\x1b[2J\x1b[31mEVIL\x07 banner\x1b]0;pwned\x07\r\n"
    cleaned = sanitize(hostile)
    assert "\x1b" not in cleaned and "\x07" not in cleaned
    assert "EVIL" in cleaned


def test_sanitize_collapses_whitespace_and_line_breaks():
    assert sanitize(b"SSH-2.0-OpenSSH_9.6\r\n\r\n") == "SSH-2.0-OpenSSH_9.6"
    assert sanitize(b"a\t\tb\n c") == "a b c"


def test_sanitize_truncates_long_banners():
    cleaned = sanitize(b"A" * 500)
    assert len(cleaned) == MAX_BANNER_CHARS
    assert cleaned.endswith("...")


def test_sanitize_summarizes_binary_data():
    assert sanitize(bytes(range(40))) == "<binary data, 40 bytes>"


def test_sanitize_empty():
    assert sanitize(b"") == ""


# --- detect_service() --------------------------------------------------------

@pytest.mark.parametrize(
    ("port", "banner", "expected"),
    [
        (22, "SSH-2.0-OpenSSH_9.6", ("ssh", "banner")),
        (8080, "SSH-2.0-dropbear", ("ssh", "banner")),  # banner beats port number
        (80, "HTTP/1.1 200 OK | Server: Apache", ("http", "banner")),
        (21, "220 (vsFTPd 3.0.5)", ("ftp", "banner")),
        (25, "220 mx.example.com ESMTP Postfix", ("smtp", "banner")),
        (110, "+OK POP3 ready", ("pop3", "banner")),
        (143, "* OK IMAP4rev1", ("imap", "banner")),
        (3306, "", ("mysql", "port")),  # silent: fall back to the port table
        (40000, "", ("unknown", "port")),
    ],
)
def test_detect_service(port, banner, expected):
    assert detect_service(port, banner) == expected


def test_http_summary_keeps_status_line_and_server_header():
    raw = b"HTTP/1.1 200 OK\r\nDate: today\r\nServer: nginx/1.25\r\nX-Foo: bar\r\n\r\n"
    assert _http_summary(raw) == b"HTTP/1.1 200 OK | Server: nginx/1.25"


# --- grab_banner() against real local sockets --------------------------------

def test_grab_banner_reads_talk_first_service(listener):
    port = listener(b"SSH-2.0-TestServer\r\n")
    assert grab_banner("127.0.0.1", port, timeout=2) == "SSH-2.0-TestServer"


def test_grab_banner_silent_service_returns_empty(listener):
    port = listener(b"")
    assert grab_banner("127.0.0.1", port, timeout=0.3) == ""


def test_grab_banner_closed_port_returns_empty(unused_port):
    assert grab_banner("127.0.0.1", unused_port, timeout=0.3) == ""
