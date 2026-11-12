"""Banner grabbing and basic service detection.

A *banner* is the text a service sends to identify itself, such as
`SSH-2.0-OpenSSH_9.6` or `220 mail.example.com ESMTP Postfix`. Knowing
the exact software and version is what turns "port 22 is open" into
"port 22 runs OpenSSH 9.6, check it for known CVEs".

Services fall into two groups:
  * Talk-first: SSH, FTP, SMTP, POP3, IMAP and MySQL send a greeting as
    soon as you connect. We just listen ("passive" grab).
  * Wait-for-client: HTTP and most web services say nothing until they
    get a request, so we send a small probe ("active" grab).

Port numbers are only a convention: anyone can run SSH on port 80. So a
banner match beats a guess from the port number, and the report says
which method was used.
"""

from __future__ import annotations

import re
import socket

DEFAULT_BANNER_TIMEOUT = 2.0
MAX_BANNER_BYTES = 1024  # services greet in a few bytes; don't read forever
MAX_BANNER_CHARS = 80  # keep terminal output readable

# Ports where the client speaks first, so the probe must be a request.
HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888}

# Fallback guesses from the port number (IANA well-known ports).
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    9929: "nping-echo", 27017: "mongodb",
}

# Banner signatures, checked in order. Each maps a regex to a service name.
SIGNATURES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^SSH-\d", re.I), "ssh"),
    (re.compile(r"^HTTP/\d", re.I), "http"),
    (re.compile(r"^220[ -].*\bE?SMTP\b", re.I), "smtp"),
    # Plain substring, not \bFTP\b, so product names like vsFTPd match too.
    (re.compile(r"^220[ -].*ftp", re.I), "ftp"),
    (re.compile(r"^220[ -]"), "ftp/smtp"),  # 220 greeting with no product hint
    (re.compile(r"^\+OK", re.I), "pop3"),
    (re.compile(r"^\* OK", re.I), "imap"),
    (re.compile(r"^-ERR.*redis|^-NOAUTH", re.I), "redis"),
    (re.compile(r"mysql|mariadb", re.I), "mysql"),
    (re.compile(r"^RFB \d", re.I), "vnc"),
]

# Anything that isn't printable ASCII. See sanitize() for why this matters.
_UNSAFE = re.compile(r"[^\x20-\x7e]")


def sanitize(raw: bytes) -> str:
    """Make untrusted banner bytes safe to print.

    A banner comes from a machine we don't control. A hostile service could
    send ANSI escape sequences (bytes starting with \\x1b) that clear your
    terminal, hide output or recolor text when printed. That is a real
    attack against security tools. So: decode leniently, turn every
    non-printable character into a space, collapse whitespace and truncate.

    Binary protocols (TLS, Nping echo, databases) reply with bytes that
    aren't text at all. If under 70% of the bytes are printable, we report
    the size instead of printing noise.
    """
    if raw:
        printable = sum(32 <= b < 127 or b in b"\r\n\t" for b in raw)
        if printable / len(raw) < 0.7:
            return f"<binary data, {len(raw)} bytes>"
    text = raw.decode("utf-8", errors="replace")
    text = _UNSAFE.sub(" ", text)
    text = " ".join(text.split())
    if len(text) > MAX_BANNER_CHARS:
        text = text[: MAX_BANNER_CHARS - 3] + "..."
    return text


def _http_summary(raw: bytes) -> bytes:
    """Reduce an HTTP response to its status line plus the Server header.

    A raw HTTP response is mostly noise (dates, cookies). The status line
    and the Server header, e.g. `Apache/2.4.7 (Ubuntu)`, are the useful
    parts for identification.
    """
    lines = raw.split(b"\r\n")
    server = next((l for l in lines if l.lower().startswith(b"server:")), b"")
    return lines[0] + (b" | " + server if server else b"")


def grab_banner(ip: str, port: int, timeout: float = DEFAULT_BANNER_TIMEOUT) -> str:
    """Connect to an open port and return its sanitized banner ('' if none)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            if port in HTTP_PORTS:
                # HEAD asks for headers only, no page body. HTTP/1.0 makes
                # the server close the connection after one response.
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            raw = _recv_some(sock)
            if not raw and port not in HTTP_PORTS:
                # Silent service on an unexpected port: nudge it with a
                # bare newline, which many line-based protocols answer.
                sock.sendall(b"\r\n")
                raw = _recv_some(sock)
    except OSError:
        return ""

    if raw.startswith(b"HTTP/"):
        raw = _http_summary(raw)
    return sanitize(raw)


def _recv_some(sock: socket.socket) -> bytes:
    """Read whatever arrives before the timeout; b'' if nothing does."""
    try:
        return sock.recv(MAX_BANNER_BYTES)
    except (socket.timeout, TimeoutError):
        return b""


def detect_service(port: int, banner: str) -> tuple[str, str]:
    """Identify the service. Returns (name, method).

    method is "banner" when a signature matched (strong evidence), or
    "port" when we fell back to the well-known port table (just a guess).
    """
    for pattern, name in SIGNATURES:
        if pattern.search(banner):
            return name, "banner"
    return COMMON_PORTS.get(port, "unknown"), "port"
