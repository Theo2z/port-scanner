# portscanner

A multithreaded TCP port scanner written from scratch in Python, using only the standard library.

> **Status:** in development. Features are added in phases (see the roadmap below).

## ⚠️ Legal and ethical use

Only scan systems you own or have **explicit written permission** to test.
Unauthorized port scanning can break laws such as the U.S. Computer Fraud and Abuse Act or the UK Computer Misuse Act, and it can break your ISP's or cloud provider's terms of service.

This project is tested only against:

- `localhost` / `127.0.0.1`
- `scanme.nmap.org`, which the Nmap project provides for this purpose (scan it lightly; don't hammer it)

## Roadmap

- [x] Phase 1: Core. TCP connect scan of one host with a configurable timeout
- [ ] Phase 2: Speed. Worker-pool threading and benchmarks
- [ ] Phase 3: Intel. Banner grabbing and basic service detection
- [ ] Phase 4: CLI. Targets as IP, hostname or CIDR; port ranges; threads; timeout
- [ ] Phase 5: Output. Terminal table, CSV and JSON export
- [ ] Phase 6: Polish. Error handling, pytest suite and full docs

## Development setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux
pip install -e ".[dev]"
```

## License

MIT
