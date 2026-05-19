# vtScanner

A Python-based network monitoring tool that maps active connections to their processes and checks remote IPs against [VirusTotal](https://www.virustotal.com) for known threats.

Built as a portfolio project while studying for SOC analyst roles.

---

## What it does

- Enumerates all active network connections using `psutil`
- Filters to public IPs only (ignores loopback, private, and link-local)
- Maps each connection to its process name, PID, and a SHA-256 hash of the process executable
- Queries VirusTotal for each remote IP and flags anything with a malicious or suspicious detection
- Supports one-shot mode or continuous monitoring with desktop alerts for new threats

---

## Requirements

- Python 3.10+
- A [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) (free tier works)
- `notify-send` for desktop alerts (optional, Linux only)

Install dependencies:
```bash
pip install psutil vt-py
```

---

## Setup

Export your VirusTotal API key before running:
```bash
export VT_API_KEY=your_api_key_here
```

---

## Usage

**One-shot scan:**
```bash
python3 vtScanner.py
```

**Continuous monitoring (default 60s interval):**
```bash
python3 vtScanner.py --monitor
```

**Custom interval:**
```bash
python3 vtScanner.py --monitor --interval 30
```

If `VT_API_KEY` is not set, the tool will still run and display active connections — just without VirusTotal lookups.

---

## Example output

```
--- scan 2026-05-19 14:32:01 ---
203.0.113.42  [ALERT] 12 malicious, 3 suspicious / 90
  pid=3821  proc=curl  hash=a3f1...
  TCP/IPv4  ESTABLISHED  local=('192.168.1.5', 52100)  remote=('203.0.113.42', 443)

142.250.80.14  [OK] 0 malicious, 0 suspicious / 90
  pid=1042  proc=chrome  hash=9c2d...
  TCP/IPv4  ESTABLISHED  local=('192.168.1.5', 51888)  remote=('142.250.80.14', 443)
```

Desktop alerts fire via `notify-send` when a new suspicious IP is detected in monitor mode.

---

## Notes

- Run with `sudo` if some connections show no process info (some sockets require elevated permissions to inspect)
- VirusTotal free tier allows 4 lookups/minute — lower `--interval` values may hit rate limits
- The tool only alerts once per suspicious IP per session, so repeated polls won't spam notifications
