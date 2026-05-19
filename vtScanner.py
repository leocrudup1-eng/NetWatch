#!/usr/bin/env python3
"""
vtScanner.py — checks active network connections against VirusTotal.
Run with: python3 vtScanner.py
"""

import os
import ipaddress
import hashlib
import psutil
import vt

VT_API_KEY = os.getenv("VT_API_KEY")
VT_THRESHOLD = 1
SHOW_ALL = True


def is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local)
    except ValueError:
        return False


def collect_connections(kind: str = "inet"):
    try:
        return psutil.net_connections(kind=kind)
    except Exception:
        return []


def ip_to_proc_map(conns: list) -> dict:
    result = {}
    for c in conns:
        if not c.raddr:
            continue
        rip = getattr(c.raddr, "ip", None)
        if not rip or not is_public_ip(rip):
            continue

        protocol = "IPv6" if c.family.name.endswith("6") else "IPv4"
        transport = "TCP" if c.type.name == "SOCK_STREAM" else "UDP"

        name = None
        exe = None
        exe_hash = None
        if c.pid is not None:
            try:
                proc = psutil.Process(c.pid)
                name = proc.name()
                exe = proc.exe()
                exe_hash = get_sha256_hash(exe)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        record = {
            "pid": c.pid,
            "name": name,
            "exe_hash": exe_hash,
            "laddr": (c.laddr.ip, c.laddr.port) if c.laddr else None,
            "raddr": (c.raddr.ip, c.raddr.port) if c.raddr else None,
            "status": getattr(c, "status", None),
            "protocol": protocol,
            "transport": transport,
        }
        result.setdefault(rip, []).append(record)
    return result


def get_sha256_hash(path: str, block_size: int = 65536) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(block_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def vt_lookup(client: vt.Client, endpoint: str) -> tuple[bool, str]:
    try:
        obj = client.get_object(endpoint)
        attrs = obj.to_dict().get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())
        is_bad = (malicious + suspicious) >= VT_THRESHOLD
        if is_bad:
            return True, f"[ALERT] {malicious} malicious, {suspicious} suspicious / {total}"
        return False, f"[OK] {malicious} malicious, {suspicious} suspicious / {total}"
    except vt.error.APIError as e:
        return False, f"VT API error: {e.code} {e.message}"
    except Exception as e:
        return False, f"VT error: {e}"


def vt_lookup_ip(client: vt.Client, ip: str) -> tuple[bool, str]:
    return vt_lookup(client, f"/ip_addresses/{ip}")


def vt_lookup_hash(client: vt.Client, file_hash: str) -> tuple[bool, str]:
    return vt_lookup(client, f"/files/{file_hash}")


def scan(client: vt.Client | None) -> int:
    conns = collect_connections()
    ip_map = ip_to_proc_map(conns)

    if not ip_map:
        print("No public remote connections found.")
        return 0

    suspicious_count = 0
    for ip, records in ip_map.items():
        is_bad, msg = vt_lookup_ip(client, ip) if client else (False, "(no VT lookup)")

        if is_bad or SHOW_ALL:
            print(f"{ip}  {msg}")
            for rec in records:
                print(
                    f"  pid={rec['pid']}  proc={rec['name']}  hash={rec['exe_hash']}\n"
                    f"  {rec['transport']}/{rec['protocol']}  {rec['status']}  "
                    f"local={rec['laddr']}  remote={rec['raddr']}"
                )
            print()

        if is_bad:
            suspicious_count += 1

    return suspicious_count


def main():
    if not VT_API_KEY:
        print("Warning: VT_API_KEY not set. Only showing IPs and processes.\n")
        suspicious_count = scan(None)
    else:
        with vt.Client(VT_API_KEY) as client:
            suspicious_count = scan(client)

    if not SHOW_ALL:
        if suspicious_count == 0:
            print("No suspicious IPs found.")
        else:
            print(f"Total suspicious IPs: {suspicious_count}")


if __name__ == "__main__":
    main()
