#!/usr/bin/env python3
"""Generate a demo PCAP file (no external tools required).

Writes a valid libpcap file containing a synthetic attack pattern:
  * one external host probing many ports on an internal host (a port scan)
  * a later large outbound transfer to an external address

Run:  python backend/demo_logs/generate_pcap.py
Output: backend/demo_logs/demo_port_scan.pcap
"""
from __future__ import annotations

import struct
import time
from pathlib import Path

PCAP_MAGIC = 0xA1B2C3D4


def _pcap_header() -> bytes:
    return struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1)


def _record_header(ts: float, length: int) -> bytes:
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack("<IIII", sec, usec, length, length)


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    def _b(ip: str) -> bytes:
        return bytes(int(p) for p in ip.split("."))
    total = 20 + len(payload)
    ver_ihl = (4 << 4) | 5
    header = struct.pack(">BBHHHBBH4s4s", ver_ihl, 0, total, 0, 0, ttl, proto, 0, _b(src), _b(dst))
    chk = _ip_checksum(header)
    header = struct.pack(">BBHHHBBH4s4s", ver_ihl, 0, total, 0, 0, ttl, proto, chk, _b(src), _b(dst))
    return header + payload


def _tcp(sport: int, dport: int, seq: int = 1, ack: int = 0, flags: int = 0x02) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, 8192, 0, 0)


def _eth(payload: bytes) -> bytes:
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + payload


def _frame(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    return _eth(_ipv4(src, dst, 6, _tcp(sport, dport) + payload))


def main() -> None:
    attacker = "185.42.18.91"
    target = "10.0.0.22"
    exfil_dst = "45.133.216.77"
    now = time.time()
    frames: list[bytes] = []
    for i in range(40):
        frames.append(_frame(attacker, target, 40000 + i, 20 + i, b"scan"))
    # ~1.5 MB outbound FROM THE ATTACKER so the scan and the transfer correlate
    # into a single incident (same source IP) - a stronger end-to-end demo.
    for i in range(200):
        frames.append(_frame(attacker, exfil_dst, 50000, 443, b"X" * 8000))
    out = Path(__file__).resolve().parent / "demo_port_scan.pcap"
    with out.open("wb") as fh:
        fh.write(_pcap_header())
        t = now
        for fr in frames:
            t += 0.01
            fh.write(_record_header(t, len(fr)))
            fh.write(fr)
    print(f"wrote {out} ({len(frames)} packets)")


if __name__ == "__main__":
    main()