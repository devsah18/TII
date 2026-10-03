"""PCAP / PCAPNG ingestion.

TRACE reads packet captures by shelling out to **tshark** (Wireshark's CLI) in
FILE mode - never live capture, so no Administrator rights are required and the
result is fully deterministic and repeatable.

Each capture is converted into the SAME normalized event schema the log parser
produces, so detection, correlation, risk, MITRE and the attack graph all work
unchanged. Packet captures primarily surface network-layer behaviour:

  * many distinct ports from one source in a short window -> "reconnaissance"
  * large outbound transfers to an external host          -> "data_transfer"
  * any external conversation                             -> "network_connection"

The engine validates that tshark exists, runs with a hard timeout, and degrades
gracefully with a clear message if it is not installed.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .parser import ParseError, _build_event, is_private_ip

PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

_TSHARK_CANDIDATES = (
    "tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
    "/opt/homebrew/bin/tshark",
)

MAX_PCAP_EVENTS = 20000

_FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "_ws.col.Protocol",
)


def find_tshark() -> Optional[str]:
    """Return a usable tshark path, or None if it is not installed."""
    for cand in _TSHARK_CANDIDATES:
        if os.path.sep in cand or cand.lower().endswith(".exe"):
            if Path(cand).exists():
                return cand
        found = shutil.which(cand)
        if found:
            return found
    return None


def tshark_available() -> bool:
    return find_tshark() is not None


def list_interfaces() -> List[Dict[str, str]]:
    """Return the capture interfaces tshark can see.

    Output of `tshark -D` looks like:
        "1. \\Device\\NPF_{GUID} (Wi-Fi)"
    We parse the index, the device name and the friendly label.
    """
    binary = find_tshark()
    if not binary:
        return []
    try:
        proc = subprocess.run([binary, "-D"], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    interfaces: List[Dict[str, str]] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line or "." not in line:
            continue
        idx, _, rest = line.partition(".")
        rest = rest.strip()
        name = rest
        label = ""
        if rest.endswith(")") and "(" in rest:
            name, _, label = rest.rpartition("(")
            name = name.strip()
            label = label[:-1].strip()
        interfaces.append({"index": idx.strip(), "name": name, "label": label or name})
    return interfaces


def _run_tshark(pcap_path: str, timeout: int = 60) -> str:
    """Run tshark in field mode and return its stdout as text."""
    binary = find_tshark()
    if not binary:
        raise ParseError(
            "PCAP support requires Wireshark's tshark, which was not found. "
            "Install Wireshark and retry."
        )
    cmd = [binary, "-r", pcap_path, "-T", "fields", "-E", "occurrence=f"]
    for f in _FIELDS:
        cmd += ["-e", f]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ParseError("Timed out while reading the capture file.")
    except OSError as exc:
        raise ParseError(f"Could not run tshark: {exc}")
    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or "").strip().splitlines()
        raise ParseError(f"tshark could not read this capture: {err[-1] if err else 'unknown error'}")
    return proc.stdout


def _epoch_to_iso(raw: str) -> Optional[str]:
    try:
        return datetime.fromtimestamp(float(raw), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None


def _parse_rows(stdout: str) -> List[Dict[str, Any]]:
    """Turn tshark field output into lightweight packet records."""
    rows: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        parts += [""] * (len(_FIELDS) - len(parts))
        (t, ip_src, ip_dst, v6_src, v6_dst, t_src, t_dst, u_src, u_dst, length, proto) = parts[:11]
        try:
            frame_len = int(length)
        except (TypeError, ValueError):
            frame_len = 0
        rows.append(
            {
                "timestamp": _epoch_to_iso(t),
                "src": ip_src or v6_src,
                "dst": ip_dst or v6_dst,
                "sport": t_src or u_src,
                "dport": t_dst or u_dst,
                "length": frame_len,
                "proto": (proto or "").upper(),
            }
        )
    return rows


def _classify_packets(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse raw packets into TRACE events.

    Aggregating keeps the event count meaningful (a scan of 200 ports becomes
    ONE reconnaissance event) and avoids flooding the pipeline with noise.
    """
    events: List[Dict[str, Any]] = []

    # --- 1. reconnaissance: one source touching many distinct ports ----------
    ports_by_src: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        src, dport = r.get("src"), r.get("dport")
        if not src or not dport:
            continue
        b = ports_by_src.setdefault(
            src, {"ports": set(), "dst": set(), "first": r["timestamp"], "last": r["timestamp"], "count": 0}
        )
        b["ports"].add(dport)
        if r.get("dst"):
            b["dst"].add(r["dst"])
        b["last"] = r["timestamp"] or b["last"]
        b["count"] += 1

    for src, b in ports_by_src.items():
        distinct = len(b["ports"])
        if distinct >= 10:
            targets = ", ".join(sorted(b["dst"])[:3]) or "the network"
            events.append(
                _build_event(
                    timestamp=b["first"],
                    source_ip=src,
                    destination_ip=sorted(b["dst"])[0] if b["dst"] else None,
                    username=None,
                    event_type="reconnaissance",
                    action="network_discovery",
                    status="unknown",
                    source="pcap",
                    raw_message=(
                        f"Port scan: {src} probed {distinct} distinct ports on {targets} "
                        f"({b['count']} packets)"
                    ),
                    seq=len(events),
                    extra={"distinct_ports": distinct, "packets": b["count"], "transport": "tcp/udp"},
                )
            )

    # --- 2. large outbound transfers to external hosts -----------------------
    flows: Dict[tuple, Dict[str, Any]] = {}
    for r in rows:
        src, dst = r.get("src"), r.get("dst")
        if not src or not dst:
            continue
        f = flows.setdefault((src, dst), {"bytes": 0, "first": r["timestamp"], "packets": 0, "proto": r["proto"]})
        f["bytes"] += r["length"]
        f["packets"] += 1
        f["last"] = r["timestamp"] or f["first"]

    for (src, dst), f in flows.items():
        if f["bytes"] >= 1024 * 1024 and not is_private_ip(dst):
            events.append(
                _build_event(
                    timestamp=f["first"],
                    source_ip=src,
                    destination_ip=dst,
                    username=None,
                    event_type="data_transfer",
                    action="network_transfer",
                    status="success",
                    source="pcap",
                    raw_message=(
                        f"Outbound transfer: {src} -> {dst} {f['bytes'] / (1024 * 1024):.1f} MB "
                        f"across {f['packets']} packets ({f['proto']})"
                    ),
                    seq=len(events),
                    extra={"bytes": f["bytes"], "packets": f["packets"], "transport": f["proto"]},
                )
            )

    # --- 3. external conversations as context --------------------------------
    ext_flows = sorted(
        {(r["src"], r["dst"]) for r in rows if r.get("src") and r.get("dst")
         and (not is_private_ip(r["src"]) or not is_private_ip(r["dst"]))}
    )
    for src, dst in ext_flows[:40]:
        events.append(
            _build_event(
                timestamp=next((r["timestamp"] for r in rows if r["src"] == src and r["dst"] == dst), None),
                source_ip=src,
                destination_ip=dst,
                username=None,
                event_type="network_connection",
                action="network",
                status="success",
                source="pcap",
                raw_message=f"Network conversation observed: {src} <-> {dst}",
                seq=len(events),
                extra={"external": (not is_private_ip(src)) or (not is_private_ip(dst))},
            )
        )

    return events


def parse_pcap_bytes(content: bytes, filename: str = "capture.pcap") -> List[Dict[str, Any]]:
    """Parse a packet capture into normalized TRACE events.

    Writes the bytes to a temporary file (tshark reads from disk), runs tshark,
    converts the output, then removes the temp file. Nothing is persisted.
    """
    suffix = Path(filename).suffix or ".pcap"
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    try:
        tmp.write(content)
        tmp.flush()
        tmp.close()
        stdout = _run_tshark(tmp.name)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    rows = _parse_rows(stdout)
    if not rows:
        raise ParseError("The capture file contained no readable IP packets.")

    events = _classify_packets(rows)
    if not events:
        first = rows[0]
        events = [
            _build_event(
                timestamp=first.get("timestamp"),
                source_ip=first.get("src"),
                destination_ip=first.get("dst"),
                username=None,
                event_type="network_connection",
                action="network",
                status="success",
                source="pcap",
                raw_message=f"Capture parsed: {len(rows)} packet(s), no anomalous network behaviour detected.",
                seq=0,
                extra={"packets": len(rows)},
            )
        ]

    if len(events) > MAX_PCAP_EVENTS:
        events = events[:MAX_PCAP_EVENTS]
    for i, ev in enumerate(events):
        ev["id"] = f"PCAP-{i + 1:04d}"
        ev.pop("_seq", None)
    return events