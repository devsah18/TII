"""Live packet capture using tshark.

Streams packets from a network interface, converts them to TRACE events and
feeds the SAME deterministic pipeline as uploaded logs. Because it reads a live
interface it requires tshark + Npcap and, on Windows, an elevated process. The
manager reports a clear reason if capture cannot start, so the UI can explain it.

Threading model: one background thread owns the tshark subprocess and reads its
stdout line by line. A rolling buffer of parsed packets is reclassified into
events periodically (not per-packet) to keep the CPU cost low, then any new
events are turned into an incident via the standard investigation service.
"""
from __future__ import annotations

import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

from ..engines import pcap

_FIELDS = pcap._FIELDS
_FLUSH_INTERVAL = 3.0
_MAX_BUFFER = 6000


class LiveCapture:
    """A single live-capture session."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen] = None
        self._running = False
        self._stop_flag = threading.Event()
        self._interface: Optional[str] = None
        self._bpf = ""
        self._started_at: Optional[float] = None
        self._packet_count = 0
        self._event_count = 0
        self._last_incident_id: Optional[str] = None
        self._last_error = ""
        self._buffer: List[Dict[str, Any]] = []
        self._seen: set = set()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = int(time.time() - self._started_at) if self._started_at else 0
            return {
                "running": self._running,
                "interface": self._interface,
                "bpf_filter": self._bpf,
                "packets": self._packet_count,
                "events": self._event_count,
                "elapsed_seconds": elapsed,
                "last_incident_id": self._last_incident_id,
                "last_error": self._last_error,
                "tshark_available": pcap.tshark_available(),
                "interfaces": pcap.list_interfaces(),
            }

    def start(self, interface: str, bpf_filter: str = "") -> Dict[str, Any]:
        with self._lock:
            if self._running:
                return {"ok": False, "error": "A capture is already running."}
            binary = pcap.find_tshark()
            if not binary:
                return {"ok": False, "error": "tshark was not found. Install Wireshark to enable live capture."}
            if not interface:
                return {"ok": False, "error": "No interface selected."}
            cmd = [binary, "-i", interface, "-l", "-T", "fields", "-E", "occurrence=f"]
            if bpf_filter.strip():
                cmd += ["-f", bpf_filter.strip()]
            for f in _FIELDS:
                cmd += ["-e", f]
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
                )
            except OSError as exc:
                return {"ok": False, "error": f"Could not start tshark: {exc}"}
            time.sleep(0.6)
            if proc.poll() is not None:
                err = ""
                try:
                    lines = (proc.stderr.read() or "").strip().splitlines()
                    err = lines[-1] if lines else ""
                except Exception:
                    err = ""
                return {"ok": False, "error": _humanize_capture_error(err)}
            self._proc = proc
            self._interface = interface
            self._bpf = bpf_filter.strip()
            self._running = True
            self._stop_flag.clear()
            self._started_at = time.time()
            self._packet_count = 0
            self._event_count = 0
            self._last_error = ""
            self._buffer = []
            self._seen = set()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            return {"ok": True, "interface": interface, "bpf_filter": self._bpf}

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            self._stop_flag.set()
            self._running = False
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                pass
        self._proc = None
        self._flush()
        with self._lock:
            return {"ok": True, "packets": self._packet_count, "events": self._event_count}

    def _run(self) -> None:
        proc = self._proc
        if not proc or not proc.stdout:
            return
        last_flush = time.time()
        try:
            for line in proc.stdout:
                if self._stop_flag.is_set():
                    break
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                for row in pcap._parse_rows(line):
                    with self._lock:
                        self._buffer.append(row)
                        self._packet_count += 1
                        if len(self._buffer) > _MAX_BUFFER:
                            self._buffer = self._buffer[-_MAX_BUFFER:]
                if time.time() - last_flush >= _FLUSH_INTERVAL:
                    self._flush()
                    last_flush = time.time()
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
        finally:
            self._flush()

    def _flush(self) -> None:
        with self._lock:
            rows = list(self._buffer)
            if not rows:
                return
        events = pcap._classify_packets(rows)
        fresh = []
        for ev in events:
            fp = f"{ev.get('event_type')}|{ev.get('source_ip')}|{ev.get('destination_ip')}|{ev.get('raw_message')}"
            if fp in self._seen:
                continue
            self._seen.add(fp)
            fresh.append(ev)
        if not fresh:
            return
        from . import investigation as investigation_service
        from ..utils.store import store
        for i, ev in enumerate(fresh):
            ev["id"] = f"LIVE-{int(time.time())}-{i:03d}"
            ev.pop("_seq", None)
        incident = investigation_service.analyze_events(
            fresh, source_file={"filename": f"live:{self._interface}", "scenario": "live_capture"}
        )
        incident["live"] = True
        incident["capture_interface"] = self._interface
        store.put_incident(incident)
        store.record_run(
            source="live",
            label=f"Live capture · {self._interface}",
            incident_id=incident["incident_id"],
            risk_score=incident.get("risk_score"),
            severity=incident.get("severity"),
            event_count=len(fresh),
            detection_count=incident.get("detection_count", 0),
            mitre_count=len(incident.get("mitre_techniques", [])),
            extra={"interface": self._interface, "bpf_filter": self._bpf, "packets": self._packet_count},
        )
        with self._lock:
            self._event_count += len(fresh)
            self._last_incident_id = incident["incident_id"]


def _humanize_capture_error(err: str) -> str:
    low = (err or "").lower()
    if "permission" in low or "access is denied" in low or "failed to set" in low:
        return (
            "Live capture needs elevated privileges. Restart the TRACE backend as "
            "Administrator (Npcap requires it) and try again."
        )
    if "no such device" in low or "invalid" in low:
        return "That capture interface could not be opened. Pick a different interface."
    if not err:
        return (
            "tshark exited immediately. This usually means the backend lacks packet-capture "
            "privileges - run it as Administrator."
        )
    return f"tshark could not start capture: {err}"


live_capture = LiveCapture()