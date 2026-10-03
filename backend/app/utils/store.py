"""In-memory stores.

The MVP keeps everything in process memory on purpose (section 26 of the spec):
no Redis, no broker, no database. Logs are not persisted to disk, which also
keeps sensitive sample data from lingering after the demo.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional


class TraceStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._files: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._incidents: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._file_seq = 0
        self._incident_seq = 0
        self._activity: List[Dict[str, Any]] = []
        self._alerts: List[Dict[str, Any]] = []
        self._alert_seq = 0

    # -- ids ------------------------------------------------------------------
    def next_file_id(self, prefix: str = "FILE") -> str:
        with self._lock:
            self._file_seq += 1
            return f"{prefix}-{self._file_seq:03d}"

    def next_incident_id(self) -> str:
        with self._lock:
            self._incident_seq += 1
            return f"INC-{self._incident_seq:03d}"

    # -- files ----------------------------------------------------------------
    def put_file(self, file_id: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._files[file_id] = payload

    def get_file(self, file_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._files.get(file_id)

    def total_file_events(self) -> int:
        """Total number of events parsed across every tracked file."""
        with self._lock:
            return sum(len(f.get("events") or []) for f in self._files.values())

    # -- incidents ------------------------------------------------------------
    def put_incident(self, incident: Dict[str, Any]) -> None:
        # Enrich with spec-shaped alias fields (evidence, timeline_spec,
        # risk_breakdown, mitre, recommended_actions, ...) at this single choke
        # point so every incident returned or stored carries the contract fields.
        try:
            from ..services.spec_view import add_spec_fields

            add_spec_fields(incident)
        except Exception:
            # Never let enrichment break incident storage.
            pass
        with self._lock:
            self._incidents[incident["incident_id"]] = incident

        # Emit live alerts for this incident (one per detection + a headline).
        # Done outside the lock to keep push_alert's own locking re-entrant-safe.
        try:
            self._emit_alerts_for(incident)
        except Exception:
            pass

    def _emit_alerts_for(self, incident: Dict[str, Any]) -> None:
        iid = incident.get("incident_id")
        src = incident.get("source_ip")
        self.push_alert(
            level=incident.get("severity", "info"),
            title=incident.get("title") or "Incident reconstructed",
            detail=(
                f"{incident.get('detection_count', 0)} detection(s), risk "
                f"{incident.get('risk_score', 0)}/100"
            ),
            incident_id=iid,
            source_ip=src,
            meta={"kind": "incident", "risk_score": incident.get("risk_score")},
        )
        for d in incident.get("detections", []):
            self.push_alert(
                level=d.get("severity", "info"),
                title=d.get("title") or d.get("type", "Detection"),
                detail=d.get("description", ""),
                incident_id=iid,
                source_ip=d.get("source_ip") or src,
                meta={"kind": "detection", "detection_type": d.get("type")},
            )

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._incidents.get(incident_id)

    def list_incidents(self, newest_first: bool = True) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._incidents.values())
        return list(reversed(items)) if newest_first else items

    # -- activity feed --------------------------------------------------------
    def log_activity(self, kind: str, message: str, meta: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            self._activity.append(
                {
                    "kind": kind,
                    "message": message,
                    "meta": meta or {},
                    "at": _utcnow_iso(),
                }
            )
            self._activity = self._activity[-40:]

    def activity(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(reversed(self._activity))

    # -- live alerts ----------------------------------------------------------
    def push_alert(
        self,
        *,
        level: str,
        title: str,
        detail: str = "",
        incident_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            self._alert_seq += 1
            alert = {
                "id": f"ALR-{self._alert_seq:04d}",
                "level": level,  # critical | high | medium | low | info
                "title": title,
                "detail": detail,
                "incident_id": incident_id,
                "source_ip": source_ip,
                "meta": meta or {},
                "at": _utcnow_iso(),
                "acknowledged": False,
            }
            self._alerts.append(alert)
            self._alerts = self._alerts[-100:]
            return alert

    def alerts(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._lock:
            return list(reversed(self._alerts))[:limit]

    def acknowledge_alert(self, alert_id: str) -> bool:
        with self._lock:
            for a in self._alerts:
                if a["id"] == alert_id:
                    a["acknowledged"] = True
                    return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._files.clear()
            self._incidents.clear()
            self._activity.clear()
            self._alerts.clear()
            self._file_seq = 0
            self._incident_seq = 0
            self._alert_seq = 0


def _utcnow_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


store = TraceStore()
