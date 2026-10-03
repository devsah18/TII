"""Correlation engine.

Groups individual detections that share a source IP, a username or a
destination into a single incident, so "17 failed logins + a success + sudo +
a database query" becomes ONE incident instead of four alerts.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .detection import max_severity
from .parser import is_private_ip

ENTITY_PRIORITY = ("source_ip", "username", "destination_ip")


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def correlate(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return incident clusters. Each cluster: {detections, entities, ...}."""
    if not detections:
        return []

    uf = _UnionFind(len(detections))
    buckets: Dict[str, int] = {}
    for idx, det in enumerate(detections):
        for field in ENTITY_PRIORITY:
            value = det.get(field)
            if not value:
                continue
            key = f"{field}:{value}"
            if key in buckets:
                uf.union(buckets[key], idx)
            else:
                buckets[key] = idx
        # detections that share a concrete event belong to the same incident even
        # when they carry no common entity field
        for eid in det.get("event_ids") or []:
            key = f"event:{eid}"
            if key in buckets:
                uf.union(buckets[key], idx)
            else:
                buckets[key] = idx

    clusters: Dict[int, List[Dict[str, Any]]] = {}
    for idx, det in enumerate(detections):
        clusters.setdefault(uf.find(idx), []).append(det)

    incidents: List[Dict[str, Any]] = []
    for members in clusters.values():
        ips = {d["source_ip"] for d in members if d.get("source_ip")}
        users = {d["username"] for d in members if d.get("username")}
        dests = {d["destination_ip"] for d in members if d.get("destination_ip")}
        event_ids = sorted({eid for d in members for eid in d["event_ids"]})
        firsts = [d["first_seen"] for d in members if d.get("first_seen")]
        lasts = [d["last_seen"] for d in members if d.get("last_seen")]
        types = [d["type"] for d in members]
        severity = "info"
        for d in members:
            severity = max_severity(severity, d["severity"])
        # A correlated cluster touches several addresses (attacker, auth host,
        # database). The headline source must be the external address that drove
        # the activity, not an internal host sorted first alphabetically.
        external_ips = sorted(ip for ip in ips if ip and not is_private_ip(ip))
        primary_ip = external_ips[0] if external_ips else (sorted(ips)[0] if ips else None)

        incidents.append(
            {
                "detections": sorted(members, key=lambda d: d["id"]),
                "detection_types": sorted(set(types)),
                "entities": {
                    "source_ips": sorted(ips),
                    "external_ips": external_ips,
                    "usernames": sorted(users),
                    "destinations": sorted(dests),
                },
                "source_ip": primary_ip,
                "username": sorted(users)[0] if len(users) == 1 else None,
                "affected_users": sorted(users),
                "event_ids": event_ids,
                "first_seen": min(firsts) if firsts else None,
                "last_seen": max(lasts) if lasts else None,
                "severity": severity,
            }
        )

    # strongest chain first
    def _weight(inc: Dict[str, Any]) -> Any:
        order = ["reconnaissance", "brute_force", "account_compromise",
                 "privilege_escalation", "sensitive_data_access", "data_exfiltration"]
        score = sum(10 - order.index(t) for t in inc["detection_types"] if t in order)
        return (-score, inc["first_seen"] or "")

    incidents.sort(key=_weight)
    return incidents
