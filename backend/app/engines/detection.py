"""Deterministic detection engine.

Rules are plain Python: no LLM is involved in deciding whether something is
suspicious. Every detection carries a type, severity, confidence and the
evidence strings that justify it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

BRUTE_FORCE_MIN_FAILURES = 5
BRUTE_FORCE_WINDOW_MIN = 15
SUCCESS_WINDOW_MIN = 120
MIN_FAILURES_FOR_COMPROMISE = 3
EXFIL_BYTES_THRESHOLD = 5 * 1024 * 1024

SENSITIVE_KEYWORDS = (
    "customer", "payment", "card_token", "pii", "confidential", "credentials",
    "credential", "secret", "shadow", "keyvault", "select * from", "dump",
    "exfiltrat", "bulk download", "sensitive=true",
)

# Clearly routine operations that must NOT be treated as sensitive data access.
ROUTINE_SUPPRESSORS = ("routine", "metrics_db", "health_check", "duration=", "stats query")

# Fallback for "failures then success" when the source IP differs between them.
FALLBACK_MIN_FAILURES = 5

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _dt(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def _time_range(events: List[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str]]:
    stamps = [e["timestamp"] for e in events if e.get("timestamp")]
    if not stamps:
        return None, None
    return min(stamps), max(stamps)


def _cluster(events: List[Dict[str, Any]], window_min: int) -> List[Dict[str, Any]]:
    """Largest burst of events inside a sliding time window."""
    stamped = [e for e in events if e.get("timestamp")]
    if not stamped:
        return list(events)
    stamped.sort(key=lambda e: e["timestamp"])
    best: List[Dict[str, Any]] = []
    start = 0
    for end in range(len(stamped)):
        end_dt = _dt(stamped[end]["timestamp"])
        while start < end:
            s = _dt(stamped[start]["timestamp"])
            if end_dt and s and (end_dt - s) > timedelta(minutes=window_min):
                start += 1
            else:
                break
        window = stamped[start:end + 1]
        if len(window) > len(best):
            best = window
    return best


def _display_time(ts: Optional[str]) -> str:
    dt = _dt(ts)
    return dt.strftime("%H:%M:%S") if dt else "unknown time"


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------
def _rule_brute_force(events: List[Dict[str, Any]], thresholds: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    thresholds = thresholds or {}
    min_failures = int(thresholds.get("brute_force_min_failures", BRUTE_FORCE_MIN_FAILURES))
    window_min = int(thresholds.get("brute_force_window_min", BRUTE_FORCE_WINDOW_MIN))
    out: List[Dict[str, Any]] = []
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for ev in events:
        if ev["event_type"] != "login_failed":
            continue
        key = (ev.get("source_ip") or "unknown-source", ev.get("username") or "unknown-user")
        groups.setdefault(key, []).append(ev)

    for (ip, user), items in groups.items():
        burst = _cluster(items, window_min)
        if len(burst) < min_failures:
            continue
        n = len(burst)
        first, last = _time_range(burst)
        severity = "high" if n >= 10 else "medium"
        confidence = round(min(0.94, 0.60 + 0.04 * n), 2)
        distinct_users = {i.get("username") for i in items if i.get("username")}
        spray = len(distinct_users) > 1
        out.append(
            {
                "type": "brute_force",
                "title": "Password Spraying Against Multiple Accounts" if spray else "Brute Force Authentication Attempts",
                "severity": severity,
                "confidence": confidence,
                "description": (
                    f"{n} failed authentication attempts targeted "
                    f"{'multiple accounts' if spray else f'account {user!r}'} from {ip} "
                    f"within a {BRUTE_FORCE_WINDOW_MIN}-minute window."
                ),
                "evidence": [
                    f"{n} failed authentication attempts from {ip}",
                    f"Target account: {user}" if not spray else f"Target accounts: {', '.join(sorted(distinct_users))}",
                    f"Observed between {_display_time(first)} and {_display_time(last)} UTC",
                ],
                "event_ids": [e["id"] for e in burst],
                "source_ip": ip if ip != "unknown-source" else None,
                "username": None if spray else user,
                "first_seen": first,
                "last_seen": last,
            }
        )

    # spray: same IP against many users, each with fewer failures
    by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        if ev["event_type"] == "login_failed" and ev.get("source_ip"):
            by_ip.setdefault(ev["source_ip"], []).append(ev)
    for ip, items in by_ip.items():
        users = {i.get("username") for i in items if i.get("username")}
        if len(users) >= 3 and len(items) >= min_failures:
            if any(d["source_ip"] == ip and d["type"] == "brute_force" for d in out):
                continue
            first, last = _time_range(items)
            out.append(
                {
                    "type": "brute_force",
                    "title": "Password Spraying Across Accounts",
                    "severity": "high",
                    "confidence": 0.82,
                    "description": (
                        f"{len(items)} failed logins from {ip} spread across {len(users)} accounts, "
                        "consistent with password spraying."
                    ),
                    "evidence": [
                        f"{len(items)} failed logins from {ip}",
                        f"{len(users)} distinct accounts targeted: {', '.join(sorted(u for u in users if u))}",
                    ],
                    "event_ids": [e["id"] for e in items],
                    "source_ip": ip,
                    "username": None,
                    "first_seen": first,
                    "last_seen": last,
                }
            )
    return out


def _rule_account_compromise(events: List[Dict[str, Any]], brute: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    failures = [e for e in events if e["event_type"] == "login_failed"]
    successes = [e for e in events if e["event_type"] == "login_success"]

    for suc in successes:
        ip = suc.get("source_ip")
        user = suc.get("username")
        if not user:
            continue
        recent = [
            f for f in failures
            if f.get("username") == user
            and (not ip or f.get("source_ip") == ip)
            and _within(f, suc, SUCCESS_WINDOW_MIN)
        ]
        same_user_any_ip = [f for f in failures if f.get("username") == user and _within(f, suc, 10)]
        if len(recent) >= MIN_FAILURES_FOR_COMPROMISE:
            candidates = recent
        elif len(same_user_any_ip) >= FALLBACK_MIN_FAILURES:
            candidates = same_user_any_ip
        else:
            continue

        n = len(candidates)
        first, last = _time_range(candidates + [suc])
        strong = bool(ip) and n >= 10
        confidence = 0.94 if strong else (0.87 if n >= 5 else 0.78)
        out.append(
            {
                "type": "account_compromise",
                "title": "Successful Login After Repeated Failures",
                "severity": "critical",
                "confidence": confidence,
                "description": (
                    f"Account {user!r} authenticated successfully after {n} failed attempts"
                    + (f" from the same source IP {ip}." if ip else " from the same source.")
                ),
                "evidence": [
                    f"{n} failed authentication attempts for {user!r}",
                    f"Successful authentication at {_display_time(suc.get('timestamp'))} UTC",
                    f"Source IP {ip} used for both the failures and the success" if ip else "Failures and success share the same account",
                ],
                "event_ids": [e["id"] for e in candidates] + [suc["id"]],
                "source_ip": ip,
                "username": user,
                "first_seen": first,
                "last_seen": last,
                "success_event_id": suc["id"],
            }
        )
    return out


def _within(a: Dict[str, Any], b: Dict[str, Any], minutes: int) -> bool:
    a_dt, b_dt = _dt(a.get("timestamp")), _dt(b.get("timestamp"))
    if not a_dt or not b_dt:
        return True  # no timestamps: treat the file as one session
    delta = (b_dt - a_dt).total_seconds() / 60.0
    return -1.0 <= delta <= minutes


def _rule_privilege_escalation(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits = [e for e in events if e["event_type"] == "privilege_escalation"]
    if not hits:
        return []
    first, last = _time_range(hits)
    users = sorted({e.get("username") for e in hits if e.get("username")})
    commands = []
    for e in hits:
        cmd = (e.get("extra") or {}).get("command") if isinstance(e.get("extra"), dict) else None
        if cmd:
            commands.append(str(cmd))
    evidence = [
        f"{len(hits)} privilege-related event(s) detected",
        f"Affected account(s): {', '.join(users)}" if users else "Privilege escalation activity observed",
    ]
    evidence += [f"Command: {c}" for c in commands[:3]]
    return [
        {
            "type": "privilege_escalation",
            "title": "Privilege Escalation Activity",
            "severity": "high",
            "confidence": 0.90 if len(hits) == 1 else 0.93,
            "description": (
                "Elevation to administrative or root privileges was observed"
                + (f" for account(s) {', '.join(users)}." if users else ".")
            ),
            "evidence": evidence,
            "event_ids": [e["id"] for e in hits],
            "source_ip": next((e.get("source_ip") for e in hits if e.get("source_ip")), None),
            "username": users[0] if len(users) == 1 else None,
            "first_seen": first,
            "last_seen": last,
        }
    ]


def _rule_sensitive_data_access(
    events: List[Dict[str, Any]], compromised_users: set[str]
) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for ev in events:
        if ev["event_type"] not in ("database_access", "file_access", "data_transfer"):
            continue
        text = " ".join(
            [
                str(ev.get("raw_message") or ""),
                " ".join(f"{k}={v}" for k, v in (ev.get("extra") or {}).items()),
            ]
        ).lower()
        if any(k in text for k in ROUTINE_SUPPRESSORS):
            continue
        if any(k in text for k in SENSITIVE_KEYWORDS):
            hits.append(ev)
    if not hits:
        return []
    first, last = _time_range(hits)
    users = sorted({e.get("username") for e in hits if e.get("username")})
    elevated = bool(users and compromised_users.intersection(users))
    resources = sorted(
        {
            str((e.get("extra") or {}).get("db") or (e.get("extra") or {}).get("file") or "")
            for e in hits
        }
        - {""}
    )
    evidence = [f"{len(hits)} access event(s) to sensitive resources"]
    if resources:
        evidence.append(f"Resources touched: {', '.join(resources[:4])}")
    if users:
        evidence.append(f"Accounts involved: {', '.join(users)}")
    if elevated:
        evidence.append("Access performed by an account that was just compromised")
    return [
        {
            "type": "sensitive_data_access",
            "title": "Sensitive Data Access",
            "severity": "critical" if elevated else "high",
            "confidence": 0.92 if elevated else 0.86,
            "description": (
                "Access to sensitive or confidential data was detected"
                + (" by an account with signs of compromise." if elevated else ".")
            ),
            "evidence": evidence,
            "event_ids": [e["id"] for e in hits],
            "source_ip": next((e.get("source_ip") for e in hits if e.get("source_ip")), None),
            "username": users[0] if len(users) == 1 else None,
            "first_seen": first,
            "last_seen": last,
        }
    ]


def _rule_reconnaissance(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits = [e for e in events if e["event_type"] == "reconnaissance"]
    if not hits:
        return []
    first, last = _time_range(hits)
    ips = sorted({e.get("source_ip") for e in hits if e.get("source_ip")})
    return [
        {
            "type": "reconnaissance",
            "title": "Reconnaissance / Service Scanning",
            "severity": "medium",
            "confidence": 0.72,
            "description": "Scanning or enumeration activity preceded the authentication attempts.",
            "evidence": [f"{len(hits)} reconnaissance event(s)"] + ([f"Scanning source: {', '.join(ips)}"] if ips else []),
            "event_ids": [e["id"] for e in hits],
            "source_ip": ips[0] if ips else None,
            "username": None,
            "first_seen": first,
            "last_seen": last,
        }
    ]


def _rule_exfiltration(events: List[Dict[str, Any]], thresholds: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    thresholds = thresholds or {}
    exfil_bytes = int(thresholds.get("exfil_bytes_threshold", EXFIL_BYTES_THRESHOLD))
    hits = []
    for ev in events:
        if ev["event_type"] != "data_transfer":
            continue
        # Bytes may be nested under "extra" or flattened to the top level,
        # depending on how the event was built. Check both.
        extra = ev.get("extra") or {}
        raw_bytes = extra.get("bytes", ev.get("bytes"))
        try:
            size = int(raw_bytes or 0)
        except (TypeError, ValueError):
            size = 0
        text = str(ev.get("raw_message") or "").lower()
        external_dst = bool(ev.get("destination_ip")) and not _is_private(ev.get("destination_ip"))
        flagged = (
            size >= exfil_bytes
            or (external_dst and size >= 1024 * 1024)
            or "bulk" in text
            or "exfiltrat" in text
        )
        if flagged:
            hits.append((ev, size))
    if not hits:
        return []
    first, last = _time_range([h[0] for h in hits])
    total = sum(h[1] for h in hits)
    dsts = sorted({h[0].get("destination_ip") for h in hits if h[0].get("destination_ip")})
    evidence = [f"{len(hits)} bulk data transfer event(s)"]
    if total:
        evidence.append(f"{total / (1024 * 1024):.1f} MB transferred outbound")
    if dsts:
        evidence.append(f"External destination(s): {', '.join(dsts)}")
    return [
        {
            "type": "data_exfiltration",
            "title": "Potential Data Exfiltration",
            "severity": "critical",
            "confidence": 0.88,
            "description": "Large or externally directed data transfers suggest data leaving the environment.",
            "evidence": evidence,
            "event_ids": [h[0]["id"] for h in hits],
            "source_ip": next((h[0].get("source_ip") for h in hits if h[0].get("source_ip")), None),
            "username": next((h[0].get("username") for h in hits if h[0].get("username")), None),
            "first_seen": first,
            "last_seen": last,
        }
    ]


def _is_private(ip: Optional[str]) -> bool:
    from .parser import is_private_ip

    return is_private_ip(ip)


def detect(events: List[Dict[str, Any]], thresholds: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Run every rule and return the ordered list of detections.

    ``thresholds`` optionally overrides tuning constants, e.g.
    ``{"brute_force_min_failures": 3, "brute_force_window_min": 10}``. When
    omitted the module defaults apply, so existing callers are unaffected.
    """
    detections: List[Dict[str, Any]] = []

    brute = _rule_brute_force(events, thresholds)
    compromise = _rule_account_compromise(events, brute)
    priv = _rule_privilege_escalation(events)
    compromised_users = {d["username"] for d in (compromise or []) if d.get("username")}
    sensitive = _rule_sensitive_data_access(events, compromised_users)
    recon = _rule_reconnaissance(events)
    exfil = _rule_exfiltration(events, thresholds)

    order = ["reconnaissance", "brute_force", "account_compromise", "privilege_escalation",
             "sensitive_data_access", "data_exfiltration"]
    detections = brute + compromise + priv + sensitive + recon + exfil
    detections.sort(key=lambda d: (order.index(d["type"]) if d["type"] in order else 99,
                                   d.get("first_seen") or ""))

    # suspicious external source IP (risk factor + IOC)
    anomalous_ips: Dict[str, str] = {}
    for d in detections:
        ip = d.get("source_ip")
        if ip and not _is_private(ip):
            anomalous_ips[ip] = max_severity(anomalous_ips.get(ip, "low"), d["severity"])
    for ip, sev in anomalous_ips.items():
        related = [d for d in detections if d.get("source_ip") == ip]
        ev_ids = sorted({eid for d in related for eid in d["event_ids"]})
        detections.append(
            {
                "type": "suspicious_source_ip",
                "title": "External Source IP Driving Malicious Activity",
                "severity": sev if sev in ("high", "critical") else "medium",
                "confidence": 0.78,
                "description": f"External address {ip} is the origin of the detected malicious activity.",
                "evidence": [
                    f"{ip} is an external (non-RFC1918) address",
                    f"Linked to {len(related)} detection(s): {', '.join(sorted({d['type'] for d in related}))}",
                ],
                "event_ids": ev_ids,
                "source_ip": ip,
                "username": None,
                "first_seen": min([d.get("first_seen") for d in related if d.get("first_seen")] or [None]),
                "last_seen": max([d.get("last_seen") for d in related if d.get("last_seen")] or [None]),
            }
        )

    for idx, det in enumerate(detections):
        det["id"] = f"DET-{idx + 1:03d}"
    return detections


def annotate_events(events: List[Dict[str, Any]], detections: List[Dict[str, Any]]) -> None:
    """Tag each normalized event with the detections that cover it (in place)."""
    index: Dict[str, List[Dict[str, Any]]] = {}
    for det in detections:
        for eid in det["event_ids"]:
            index.setdefault(eid, []).append(det)

    for ev in events:
        hits = index.get(ev["id"], [])
        severity = "info"
        for h in hits:
            severity = max_severity(severity, h["severity"])
        ev["suspicious"] = bool(hits)
        ev["detection_types"] = sorted({h["type"] for h in hits})
        ev["severity"] = severity
