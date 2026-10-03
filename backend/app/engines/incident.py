"""Incident reconstruction: attack chain, timeline, attack graph, IOCs, summary."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .detection import max_severity
from .risk import calculate as calculate_risk
from .mitre import map_techniques

# stage definitions: (order, detection type, stage title, icon)
CHAIN_STAGES = [
    ("reconnaissance", "Reconnaissance", "🔍"),
    ("brute_force", "Brute Force", "🔴"),
    ("account_compromise", "Account Compromise", "🔐"),
    ("privilege_escalation", "Privilege Escalation", "⚠"),
    ("sensitive_data_access", "Sensitive Data Access", "💾"),
    ("data_exfiltration", "Data Exfiltration", "📤"),
]

STAGE_TITLES = {
    "brute_force": "Repeated Login Attempts",
    "account_compromise": "Successful Login After Brute Force",
    "privilege_escalation": "Privilege Escalation via sudo",
    "sensitive_data_access": "Sensitive Database Access",
    "reconnaissance": "Port Scanning / Reconnaissance",
    "data_exfiltration": "Bulk Outbound Data Transfer",
    "suspicious_source_ip": "External Source IP Identified",
}


def _display(ts: Optional[str]) -> Optional[str]:
    if not ts:
        return None
    return ts[11:19] if len(ts) >= 19 else ts


def build_attack_chain(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    chain: List[Dict[str, Any]] = []
    for det_type, label, icon in CHAIN_STAGES:
        for det in detections:
            if det["type"] != det_type:
                continue
            chain.append(
                {
                    "stage": len(chain) + 1,
                    "type": det["type"],
                    "stage_label": label,
                    "icon": icon,
                    "title": STAGE_TITLES.get(det["type"], det["title"]),
                    "timestamp": det.get("first_seen"),
                    "time_display": _display(det.get("first_seen")),
                    "severity": det["severity"],
                    "confidence": det["confidence"],
                    "description": det["description"],
                    "detection_id": det["id"],
                    "evidence": det["evidence"][:3],
                }
            )
    return chain


def build_timeline(events: List[Dict[str, Any]], detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    det_by_event: Dict[str, List[Dict[str, Any]]] = {}
    for det in detections:
        for eid in det["event_ids"]:
            det_by_event.setdefault(eid, []).append(det)

    timeline: List[Dict[str, Any]] = []
    for ev in events:
        hits = det_by_event.get(ev["id"], [])
        types = sorted({h["type"] for h in hits})
        severity = "info"
        for h in hits:
            severity = max_severity(severity, h["severity"])

        icon, label = _timeline_visual(ev["event_type"], types, severity)
        timeline.append(
            {
                "event_id": ev["id"],
                "timestamp": ev.get("timestamp"),
                "time_display": _display(ev.get("timestamp")) or "--:--:--",
                "event_type": ev["event_type"],
                "label": label,
                "icon": icon,
                "severity": severity,
                "suspicious": bool(hits) or bool(ev.get("suspicious")),
                "detection_types": types,
                "detection_ids": [h["id"] for h in hits],
                "source_ip": ev.get("source_ip"),
                "destination_ip": ev.get("destination_ip"),
                "username": ev.get("username"),
                "host": ev.get("source"),
                "status": ev.get("status"),
                "action": ev.get("action"),
                "evidence": [e for h in hits for e in h["evidence"][:2]],
                "description": ev.get("raw_message"),
                "raw_message": ev.get("raw_message"),
                "external_source": ev.get("external_source"),
            }
        )
    timeline.sort(key=lambda t: (t["timestamp"] or "", t["event_id"]))
    return timeline


def _timeline_visual(event_type: str, detection_types: List[str], severity: str) -> tuple[str, str]:
    if "data_exfiltration" in detection_types:
        return "📤", "Data Exfiltration"
    if "sensitive_data_access" in detection_types:
        return "💾", "Sensitive Data Access"
    if "privilege_escalation" in detection_types:
        return "⚠", "Privilege Escalation"
    if "brute_force" in detection_types:
        return "🔴", "Brute Force Attempt"
    if "account_compromise" in detection_types or event_type == "login_success":
        return "🔐", "Successful Login"
    if "reconnaissance" in detection_types:
        return "🔍", "Reconnaissance"
    if event_type == "login_failed":
        return "🔴", "Failed Login"
    if severity in ("info", "low"):
        return "🟢", _event_label(event_type)
    return "🟠", _event_label(event_type)


def _event_label(event_type: str) -> str:
    return {
        "health_check": "Health Check",
        "api_request": "Normal API Request",
        "background_process": "Background Process",
        "login_success": "Successful Login",
        "login_failed": "Failed Login",
        "database_access": "Database Access",
        "file_access": "File Access",
        "process_event": "System Event",
        "data_transfer": "Data Transfer",
    }.get(event_type, event_type.replace("_", " ").title())


# ---------------------------------------------------------------------------
# attack graph
# ---------------------------------------------------------------------------
def build_attack_graph(incident_ctx: Dict[str, Any], timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
    detections: List[Dict[str, Any]] = incident_ctx["detections"]
    events: List[Dict[str, Any]] = incident_ctx["events"]
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    edge_seen: set[tuple[str, str, str]] = set()

    def node(nid: str, label: str, ntype: str, **extra: Any) -> str:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "type": ntype, "suspicious": ntype in
                          ("attacker", "compromised", "resource"), **extra}
        return nid

    def edge(src: str, dst: str, label: str, severity: str = "info") -> None:
        key = (src, dst, label)
        if key in edge_seen or src == dst:
            return
        edge_seen.add(key)
        edges.append({"id": f"E{len(edges) + 1}", "source": src, "target": dst,
                      "label": label, "severity": severity})

    src_ip = incident_ctx.get("source_ip")
    users = incident_ctx.get("affected_users") or []
    primary_user = incident_ctx.get("username") or (users[0] if users else None)

    attacker_id = None
    if src_ip:
        external = not _is_private(src_ip)
        attacker_id = node(
            f"ip:{src_ip}",
            src_ip,
            "attacker" if external else "source",
            external=external,
            subtitle="External attacker" if external else "Internal source",
            first_seen=_display(incident_ctx.get("first_seen")),
        )

    compromised_id = None
    if primary_user:
        compromised_id = node(f"user:{primary_user}", primary_user, "compromised",
                              subtitle="Compromised account", owner=primary_user)

    # login endpoint
    login_hosts = [e.get("destination_ip") or e.get("source") for e in events
                   if e["event_type"] in ("login_failed", "login_success")]
    login_host = next((h for h in login_hosts if h), None)
    login_id = node(f"endpoint:{login_host or 'auth'}", str(login_host or "Auth Endpoint"),
                    "endpoint", subtitle="Authentication endpoint")

    if attacker_id and login_id:
        edge(attacker_id, login_id, "brute force", "high")
    if login_id and compromised_id:
        edge(login_id, compromised_id, "authenticates as", "critical")

    if attacker_id and compromised_id:
        edge(attacker_id, compromised_id, "compromised via", "high")

    # privilege node
    if any(d["type"] == "privilege_escalation" for d in detections):
        priv_id = node("priv:admin", "Admin / root privileges", "privilege",
                       subtitle="Elevated privileges granted")
        if compromised_id:
            edge(compromised_id, priv_id, "escalates to", "high")

    # sensitive resources
    resources: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        if ev["event_type"] not in ("database_access", "file_access", "data_transfer"):
            continue
        extra = ev.get("extra") or {}
        name = extra.get("db") or extra.get("file") or extra.get("resource")
        if not name:
            msg = str(ev.get("raw_message") or "")
            for token in ("prod-db", "customers_db", "payments_db", "audit", "backups"):
                if token in msg:
                    name = token
                    break
        if not name:
            name = ev.get("destination_ip") or "sensitive resource"
        resources.setdefault(str(name), []).append(ev)

    for rid, evs in resources.items():
        stamps = [e["timestamp"] for e in evs if e.get("timestamp")]
        rnode = node(f"resource:{rid}", rid, "resource", subtitle="Data store",
                     records=len(evs),
                     first_seen=_display(min(stamps) if stamps else None))
        if compromised_id:
            edge(compromised_id, rnode, "reads sensitive data", "critical")
        priv_ids = [n for n in nodes if n.startswith("priv:")]
        if priv_ids:
            edge(priv_ids[0], rnode, "grants access", "medium")

    # destination / exfil sink
    sinks = {e.get("destination_ip") for e in events if e.get("destination_ip")}
    sinks = {s for s in sinks if s and s not in resources}
    for sink in list(sinks)[:2]:
        if not _is_private(sink):
            s = node(f"ip:{sink}", sink, "attacker", external=True, subtitle="External destination")
            if compromised_id:
                edge(compromised_id, s, "sends data", "critical")

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "entry_point": src_ip,
            "compromised_identity": primary_user,
            "crown_jewels": list(resources.keys()),
        },
    }


def _is_private(ip: Optional[str]) -> bool:
    from .parser import is_private_ip

    return is_private_ip(ip)


# ---------------------------------------------------------------------------
# indicators of compromise
# ---------------------------------------------------------------------------
def build_indicators(incident_ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = incident_ctx["events"]
    detections: List[Dict[str, Any]] = incident_ctx["detections"]
    iocs: List[Dict[str, Any]] = []

    for ip in sorted({e.get("source_ip") for e in events if e.get("source_ip") and not _is_private(e.get("source_ip"))}):
        related = [d for d in detections if d.get("source_ip") == ip]
        iocs.append({
            "type": "ipv4", "value": ip, "role": "attacker source",
            "confidence": max([d["confidence"] for d in related], default=0.6),
            "evidence": f"{sum(len(d['event_ids']) for d in related)} related event(s)",
        })

    for user in sorted({d.get("username") for d in detections if d.get("username")}):
        related = [d for d in detections if d.get("username") == user]
        iocs.append({
            "type": "account", "value": user, "role": "compromised account",
            "confidence": max([d["confidence"] for d in related], default=0.5),
            "evidence": f"{len(related)} detection(s) involve this account",
        })

    for ev in events:
        extra = ev.get("extra") or {}
        if extra.get("command"):
            iocs.append({"type": "command", "value": str(extra["command"]), "role": "executed",
                         "confidence": 0.9, "evidence": f"Observed at {_display(ev.get('timestamp'))} UTC"})
        if extra.get("file"):
            iocs.append({"type": "file", "value": str(extra["file"]), "role": "accessed",
                         "confidence": 0.85, "evidence": "Sensitive file read by the compromised account"})
        if extra.get("hash"):
            iocs.append({"type": "sha256", "value": str(extra["hash"]), "role": "process hash",
                         "confidence": 0.7, "evidence": "Process observed on the affected host"})

    for ev in events:
        if ev["event_type"] in ("database_access", "data_transfer"):
            extra = ev.get("extra") or {}
            if extra.get("db"):
                iocs.append({"type": "data_store", "value": str(extra["db"]), "role": "targeted",
                             "confidence": 0.88, "evidence": "Accessed during the incident"})

    seen = set()
    unique = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"], ioc["role"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(ioc)
    return unique


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
def build_summary(incident_ctx: Dict[str, Any], chain: List[Dict[str, Any]], risk: Dict[str, Any]) -> Dict[str, str]:
    dets = incident_ctx["detections"]
    types = {d["type"] for d in dets}
    src_ip = incident_ctx.get("source_ip")
    users = incident_ctx.get("affected_users") or []
    user = incident_ctx.get("username") or (users[0] if users else None)
    first = incident_ctx.get("first_seen")
    last = incident_ctx.get("last_seen")

    if "account_compromise" in types:
        title = "Account Compromise Following Successful Brute Force"
        headline = "Possible Account Compromise"
    elif "brute_force" in types:
        title = "Brute Force Authentication Attack"
        headline = "Brute Force Attack Detected"
    elif "data_exfiltration" in types:
        title = "Suspected Data Exfiltration"
        headline = "Data Exfiltration Detected"
    elif dets:
        title = "Suspicious Activity Detected"
        headline = "Suspicious Activity"
    else:
        title = "No Incident Detected"
        headline = "No Significant Findings"

    if not dets:
        return {
            "title": title,
            "headline": headline,
            "narrative": (
                "TRACE parsed the log and found no activity matching the detection rules. "
                "All parsed events look like routine operations."
            ),
            "impact": "No impact identified.",
        }

    stages = [c["stage_label"] for c in chain]
    parts: List[str] = []
    if src_ip:
        origin = "external address" if not _is_private(src_ip) else "internal address"
        parts.append(f"An {origin} {src_ip}")
    else:
        parts.append("Activity")
    parts.append("was observed")
    if first and last:
        parts.append(f"between {_display(first)} and {_display(last)} UTC")
    parts.append("")
    narrative = " ".join(parts).strip() + " "

    sentences = []
    if "brute_force" in types:
        bf = next(d for d in dets if d["type"] == "brute_force")
        sentences.append(
            f"The sequence began with automated authentication attempts against "
            f"{('account ' + user) if user else 'a set of accounts'} ({bf['evidence'][0]})."
        )
    if "account_compromise" in types and user:
        sentences.append(
            f"The attempt succeeded: {user} authenticated from the same source, so the account "
            f"must be treated as compromised rather than merely attacked."
        )
    if "privilege_escalation" in types:
        sentences.append(
            "Immediately afterwards the session elevated its privileges, giving the operator "
            "administrative or root-level control of the host."
        )
    if "sensitive_data_access" in types:
        sd = next(d for d in dets if d["type"] == "sensitive_data_access")
        sentences.append(
            f"With those privileges the operator accessed sensitive data ({sd['evidence'][0]})"
            + (", and bulk outbound traffic suggests the data left the environment." if "data_exfiltration" in types else ".")
        )
    elif "data_exfiltration" in types:
        sentences.append("Bulk outbound traffic indicates data was transferred outside the environment.")

    narrative += " ".join(sentences)
    narrative += f" TRACE correlated these events into a single incident with a risk score of {risk['score']}/100 ({risk['severity']})."

    impact_bits = []
    if user:
        impact_bits.append(f"identity of {user}")
    if "sensitive_data_access" in types:
        impact_bits.append("sensitive data stores")
    if "privilege_escalation" in types:
        impact_bits.append("host privileges")
    impact = ("Confirmed impact on: " + ", ".join(impact_bits) + ".") if impact_bits else "Impact not yet confirmed."

    return {
        "title": title,
        "headline": headline,
        "narrative": narrative,
        "impact": impact,
        "stages": " → ".join(stages),
    }


# ---------------------------------------------------------------------------
# top-level
# ---------------------------------------------------------------------------
def build_incident(
    *,
    incident_id: str,
    cluster: Dict[str, Any],
    events: List[Dict[str, Any]],
    source_file: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    detections: List[Dict[str, Any]] = cluster["detections"]
    entity_ids = set(cluster["event_ids"])
    incident_events = [e for e in events if e["id"] in entity_ids] or list(events)

    ctx: Dict[str, Any] = {
        "detections": detections,
        "events": incident_events,
        "source_ip": cluster.get("source_ip"),
        "username": cluster.get("username"),
        "affected_users": cluster.get("affected_users") or [],
        "first_seen": cluster.get("first_seen"),
        "last_seen": cluster.get("last_seen"),
    }

    risk = calculate_risk(ctx)
    chain = build_attack_chain(detections)
    timeline = build_timeline(incident_events, detections)
    graph = build_attack_graph(ctx, timeline)
    mitre = map_techniques(ctx)
    indicators = build_indicators(ctx)
    summary = build_summary(ctx, chain, risk)

    from .response import build_response_plan
    from .threat_intel import enrich_indicators, summarize as ti_summarize

    response_actions = build_response_plan(ctx)
    threat_intel = enrich_indicators(indicators)

    affected_hosts = sorted({e.get("destination_ip") for e in incident_events if e.get("destination_ip")})
    username = cluster.get("username") or (cluster.get("affected_users") or [None])[0]

    return {
        "incident_id": incident_id,
        "title": summary["title"],
        "headline": summary["headline"],
        "summary": summary["narrative"],
        "impact": summary["impact"],
        "severity": risk["severity"],
        "risk_score": risk["score"],
        "confidence": risk["confidence"],
        "status": "open",
        "source_ip": cluster.get("source_ip"),
        "affected_user": username,
        "affected_users": cluster.get("affected_users") or [],
        "affected_hosts": affected_hosts,
        "first_seen": cluster.get("first_seen"),
        "last_seen": cluster.get("last_seen"),
        "event_count": len(incident_events),
        "detection_count": len(detections),
        "source_file": source_file or {},
        "events": incident_events,
        "detections": detections,
        "timeline": timeline,
        "attack_chain": chain,
        "attack_graph": graph,
        "risk_factors": risk["factors"],
        "risk_explanation": risk["explanation"],
        "mitre_techniques": mitre,
        "indicators": indicators,
        "threat_intel": threat_intel,
        "threat_intel_summary": ti_summarize(threat_intel),
        "response_actions": response_actions,
        "detected_stages": [c["stage_label"] for c in chain],
        "created_at": None,
    }
