"""AI investigation layer.

If an LLM provider is configured via environment variables the answer is
generated from the incident context. Otherwise a deterministic, data-grounded
fallback answers the same questions. The application never fails because the AI
provider is missing or unreachable (spec sections 13 and 29 / Test 7).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_TIMEOUT

SYSTEM_PROMPT = (
    "You are TRACE's incident analyst. Answer strictly from the JSON incident context provided. "
    "Be specific: cite the numbers, IPs, accounts, timestamps and MITRE technique IDs in the context. "
    "Never invent evidence that is not in the context. Keep answers under 200 words and write plain prose."
)

SUGGESTED_QUESTIONS = [
    # spec-required core questions (kept first so the UI chips surface them)
    "Why is this critical?",
    "What happened first?",
    "Which account was compromised?",
    "What evidence supports this?",
    "What should we do now?",
    # additional prompts the deterministic investigator also covers
    "Why is this incident critical?",
    "What evidence indicates brute force?",
    "What did the attacker access?",
    "What should the security team do first?",
]


# ---------------------------------------------------------------------------
# intent detection
# ---------------------------------------------------------------------------
INTENTS: List[Tuple[str, Tuple[str, ...]]] = [
    ("first", ("what happened first", "first", "start", "beginning", "initial", "how did it start", "where did it begin")),
    ("account", ("which account", "what account", "compromised account", "who was compromised",
                 "which user", "what user", "victim")),
    ("brute_force_evidence", ("brute force", "failed login", "failed attempt", "password", "credential")),
    ("accessed", ("what did the attacker access", "what was accessed", "access", "database", "data", "exfiltrat",
                  "stolen", "records", "files")),
    ("response", ("what should", "what do we do", "next", "respond", "response", "contain", "mitigat",
                  "first action", "remediate", "security team")),
    ("mitre", ("mitre", "att&ck", "attack technique", "technique", "tactic")),
    ("risk", ("why is this critical", "why critical", "risk", "score", "severity", "why so high", "rated")),
    ("timeline", ("timeline", "sequence", "order of events", "when", "how long", "duration")),
    ("source", ("source ip", "where from", "which ip", "attacker ip", "origin")),
    ("summary", ("summarize", "summary", "overview", "what happened", "explain")),
    ("ioc", ("indicator", "ioc", "artifact", "hash", "command")),
]


def detect_intent(question: str) -> str:
    q = (question or "").lower().strip()
    if not q:
        return "summary"
    best, best_len = "summary", 0
    for intent, keywords in INTENTS:
        for kw in keywords:
            if kw in q and len(kw) > best_len:
                best, best_len = intent, len(kw)
    return best


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def answer_question(incident: Dict[str, Any], question: str) -> Dict[str, Any]:
    intent = detect_intent(question)
    fallback = _fallback_answer(incident, question, intent)

    if not LLM_API_KEY:
        return {
            "answer": fallback["answer"],
            "sources": fallback["sources"],
            "mode": "deterministic",
            "intent": intent,
        }

    context = _compact_context(incident)
    llm_answer = _call_llm(question, context)
    if not llm_answer:
        return {
            "answer": fallback["answer"],
            "sources": fallback["sources"],
            "mode": "deterministic-fallback",
            "intent": intent,
        }
    return {
        "answer": llm_answer,
        "sources": fallback["sources"],
        "mode": "llm",
        "intent": intent,
    }


def _compact_context(incident: Dict[str, Any]) -> str:
    ctx = {
        "incident_id": incident.get("incident_id"),
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "risk_score": incident.get("risk_score"),
        "confidence": incident.get("confidence"),
        "source_ip": incident.get("source_ip"),
        "affected_user": incident.get("affected_user"),
        "first_seen": incident.get("first_seen"),
        "last_seen": incident.get("last_seen"),
        "summary": incident.get("summary"),
        "attack_chain": [
            {"stage": c["stage"], "type": c["type"], "title": c["title"], "at": c["timestamp"]}
            for c in incident.get("attack_chain", [])
        ],
        "detections": [
            {"type": d["type"], "severity": d["severity"], "confidence": d["confidence"],
             "evidence": d["evidence"]}
            for d in incident.get("detections", [])
        ],
        "risk_factors": [
            {"name": f["name"], "points": f["points"], "evidence": f["evidence"]}
            for f in incident.get("risk_factors", [])
        ],
        "mitre_techniques": [
            {"id": t["id"], "name": t["name"], "confidence": t["confidence"], "evidence": t["evidence"]}
            for t in incident.get("mitre_techniques", [])
        ],
        "indicators": incident.get("indicators", [])[:10],
        "response_actions": [
            {"priority": a["priority"], "action": a["action"], "reason": a["reason"]}
            for a in incident.get("response_actions", [])
        ],
        "key_events": [
            {"at": e.get("timestamp"), "type": e.get("event_type"), "user": e.get("username"),
             "src": e.get("source_ip"), "message": e.get("raw_message")}
            for e in incident.get("events", []) if e.get("suspicious")
        ][:25],
    }
    return json.dumps(ctx, indent=1)[:12000]


def _call_llm(question: str, context: str) -> Optional[str]:
    """Best-effort call. Any failure returns None so the fallback takes over."""
    try:
        import urllib.error
        import urllib.request

        payload = json.dumps(
            {
                "model": LLM_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Incident context:\n{context}\n\nQuestion: {question}"},
                ],
                "temperature": 0.2,
                "max_tokens": 400,
            }
        ).encode()
        req = urllib.request.Request(
            f"{LLM_BASE_URL.rstrip('/')}/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {LLM_API_KEY}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content")
        return text.strip() if text else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# deterministic fallback
# ---------------------------------------------------------------------------
def _fmt_time(ts: Optional[str]) -> str:
    return ts[11:19] + " UTC" if ts and len(ts) >= 19 else "an unknown time"


def _fallback_answer(incident: Dict[str, Any], question: str, intent: str) -> Dict[str, Any]:
    dets: List[Dict[str, Any]] = incident.get("detections", [])
    chain: List[Dict[str, Any]] = incident.get("attack_chain", [])
    types = {d["type"] for d in dets}
    ip = incident.get("source_ip")
    user = incident.get("affected_user") or "unknown"
    score = incident.get("risk_score", 0)
    severity = incident.get("severity", "unknown")
    sources: List[str] = []

    def det(dtype: str) -> Optional[Dict[str, Any]]:
        return next((d for d in dets if d["type"] == dtype), None)

    if intent == "first":
        if chain:
            first = chain[0]
            answer = (
                f"The incident starts at stage {first['stage']} — {first['title']} at {_fmt_time(first['timestamp'])}. "
                f"{first['description']} "
            )
            if len(chain) > 1:
                answer += f"It was followed by {chain[1]['title'].lower()} at {_fmt_time(chain[1]['timestamp'])}."
            sources = [f"{first['title']} at {_fmt_time(first['timestamp'])}"] + first.get("evidence", [])[:2]
        else:
            answer = "No attack chain could be reconstructed: no detection rules were triggered by this log."
            sources = ["No detections matched"]

    elif intent == "account":
        if user and user != "unknown":
            comp = det("account_compromise")
            answer = (
                f"The account {user} is the compromised identity. "
            )
            if comp:
                answer += f"{comp['description']} "
            answer += (
                f"It is the account used for the successful authentication after the failed attempts"
                + (f" from {ip}" if ip else "") + "."
            )
            sources = (comp["evidence"][:3] if comp else [f"Account {user} appears in the detection evidence"])
        else:
            answer = "No specific account was confirmed as compromised — only suspicious authentication activity was observed."
            sources = ["No account-level detection triggered"]

    elif intent == "brute_force_evidence":
        bf = det("brute_force")
        if bf:
            answer = (
                f"Brute force is supported by {bf['evidence'][0]}. Detectable signals used by TRACE: "
                f"{'; '.join(bf['evidence'][1:3])}. Detection confidence is {bf['confidence']:.0%} and the "
                f"pattern was contained inside a single short window, which is what separates it from normal "
                f"user mistyping."
            )
            sources = bf["evidence"][:4]
        else:
            answer = "No brute-force pattern was detected: the log does not contain a burst of failed authentication attempts."
            sources = ["No brute-force detection"]

    elif intent == "accessed":
        sd = det("sensitive_data_access")
        ex = det("data_exfiltration")
        if sd:
            answer = f"The attacker reached sensitive data: {sd['description']} "
            answer += "Evidence: " + "; ".join(sd["evidence"][:3]) + ". "
            if ex:
                answer += f"Additionally, {ex['evidence'][0]}, indicating the collected data was moved out of the environment."
            sources = sd["evidence"][:3] + (ex["evidence"][:2] if ex else [])
        else:
            answer = "No confirmed access to sensitive data was found in this log."
            sources = ["No sensitive-data detection"]

    elif intent == "response":
        actions = incident.get("response_actions", [])
        immediate = [a for a in actions if a["priority"] == "IMMEDIATE"]
        if immediate:
            answer = "Start with the IMMEDIATE actions: " + " ".join(
                f"({i + 1}) {a['action']} — {a['reason']}" for i, a in enumerate(immediate[:3])
            )
            sources = [f"{a['action']}" for a in immediate[:3]]
        else:
            answer = "No urgent containment is required; work through the INVESTIGATE items in the response plan."
            sources = [a["action"] for a in actions[:3]]

    elif intent == "mitre":
        techs = incident.get("mitre_techniques", [])
        if techs:
            answer = "The behaviour maps to " + ", ".join(f"{t['id']} ({t['name']}, {t['confidence']:.0%})" for t in techs) + \
                     ". Each mapping is only emitted when the detection evidence supports the technique, so no unrelated techniques are listed."
            sources = [f"{t['id']} {t['name']}: {t['evidence'][0] if t['evidence'] else ''}" for t in techs[:4]]
        else:
            answer = "No MITRE ATT&CK techniques were mapped because no detection evidence supported them."
            sources = ["No technique mappings"]

    elif intent == "risk":
        factors = incident.get("risk_factors", [])
        if factors:
            answer = (
                f"The score is {score}/100 ({severity}) because it is the sum of {len(factors)} concrete findings: "
                + "; ".join(f"{f['name']} (+{f['points']})" for f in factors)
                + f". {incident.get('risk_explanation', '')}"
            )
            sources = [f"{f['name']} (+{f['points']}): {f['evidence']}" for f in factors[:5]]
        else:
            answer = f"The risk score is {score}/100. No detection rules fired, so no risk factors were added."
            sources = ["No risk factors triggered"]

    elif intent == "timeline":
        if chain:
            answer = "The reconstruction runs " + " → ".join(c["stage_label"] for c in chain) + ". " + \
                     " ".join(f"{c['stage_label']} at {_fmt_time(c['timestamp'])}." for c in chain)
            sources = [f"{c['stage_label']} at {_fmt_time(c['timestamp'])}" for c in chain]
        else:
            answer = "There is no attack sequence to reconstruct from this log."
            sources = ["No attack chain"]

    elif intent == "source":
        if ip:
            answer = (
                f"The activity originates from {ip}. "
                + (f"{'An external address' if incident.get('indicators') else 'An address'} that appears in "
                   f"{sum(len(d['event_ids']) for d in dets if d.get('source_ip') == ip)} detected event(s)."
                   if any(d.get("source_ip") == ip for d in dets) else "")
            )
            sources = [f"Source IP {ip}"] + [d["evidence"][0] for d in dets if d.get("source_ip") == ip][:2]
        else:
            answer = "No single source IP dominates this incident."
            sources = ["No dominant source IP"]

    elif intent == "ioc":
        iocs = incident.get("indicators", [])
        if iocs:
            answer = "Indicators of compromise extracted from the incident: " + "; ".join(
                f"{i['type']} {i['value']} ({i['role']})" for i in iocs[:8]
            ) + "."
            sources = [f"{i['type']}: {i['value']}" for i in iocs[:6]]
        else:
            answer = "No indicators of compromise were extracted from this log."
            sources = ["No IOCs"]

    else:  # summary
        answer = (
            f"{incident.get('title', 'Incident')} at severity {severity}, risk {score}/100, "
            f"confidence {incident.get('confidence', 0):.0%}. {incident.get('summary', '')}"
        )
        sources = [f"Risk score {score}/100", f"{len(dets)} detection(s)",
                   f"{len(chain)} attack chain stage(s)"] + [d["evidence"][0] for d in dets[:2]]

    if not sources:
        sources = ["Incident data"]
    answer = re.sub(r"\s+", " ", answer).strip()
    return {"answer": answer, "sources": sources[:6]}
