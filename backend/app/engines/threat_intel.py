"""Offline threat-intelligence enrichment.

Deterministic and network-free: this never calls an external service and never
costs money. It classifies each indicator of compromise (IOC) using local data:

  * IP address scope  -> private (RFC1918) vs external/untrusted
  * a small curated list of ranges/addresses flagged as "known malicious"
    (demo data — replaced/extended by a real TI feed in production)
  * account classification (privileged vs standard)

Every result is a transparent dict so the UI can explain exactly *why* an IOC
was scored the way it was.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List

from .parser import is_private_ip

# --- demo threat-intel data (offline, deterministic) -------------------------
# In a real deployment these would come from a MISP/OTX/AbuseIPDB feed. For the
# demo we flag external addresses that our scenarios treat as attacker origins.
KNOWN_BAD_IPS: Dict[str, str] = {
    "185.42.18.91": "Bulletproof host, brute-force source (TI feed)",
    "45.133.216.77": "Known exfiltration endpoint (TI feed)",
    "91.211.90.14": "Credential-stuffing source (TI feed)",
}

# Coarse country/region hints for demo addresses (offline GeoIP stub).
GEO_HINTS: Dict[str, str] = {
    "185.42.": "Netherlands (EU)",
    "45.133.": "Germany (EU)",
    "91.211.": "Moldova (EU)",
    "89.": "Russia",
    "103.": "Asia-Pacific",
}

PRIVILEGED_ACCOUNTS = {"admin", "root", "administrator", "sudo", "system"}


def _geo(ip: str) -> str:
    for prefix, region in GEO_HINTS.items():
        if ip.startswith(prefix):
            return region
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private:
            return "Internal network"
    except ValueError:
        return "Unknown"
    return "External / unknown"


def enrich_ip(ip: str) -> Dict[str, Any]:
    private = is_private_ip(ip)
    bad_reason = KNOWN_BAD_IPS.get(ip)

    if bad_reason:
        reputation = "malicious"
        risk = "critical"
    elif not private:
        reputation = "suspicious"
        risk = "high"
    else:
        reputation = "internal"
        risk = "low"

    return {
        "type": "ipv4",
        "value": ip,
        "scope": "private" if private else "external",
        "geo": _geo(ip),
        "reputation": reputation,
        "risk": risk,
        "known_malicious": bool(bad_reason),
        "note": bad_reason or ("RFC1918 internal address" if private else "External address, no adverse reputation on record"),
    }


def enrich_account(user: str) -> Dict[str, Any]:
    privileged = user.lower() in PRIVILEGED_ACCOUNTS
    return {
        "type": "account",
        "value": user,
        "scope": "privileged" if privileged else "standard",
        "reputation": "privileged" if privileged else "standard",
        "risk": "high" if privileged else "medium",
        "known_malicious": False,
        "note": "Privileged account — higher blast radius if compromised" if privileged else "Standard user account",
    }


def enrich_indicators(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach TI context to every IOC, preserving the original fields."""
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for ind in indicators:
        value = ind.get("value")
        if not value or value in seen:
            continue
        seen.add(value)
        kind = ind.get("type")
        if kind == "ipv4":
            out.append({**ind, **enrich_ip(value)})
        elif kind in ("account", "username", "user"):
            out.append({**ind, **enrich_account(value)})
        else:
            out.append({**ind, "scope": "unknown", "reputation": "unknown", "risk": "info", "known_malicious": False, "note": ""})
    return out


def summarize(enriched: List[Dict[str, Any]]) -> Dict[str, Any]:
    malicious = [i for i in enriched if i.get("known_malicious")]
    external = [i for i in enriched if i.get("scope") == "external"]
    return {
        "total_iocs": len(enriched),
        "known_malicious": len(malicious),
        "external": len(external),
        "max_risk": "critical" if malicious else ("high" if external else "low"),
        "verdict": (
            f"{len(malicious)} IOC(s) match known-malicious threat-intel entries"
            if malicious
            else ("External infrastructure involved but no adverse reputation on record" if external else "No external or known-malicious indicators")
        ),
    }