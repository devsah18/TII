"""Log parser + normalizer.

Turns .log / .txt / .csv / .json input into the normalized event schema:

    {
      "timestamp": "2026-10-02T10:42:01Z",
      "source_ip": "185.42.18.91",
      "destination_ip": "10.0.0.15",
      "username": "admin",
      "event_type": "login_failed",
      "action": "authentication",
      "status": "failed",
      "source": "auth_server",
      "raw_message": "Failed login attempt for admin"
    }

The parser is deliberately tolerant: syslog, key=value and plain prose lines all
work, and column/field names are matched case-insensitively against synonyms.
Unsupported input raises ParseError with a message the UI can display.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..config import DEFAULT_LOG_YEAR, MAX_EVENTS

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IP_PORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})[: ](?:port )?(\d{2,5})\b")

MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------
# Each rule: (keywords, event_type, action, status)
CLASSIFICATION_RULES: List[Tuple[Tuple[str, ...], str, str, str]] = [
    (
        ("port scan", "portscan", "service scan", "reconnaissance", "nmap", "probing",
         "probe from", "syn scan", "enumeration"),
        "reconnaissance", "network_discovery", "unknown",
    ),
    (
        ("exfiltrat", "bulk download", "large transfer", "data transfer", "mass download",
         "dumped table", "archive created for upload"),
        "data_transfer", "exfiltration", "success",
    ),
    (
        ("sudo", "privilege escalation", "root access", "admin privilege", "elevated privileges",
         "runas", "setuid", "became root", "privilege escalat", "escalated to root",
         "added to group sudo", "usermod -ag"),
        "privilege_escalation", "authorization", "success",
    ),
    (
        ("failed password", "login failed", "failed login", "authentication failure",
         "auth failed", "invalid password", "failed authentication", "bad credentials",
         "logon failure", "authentication denied", "access denied for user", "invalid user"),
        "login_failed", "authentication", "failed",
    ),
    (
        ("authentication success", "accepted password", "login successful", "successful login",
         "session opened for user", "logged in successfully", "auth success", "logon success"),
        "login_success", "authentication", "success",
    ),
    (
        ("healthcheck", "health check", "readiness", "liveness", "/healthz", "/health",
         "keep-alive", "heartbeat"),
        "health_check", "system", "success",
    ),
    (
        ("database", "db query", "select * from", "sql", "postgres", "mysql", "mongodb",
         "credentials", "secret", "sensitive file", "confidential", "customer records",
         "payment data", "pii", "keyvault", "vault read"),
        "database_access", "data_access", "success",
    ),
    (
        ("api request", "http request", "get /", "post /", "rest call", "api call"),
        "api_request", "network", "success",
    ),
    (
        ("cron", "background process", "scheduled task", "daemon", "worker", "backup job"),
        "background_process", "process", "success",
    ),
    (
        ("file read", "read file", "opened file", "cat /", "touched file"),
        "file_access", "data_access", "success",
    ),
    (
        ("process started", "service started", "systemd", "started process", "service restart"),
        "process_event", "process", "success",
    ),
]


def classify(raw_message: str, hint: Optional[str] = None) -> Tuple[str, str, str]:
    """Deterministic keyword classification of a log message."""
    if hint:
        norm = _normalize_event_type(hint)
        if norm:
            return _semantics_for(norm)
    text = (raw_message or "").lower()
    for keywords, event_type, action, status in CLASSIFICATION_RULES:
        for kw in keywords:
            if kw in text:
                return event_type, action, status
    return "process_event", "process", "unknown"


_HINT_MAP = {
    "login_failed": ("login_failed", "authentication", "failed"),
    "failed_login": ("login_failed", "authentication", "failed"),
    "auth_failure": ("login_failed", "authentication", "failed"),
    "login_success": ("login_success", "authentication", "success"),
    "successful_login": ("login_success", "authentication", "success"),
    "auth_success": ("login_success", "authentication", "success"),
    "privilege_escalation": ("privilege_escalation", "authorization", "success"),
    "priv_esc": ("privilege_escalation", "authorization", "success"),
    "database_access": ("database_access", "data_access", "success"),
    "db_access": ("database_access", "data_access", "success"),
    "file_access": ("file_access", "data_access", "success"),
    "health_check": ("health_check", "system", "success"),
    "api_request": ("api_request", "network", "success"),
    "background_process": ("background_process", "process", "success"),
    "process_event": ("process_event", "process", "success"),
    "reconnaissance": ("reconnaissance", "network_discovery", "unknown"),
    "data_transfer": ("data_transfer", "exfiltration", "success"),
    "exfiltration": ("data_transfer", "exfiltration", "success"),
}


def _normalize_event_type(value: str) -> Optional[str]:
    key = re.sub(r"[^a-z]+", "_", str(value).strip().lower()).strip("_")
    return key if key in _HINT_MAP else None


def _semantics_for(event_type: str) -> Tuple[str, str, str]:
    return _HINT_MAP[event_type]


# ---------------------------------------------------------------------------
# field extraction
# ---------------------------------------------------------------------------
_FIELD_ALIASES = {
    "timestamp": ("timestamp", "time", "@timestamp", "datetime", "date", "occurred_at", "ts"),
    "source_ip": ("source_ip", "src_ip", "src", "source", "sourceip", "client_ip", "attacker_ip", "ip"),
    "destination_ip": ("destination_ip", "dst_ip", "dst", "destination", "dest_ip", "dest", "target_ip", "host_ip"),
    "username": ("username", "user", "user_name", "account", "account_name", "principal", "login"),
    "event_type": ("event_type", "event", "type", "event_name", "action_type"),
    "action": ("action", "category", "activity"),
    "status": ("status", "result", "outcome"),
    "source": ("source", "log_source", "host", "hostname", "service", "device", "source_system"),
    "raw_message": ("raw_message", "message", "msg", "raw", "description", "event_message", "text"),
    "bytes": ("bytes", "bytes_out", "size", "transfer_bytes", "bytes_sent"),
}


def _pick(obj: Dict[str, Any], canonical: str) -> Any:
    lower = {str(k).strip().lower(): v for k, v in obj.items()}
    for alias in _FIELD_ALIASES[canonical]:
        if alias in lower and lower[alias] not in (None, ""):
            return lower[alias]
    return None


def normalize_timestamp(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))
    s = str(value).strip()

    iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return _fmt(dt)
    except Exception:
        pass

    m = re.match(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})", s)
    if m and m.group(1).lower() in MONTHS:
        try:
            dt = datetime(
                DEFAULT_LOG_YEAR, MONTHS[m.group(1).lower()], int(m.group(2)),
                int(m.group(3)), int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc,
            )
            return _fmt(dt)
        except Exception:
            pass

    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2}):(\d{2})", s)
    if m:
        try:
            dt = datetime(*(int(g) for g in m.groups()), tzinfo=timezone.utc)
            return _fmt(dt)
        except Exception:
            pass

    m = re.match(r"^(\d{4})/(\d{2})/(\d{2})[ T](\d{1,2}):(\d{2}):(\d{2})", s)
    if m:
        try:
            dt = datetime(*(int(g) for g in m.groups()), tzinfo=timezone.utc)
            return _fmt(dt)
        except Exception:
            pass

    if re.fullmatch(r"\d{10}(\.\d+)?", s):
        return _from_epoch(float(s))
    return None


def _from_epoch(value: float) -> str:
    if value > 1e11:  # milliseconds
        value = value / 1000.0
    return _fmt(datetime.fromtimestamp(value, tz=timezone.utc))


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return True
    try:
        parts = [int(p) for p in ip.split(".")]
    except Exception:
        return True
    if len(parts) != 4 or any(p > 255 for p in parts):
        return True
    a, b = parts[0], parts[1]
    if a == 10 or a == 127 or a == 0:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    if a >= 224:
        return True
    return False


_USER_RE = re.compile(
    r"(?:for|user|username|account|by)\s*[=:]?\s*['\"]?([A-Za-z0-9._@\\-]{2,64})['\"]?",
    re.IGNORECASE,
)
_USER_SUDO_RE = re.compile(r"(?:^|\s)([A-Za-z0-9._-]{2,64})\s*:\s*TTY=", re.IGNORECASE)
_CMD_RE = re.compile(r"COMMAND=(.+?)(?=\s+[A-Za-z_]\w*=|$)")
_KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)")


def extract_username(text: str) -> Optional[str]:
    m = _USER_SUDO_RE.search(text)
    if m:
        return m.group(1)
    m = _USER_RE.search(text)
    if m:
        candidate = m.group(1)
        if candidate.lower() not in {"true", "false", "null", "none", "success", "failed"}:
            return candidate
    return None


def extract_source_ip(text: str) -> Optional[str]:
    m = re.search(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})", text, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"\b(?:src|source|client|attacker)\s*[=:]\s*((?:\d{1,3}\.){3}\d{1,3})", text, re.IGNORECASE)
    if m:
        return m.group(1)
    ips = IPV4_RE.findall(text)
    return ips[0] if ips else None


def extract_destination_ip(text: str) -> Optional[str]:
    m = re.search(r"\b(?:to|dst|destination|target|host)\s*[=:]?\s*((?:\d{1,3}\.){3}\d{1,3})", text, re.IGNORECASE)
    if m:
        return m.group(1)
    ips = IPV4_RE.findall(text)
    if len(ips) >= 2:
        return ips[1]
    return None


def _extract_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in _KV_RE.findall(text):
        out[key.lower()] = value.strip("\"'")
    return out


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------
class ParseError(ValueError):
    pass


SUPPORTED_MSG = "The uploaded file could not be parsed. Supported formats: LOG, TXT, CSV, JSON."


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------
def parse_log(content: str, filename: str = "upload.log") -> List[Dict[str, Any]]:
    ext = Path(filename).suffix.lower()
    text = content.replace("\r\n", "\n").replace("\r", "\n")

    if ext == ".json":
        events = _parse_json(text)
    elif ext == ".csv":
        events = _parse_csv(text)
    else:
        events = []
        if text.lstrip()[:1] in ("[", "{"):
            try:
                events = _parse_json(text)
            except ParseError:
                events = []
        if not events:
            events = _parse_text(text)

    events = [e for e in events if e.get("raw_message") or e.get("timestamp")]
    if not events:
        raise ParseError(SUPPORTED_MSG)
    if len(events) > MAX_EVENTS:
        events = events[:MAX_EVENTS]

    events.sort(key=lambda e: (e.get("timestamp") or "", e.get("_seq", 0)))
    for i, ev in enumerate(events):
        ev["id"] = f"EVT-{i + 1:04d}"
        ev.pop("_seq", None)
    return events


# -- json ---------------------------------------------------------------------
def _parse_json(text: str) -> List[Dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        raise ParseError("The uploaded file is empty.")
    records: List[Any] = []
    try:
        loaded = json.loads(stripped)
        if isinstance(loaded, dict):
            for key in ("events", "logs", "records", "data", "entries"):
                if isinstance(loaded.get(key), list):
                    records = loaded[key]
                    break
            else:
                records = [loaded]
        elif isinstance(loaded, list):
            records = loaded
        else:
            raise ParseError(SUPPORTED_MSG)
    except json.JSONDecodeError:
        for line in stripped.split("\n"):
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if not records:
            raise ParseError(SUPPORTED_MSG)

    events: List[Dict[str, Any]] = []
    for idx, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        ev = _normalize_mapping(record, idx)
        if ev:
            events.append(ev)
    if not events:
        raise ParseError(SUPPORTED_MSG)
    return events


def _normalize_mapping(record: Dict[str, Any], idx: int) -> Optional[Dict[str, Any]]:
    raw_message = _pick(record, "raw_message")
    ts = normalize_timestamp(_pick(record, "timestamp"))
    if raw_message is None and ts is None:
        return None
    raw_message = str(raw_message) if raw_message is not None else ""

    hint = _pick(record, "event_type")
    event_type, action, status = classify(raw_message or str(hint or ""), str(hint) if hint else None)

    explicit_action = _pick(record, "action")
    explicit_status = _pick(record, "status")
    if explicit_action:
        action = str(explicit_action).strip().lower().replace(" ", "_")
    if explicit_status:
        status = str(explicit_status).strip().lower()

    source_ip = _pick(record, "source_ip")
    destination_ip = _pick(record, "destination_ip")
    username = _pick(record, "username")
    source = _pick(record, "source")

    if not source_ip:
        source_ip = extract_source_ip(raw_message)
    if not destination_ip:
        destination_ip = extract_destination_ip(raw_message)
    if not username:
        username = extract_username(raw_message)
    if not ts:
        ts = normalize_timestamp(raw_message)

    return _build_event(
        timestamp=ts,
        source_ip=str(source_ip) if source_ip else None,
        destination_ip=str(destination_ip) if destination_ip else None,
        username=str(username) if username else None,
        event_type=event_type,
        action=action,
        status=status,
        source=str(source) if source else "uploaded_log",
        raw_message=raw_message or f"{event_type} on {source or 'unknown'}",
        seq=idx,
        extra=_extra_fields(record),
    )


def _extra_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    known = set()
    for aliases in _FIELD_ALIASES.values():
        known.update(aliases)
    extra = {}
    for key, value in record.items():
        if str(key).strip().lower() in known:
            continue
        if isinstance(value, (str, int, float, bool)):
            extra[str(key)] = value
    return extra


# -- csv ----------------------------------------------------------------------
def _parse_csv(text: str) -> List[Dict[str, Any]]:
    if not text.strip():
        raise ParseError("The uploaded file is empty.")
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delimiter = dialect.delimiter
    except Exception:
        delimiter = ","

    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames:
        raise ParseError(SUPPORTED_MSG)

    events: List[Dict[str, Any]] = []
    for idx, row in enumerate(reader):
        if not any((v or "").strip() for v in row.values()):
            continue
        row = {k: v for k, v in row.items() if k is not None}
        ev = _normalize_mapping(row, idx)
        if ev:
            events.append(ev)
    if not events:
        raise ParseError(SUPPORTED_MSG)
    return events


# -- plain text / syslog ------------------------------------------------------
_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
    r"\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>[A-Za-z0-9._-]+)?\s*"
    r"(?P<proc>[A-Za-z0-9._/-]+(?:\[\d+\])?)?:?\s*(?P<msg>.*)$"
)

# "host process: message" once the leading timestamp has been consumed
_HOST_PROC_RE = re.compile(r"^(?P<host>[A-Za-z0-9._-]{2,64})\s+(?P<rest>.+)$")


def _parse_text(text: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for idx, line in enumerate(text.split("\n")):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        events.append(_parse_text_line(stripped, idx))
    if not events:
        raise ParseError(SUPPORTED_MSG)
    return events


def _extract_extras(message: str, fields: Dict[str, str]) -> Dict[str, Any]:
    """Pull structured detail out of a text line: transfer size, command, resource, hash."""
    extra: Dict[str, Any] = {}

    raw_bytes = fields.get("bytes")
    if raw_bytes is None:
        m = re.search(r"\bbytes\s*[=:]\s*([0-9]+)", message)
        raw_bytes = m.group(1) if m else None
    if raw_bytes is not None:
        try:
            extra["bytes"] = int(float(raw_bytes))
        except (TypeError, ValueError):
            pass

    m = _CMD_RE.search(message)
    if m:
        extra["command"] = m.group(1).strip()[:240]
    m = re.search(r"\bdb=([^\s;\"]+)", message)
    if m:
        extra["db"] = m.group(1).strip("'")
    m = re.search(r"\bfile=([^\s;\"]+)", message)
    if m:
        extra["file"] = m.group(1).strip("'")
    m = re.search(r"\b(?:sha256|hash)=([0-9a-fA-F]{16,})", message)
    if m:
        extra["hash"] = m.group(1)
    return extra


def _parse_text_line(line: str, idx: int) -> Dict[str, Any]:
    fields = _extract_kv(line)
    host = fields.get("host") or fields.get("source")
    message = line

    timestamp = normalize_timestamp(
        fields.get("timestamp") or fields.get("time") or fields.get("ts") or fields.get("@timestamp")
    )

    # 1) Leading ISO timestamp token: "2026-10-02T10:42:01Z host proc: message"
    if not timestamp:
        parts = line.split(None, 1)
        if parts:
            ts = normalize_timestamp(parts[0])
            if ts:
                timestamp = ts
                message = parts[1].strip() if len(parts) > 1 else line
                m = _HOST_PROC_RE.match(message)
                if m:
                    host = host or m.group("host")
                    message = m.group("rest")

    # 2) Classic syslog prefix: "Oct  2 10:42:01 host proc[pid]: message"
    if not timestamp:
        m = _SYSLOG_RE.match(line)
        if m:
            timestamp = normalize_timestamp(m.group("ts"))
            host = host or m.group("host")
            proc = m.group("proc")
            body = m.group("msg")
            if proc and body:
                message = f"{proc}: {body}"
            elif body:
                message = body
            if not host and proc:
                host = proc.split("[")[0].split("/")[-1]

    if fields:
        # keep the human-readable part as the message when key=value is used
        kv_message = fields.get("msg") or fields.get("message") or fields.get("event")
        if kv_message:
            message = kv_message
        host = fields.get("source") or host

    source_ip = fields.get("src") or fields.get("source_ip") or fields.get("src_ip") or extract_source_ip(message)
    destination_ip = (
        fields.get("dst") or fields.get("dest") or fields.get("destination_ip")
        or fields.get("dst_ip") or extract_destination_ip(message)
    )
    # A sudo/audit line carries `USER=root`, which is the *new* identity, not the
    # actor that escalated. Prefer the sudo actor ("sudo: admin : TTY=...").
    sudo_actor = _USER_SUDO_RE.search(message)
    username = (
        (sudo_actor.group(1) if sudo_actor else None)
        or fields.get("user") or fields.get("username") or fields.get("account")
        or extract_username(message)
    )

    event_type, action, status = classify(message, fields.get("event") or fields.get("event_type"))
    status = fields.get("status") or fields.get("result") or status

    extra = _extract_extras(message, fields)

    return _build_event(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        event_type=event_type,
        action=action,
        status=status,
        source=host or "uploaded_log",
        raw_message=message,
        seq=idx,
        extra=extra,
    )


def _build_event(
    *,
    timestamp: Optional[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    username: Optional[str],
    event_type: str,
    action: str,
    status: str,
    source: str,
    raw_message: str,
    seq: int,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    event = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "event_type": event_type,
        "action": action,
        "status": status,
        "source": source,
        "raw_message": raw_message.strip()[:600],
        "_seq": seq,
    }
    if extra:
        event.update(extra)
    event["external_source"] = not is_private_ip(source_ip)
    return event


def summarize_parse(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    events = list(events)
    types: Dict[str, int] = {}
    for ev in events:
        types[ev["event_type"]] = types.get(ev["event_type"], 0) + 1
    times = [e["timestamp"] for e in events if e.get("timestamp")]
    return {
        "event_count": len(events),
        "event_types": types,
        "first_event": min(times) if times else None,
        "last_event": max(times) if times else None,
        "unparsed_timestamps": sum(1 for e in events if not e.get("timestamp")),
    }
