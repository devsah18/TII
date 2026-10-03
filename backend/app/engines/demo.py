"""Synthetic attack log generator for the demo.

Produces realistic mixed logs (benign + malicious) so the full pipeline can be
demonstrated without any external data. Every scenario ends up with 25+ events.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

ATTACKER_IP = "185.42.18.91"
EXFIL_HOST = "45.133.216.77"
AUTH_HOST = "10.0.0.15"
APP_HOST = "10.0.0.22"
DB_HOST = "10.0.0.40"
COMPROMISED_USER = "admin"
NORMAL_USERS = ("j.okafor", "m.tanaka", "s.reynolds", "backup_svc")

SCENARIOS = {
    "brute_force": {
        "name": "Brute Force → Account Compromise",
        "description": "External brute force against the admin account, followed by a successful login, "
                       "privilege escalation and sensitive data access.",
        "attackers": [ATTACKER_IP],
    },
    "account_compromise": {
        "name": "Account Compromise",
        "description": "Credential stuffing against several accounts from one external address, one success.",
        "attackers": [ATTACKER_IP],
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "description": "A valid session elevates to root via sudo and then reads sensitive files.",
        "attackers": ["91.211.90.14"],
    },
    "data_exfiltration": {
        "name": "Data Exfiltration",
        "description": "An authorised account bulk-exports the customer database to an external host.",
        "attackers": ["91.211.90.14"],
    },
}


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _syslog(dt: datetime, host: str, proc: str, msg: str) -> str:
    return f"{_fmt(dt)} {host} {proc}: {msg}"


def _base_events(start: datetime) -> List[str]:
    """12 benign events spread across the window."""
    lines: List[str] = []
    t = start
    lines.append(_syslog(t, "soc-collector", "trace", f"health_check status=ok target={APP_HOST} latency=4ms"))
    lines.append(_syslog(t + timedelta(seconds=12), AUTH_HOST, "sshd",
                         f"Accepted password for {NORMAL_USERS[0]} from 10.0.0.5 port 51244 ssh2"))
    lines.append(_syslog(t + timedelta(seconds=27), APP_HOST, "nginx",
                         f"api_request GET /api/v1/orders status=200 src=10.0.0.31 bytes=8421"))
    lines.append(_syslog(t + timedelta(seconds=41), APP_HOST, "cron", "background_process backup-check completed user=backup_svc"))
    lines.append(_syslog(t + timedelta(seconds=58), AUTH_HOST, "sshd",
                         f"Accepted password for {NORMAL_USERS[1]} from 10.0.0.8 port 40122 ssh2"))
    lines.append(_syslog(t + timedelta(minutes=1, seconds=9), "soc-collector", "trace",
                         f"health_check status=ok target={APP_HOST} latency=6ms"))
    lines.append(_syslog(t + timedelta(minutes=1, seconds=22), APP_HOST, "nginx",
                         f"api_request GET /api/v1/profile status=200 src=10.0.0.44 bytes=2310"))
    lines.append(_syslog(t + timedelta(minutes=1, seconds=40), DB_HOST, "postgres",
                         "database_access routine stats query user=reporting_svc db=metrics_db rows=18"))
    lines.append(_syslog(t + timedelta(minutes=2, seconds=3), APP_HOST, "systemd", "service started worker-pool.service"))
    lines.append(_syslog(t + timedelta(minutes=2, seconds=25), "soc-collector", "trace",
                         f"health_check status=ok target={DB_HOST} latency=3ms"))
    lines.append(_syslog(t + timedelta(minutes=2, seconds=48), AUTH_HOST, "sshd",
                         f"Accepted publickey for {NORMAL_USERS[2]} from 10.0.0.12 port 33811 ssh2"))
    lines.append(_syslog(t + timedelta(minutes=3, seconds=5), APP_HOST, "nginx",
                         "api_request POST /api/v1/search status=200 src=10.0.0.31 bytes=15533"))
    return lines


def _recon(start: datetime, attacker: str) -> List[str]:
    t = start + timedelta(minutes=4)
    return [
        _syslog(t, "fw-edge", "kernel", f"port scan detected from {attacker} against {AUTH_HOST} ports 22,80,443"),
        _syslog(t + timedelta(seconds=9), "fw-edge", "kernel", f"reconnaissance probe from {attacker} tcp flag SYN count=214"),
    ]


def _failed_logins(start: datetime, attacker: str, user: str, count: int = 17) -> List[str]:
    lines = []
    t = start + timedelta(minutes=4, seconds=20)
    for i in range(count):
        t = t + timedelta(seconds=random.randint(2, 5))
        lines.append(
            _syslog(t, AUTH_HOST, "sshd",
                    f"Failed password for {user} from {attacker} port {40000 + i * 7} ssh2")
        )
    return lines


def _success(dt: datetime, attacker: str, user: str) -> List[str]:
    return [
        _syslog(dt, AUTH_HOST, "sshd", f"Accepted password for {user} from {attacker} port 51882 ssh2"),
        _syslog(dt + timedelta(seconds=2), AUTH_HOST, "sshd", f"session opened for user {user} by (uid=0)"),
    ]


def _priv_esc(dt: datetime, user: str) -> List[str]:
    return [
        _syslog(dt, APP_HOST, "sudo", f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
                                     f"COMMAND=/usr/bin/bash -c 'cat /etc/shadow' command=sudo -i new_privilege=root"),
        _syslog(dt + timedelta(seconds=6), APP_HOST, "sudo", f"admin privilege granted: user={user} elevated privileges root access"),
        _syslog(dt + timedelta(seconds=14), APP_HOST, "auditd",
                f"privilege escalation detected user={user} from=uid1000 to=uid0 src=10.0.0.15"),
    ]


def _data_access(dt: datetime) -> List[str]:
    return [
        _syslog(dt, DB_HOST, "postgres",
                "database_access user=admin db=customers_db query=\"SELECT * FROM customer_records\" rows=48211 sensitive=true"),
        _syslog(dt + timedelta(seconds=11), DB_HOST, "postgres",
                "database_access user=admin db=payments_db query=\"SELECT card_token, customer_id FROM payments\" rows=12044"),
        _syslog(dt + timedelta(seconds=23), APP_HOST, "trace",
                "file read sensitive file=/opt/app/config/credentials.env user=admin confidential=true"),
    ]


def _exfil(dt: datetime) -> List[str]:
    return [
        _syslog(dt, APP_HOST, "trace",
                f"data transfer outbound bytes=18874368 dst={EXFIL_HOST} src=10.0.0.22 protocol=https user=admin"),
        _syslog(dt + timedelta(seconds=18), "fw-edge", "kernel",
                f"bulk download outbound to {EXFIL_HOST} bytes=5242880 flagged=true"),
    ]


def _tail_benign(start: datetime) -> List[str]:
    t = start + timedelta(minutes=9)
    return [
        _syslog(t, "soc-collector", "trace", f"health_check status=ok target={APP_HOST} latency=5ms"),
        _syslog(t + timedelta(seconds=21), APP_HOST, "nginx",
                "api_request GET /api/v1/status status=200 src=10.0.0.31 bytes=980"),
        _syslog(t + timedelta(seconds=44), AUTH_HOST, "sshd",
                f"Accepted password for {NORMAL_USERS[3]} from 10.0.0.9 port 22110 ssh2"),
    ]


def generate_log_text(scenario: str = "brute_force", seed: int = 1337) -> str:
    random.seed(seed)
    scenario = scenario if scenario in SCENARIOS else "brute_force"
    start = datetime(2026, 10, 2, 10, 38, 0, tzinfo=timezone.utc)

    lines = _base_events(start)

    if scenario in ("brute_force", "account_compromise"):
        attacker = SCENARIOS[scenario]["attackers"][0]
        lines += _recon(start, attacker)
        if scenario == "account_compromise":
            for user in (COMPROMISED_USER, "j.okafor", "m.tanaka"):
                lines += _failed_logins(start, attacker, user, count=4)
            lines += _success(start + timedelta(minutes=5, seconds=40), attacker, COMPROMISED_USER)
        else:
            lines += _failed_logins(start, attacker, COMPROMISED_USER, count=17)
            lines += _success(start + timedelta(minutes=5, seconds=42), attacker, COMPROMISED_USER)
        success_dt = start + timedelta(minutes=6, seconds=20)
        lines += _priv_esc(success_dt, COMPROMISED_USER)
        lines += _data_access(success_dt + timedelta(minutes=1, seconds=10))
        if scenario == "brute_force":
            lines += _exfil(success_dt + timedelta(minutes=2, seconds=5))

    elif scenario == "privilege_escalation":
        attacker = SCENARIOS[scenario]["attackers"][0]
        lines += _recon(start, attacker)
        lines += _failed_logins(start, attacker, COMPROMISED_USER, count=7)
        lines += _success(start + timedelta(minutes=5, seconds=30), attacker, COMPROMISED_USER)
        lines += _priv_esc(start + timedelta(minutes=6), COMPROMISED_USER)
        lines += _data_access(start + timedelta(minutes=7))
        lines += _exfil(start + timedelta(minutes=8))

    elif scenario == "data_exfiltration":
        dt = start + timedelta(minutes=5)
        lines += _success(dt, "10.0.0.9", "reporting_svc")
        lines += [
            _syslog(dt + timedelta(minutes=1), DB_HOST, "postgres",
                    "database_access user=reporting_svc db=customers_db query=\"SELECT * FROM customer_records\" "
                    "rows=91244 sensitive=true confidential=true"),
            _syslog(dt + timedelta(minutes=2), DB_HOST, "postgres",
                    "bulk download database dump customer records credentials secret export started"),
        ]
        lines += _exfil(dt + timedelta(minutes=3))

    lines += _tail_benign(start)
    lines.sort()
    return "\n".join(lines) + "\n"


def generate_events(scenario: str = "brute_force") -> List[Dict[str, Any]]:
    from .parser import parse_log

    return parse_log(generate_log_text(scenario), f"demo_{scenario}.log")


def scenario_catalog() -> List[Dict[str, Any]]:
    return [
        {
            "id": key,
            "name": meta["name"],
            "description": meta["description"],
            "primary": key == "brute_force",
            "expected_severity": "critical" if key in ("brute_force", "data_exfiltration") else "high",
            "expected_stages": _expected_stages(key),
        }
        for key, meta in SCENARIOS.items()
    ]


def _expected_stages(key: str) -> List[str]:
    return {
        "brute_force": ["Reconnaissance", "Brute Force", "Account Compromise",
                        "Privilege Escalation", "Sensitive Data Access", "Data Exfiltration"],
        "account_compromise": ["Reconnaissance", "Brute Force", "Account Compromise"],
        "privilege_escalation": ["Reconnaissance", "Brute Force", "Account Compromise",
                                 "Privilege Escalation", "Sensitive Data Access", "Data Exfiltration"],
        "data_exfiltration": ["Sensitive Data Access", "Data Exfiltration"],
    }[key]


if __name__ == "__main__":
    import sys

    print(generate_log_text(sys.argv[1] if len(sys.argv) > 1 else "brute_force"), end="")
