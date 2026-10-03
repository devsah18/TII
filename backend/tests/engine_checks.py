#!/usr/bin/env python3
"""Direct engine-level checks: timestamps, correlation, all demo scenarios."""
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engines import demo, detection, parser  # noqa: E402
from app.services import investigation  # noqa: E402


def main() -> int:
    failures = 0

    # --- timestamps -------------------------------------------------------
    text = demo.generate_log_text("brute_force")
    events = parser.parse_log(text, "demo_brute_force.log")
    missing_ts = sum(1 for e in events if not e.get("timestamp"))
    print(f"events={len(events)} missing_timestamps={missing_ts}")
    first, last = events[0], events[-1]
    print(f"first={first['timestamp']} {first['event_type']:20s} {first['source_ip']}")
    print(f"last ={last['timestamp']} {last['event_type']:20s} {last['source_ip']}")
    if missing_ts:
        print("  FAIL: timestamps were not parsed")
        failures += 1
    else:
        print("  PASS: every event has an ISO timestamp")

    # --- username on the sudo line ---------------------------------------
    sudo = [e for e in events if e["event_type"] == "privilege_escalation"]
    print(f"privilege_escalation events={len(sudo)} users={[e['username'] for e in sudo]}")
    if not sudo or sudo[0]["username"] != "admin":
        print("  FAIL: sudo actor not extracted as 'admin'")
        failures += 1
    else:
        print("  PASS: sudo actor is 'admin'; extra =", sudo[0].get("command"))

    # --- detections ------------------------------------------------------
    dets = detection.detect(events)
    print("detections:", [f"{d['type']}({d['severity']})" for d in dets])
    for required in ("brute_force", "account_compromise", "privilege_escalation", "sensitive_data_access"):
        if required not in {d["type"] for d in dets}:
            print(f"  FAIL: {required} not detected")
            failures += 1

    # --- incident per scenario -------------------------------------------
    for scenario in demo.SCENARIOS:
        try:
            evs = demo.generate_events(scenario)
            inc = investigation.analyze_events(evs, source_file={"filename": f"demo_{scenario}.log"})
            print(
                f"\n[{scenario}] risk={inc['risk_score']} sev={inc['severity']} "
                f"conf={inc['confidence']} src={inc['source_ip']} user={inc['affected_user']}"
            )
            print(f"   chain  : {' -> '.join(c['stage_label'] for c in inc['attack_chain'])}")
            print(f"   times  : {inc['first_seen']} .. {inc['last_seen']}")
            print(f"   graph  : {len(inc['attack_graph']['nodes'])} nodes / {len(inc['attack_graph']['edges'])} edges")
            print(f"   mitre  : {[t['id'] for t in inc['mitre_techniques']]}")
            print(f"   iocs   : {[i['value'] for i in inc['indicators']]}")
            print(f"   actions: {len(inc['response_actions'])}  timeline={len(inc['timeline'])}")
            print(f"   related: {len(inc.get('related_incidents') or [])}")
            if not inc["first_seen"] or not inc["attack_chain"]:
                print("   FAIL: missing timestamps or attack chain")
                failures += 1
            if inc["source_ip"] and parser.is_private_ip(inc["source_ip"]) and scenario != "data_exfiltration":
                print("   FAIL: headline source IP is internal")
                failures += 1
            if not inc["risk_factors"]:
                print("   FAIL: no risk factors")
                failures += 1
        except Exception:
            print(f"\n[{scenario}] EXCEPTION")
            traceback.print_exc()
            failures += 1

    print("\n" + ("ALL ENGINE CHECKS PASSED" if not failures else f"{failures} ENGINE CHECK FAILURE(S)"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
