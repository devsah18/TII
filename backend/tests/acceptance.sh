#!/usr/bin/env bash
# Acceptance test for the TRACE backend (spec section 29).
BASE="http://127.0.0.1:8000"
PASS=0
FAIL=0

check() {
  if [ "$1" = "1" ]; then echo "  PASS: $2"; PASS=$((PASS+1)); else echo "  FAIL: $2"; FAIL=$((FAIL+1)); fi
}

echo "=============================================================="
echo " TEST 1 — GET /api/health returns HTTP 200"
echo "=============================================================="
CODE=$(curl -s -o /tmp/t1.json -w "%{http_code}" "$BASE/api/health")
cat /tmp/t1.json; echo
[ "$CODE" = "200" ] && check 1 "HTTP 200" || check 0 "HTTP $CODE"
python3 -c "
import json;d=json.load(open('/tmp/t1.json'))
assert d['status']=='ok' and d['service']=='TRACE' and d['version']=='1.0.0', d
" && check 1 "schema {status:ok, service:TRACE, version:1.0.0}" || check 0 "health schema"

echo
echo "=============================================================="
echo " TEST 2 — POST /api/upload with the demo log"
echo "=============================================================="
CODE=$(curl -s -o /tmp/t2.json -w "%{http_code}" -F "file=@/home/user/trace/backend/demo_logs/demo_brute_force.log" "$BASE/api/upload")
cat /tmp/t2.json; echo
[ "$CODE" = "200" ] && check 1 "HTTP 200" || check 0 "HTTP $CODE"
FILE_ID=$(python3 -c "
import json;d=json.load(open('/tmp/t2.json'))
print(d['file_id'] if d.get('success') and d.get('file_id') and d.get('event_count') else '')
")
[ -n "$FILE_ID" ] && check 1 "file_id=$FILE_ID, event_count=$(python3 -c "import json;print(json.load(open('/tmp/t2.json'))['event_count'])")" || check 0 "file_id / event_count missing"

echo
echo "=============================================================="
echo " TEST 3 — POST /api/investigate with file_id=$FILE_ID"
echo "=============================================================="
CODE=$(curl -s -o /tmp/t3.json -w "%{http_code}" -X POST "$BASE/api/investigate" \
  -H 'Content-Type: application/json' -d "{\"file_id\":\"$FILE_ID\"}")
[ "$CODE" = "200" ] && check 1 "HTTP 200" || check 0 "HTTP $CODE"
python3 - <<'PY'
import json
d = json.load(open('/tmp/t3.json'))
inc = d['incident']
required = ["incident_id","title","severity","risk_score","confidence","summary","events",
            "timeline","attack_chain","attack_graph","risk_factors","mitre_techniques",
            "indicators","response_actions"]
missing = [k for k in required if k not in inc]
print("  missing keys:", missing or "none")
print(f"  incident_id={inc['incident_id']} risk={inc['risk_score']} severity={inc['severity']}")
print(f"  events={len(inc['events'])} timeline={len(inc['timeline'])} chain={len(inc['attack_chain'])} "
      f"graph_nodes={len(inc['attack_graph']['nodes'])} graph_edges={len(inc['attack_graph']['edges'])}")
print(f"  detections={len(inc['detections'])} risk_factors={len(inc['risk_factors'])} "
      f"mitre={[t['id'] for t in inc['mitre_techniques']]} iocs={len(inc['indicators'])} "
      f"actions={len(inc['response_actions'])}")
print("  chain:", " -> ".join(f"{c['stage']}:{c['stage_label']}" for c in inc['attack_chain']))
assert not missing, f"missing {missing}"
assert inc['risk_score'] > 0 and inc['timeline'] and inc['attack_chain'] and inc['attack_graph']['nodes']
PY
[ $? = 0 ] && check 1 "incident object has all required keys with real data" || check 0 "incident schema"

echo
echo "=============================================================="
echo " TEST 4 — POST /api/simulate"
echo "=============================================================="
for SC in brute_force account_compromise privilege_escalation data_exfiltration; do
  CODE=$(curl -s -o /tmp/t4.json -w "%{http_code}" -X POST "$BASE/api/simulate" \
    -H 'Content-Type: application/json' -d "{\"scenario\":\"$SC\"}")
  python3 - "$SC" "$CODE" <<'PY'
import json, sys
sc, code = sys.argv[1], sys.argv[2]
d = json.load(open('/tmp/t4.json'))
inc = d['incident']
ok = code == "200" and d['success'] and inc['incident_id'] and inc['risk_score'] > 0
print(f"  {sc:22s} HTTP {code}  {inc['incident_id']}  risk={inc['risk_score']:3d} "
      f"{inc['severity']:8s} events={len(inc['events']):2d} "
      f"detections={len(inc['detections'])} mitre={len(inc['mitre_techniques'])} "
      f"stages={len(inc['attack_chain'])} -> {'PASS' if ok else 'FAIL'}")
PY
done

echo
echo "=============================================================="
echo " TEST 5 — GET /api/incidents/{incident_id}"
echo "=============================================================="
INC=$(python3 -c "import json;print(json.load(open('/tmp/t3.json'))['incident']['incident_id'])")
CODE=$(curl -s -o /tmp/t5.json -w "%{http_code}" "$BASE/api/incidents/$INC")
[ "$CODE" = "200" ] && check 1 "HTTP 200 for $INC" || check 0 "HTTP $CODE"
python3 -c "
import json;d=json.load(open('/tmp/t5.json'))
assert d['incident_id'] and d['risk_factors'] and d['response_actions'] and d['attack_graph']['nodes']
print('  complete incident returned, detections =', len(d['detections']))
" && check 1 "complete incident object" || check 0 "incident payload"
CODE404=$(curl -s -o /tmp/t5b.json -w "%{http_code}" "$BASE/api/incidents/INC-9999")
cat /tmp/t5b.json; echo
[ "$CODE404" = "404" ] && check 1 "unknown id returns 404 with JSON error" || check 0 "404 handling"

echo
echo "=============================================================="
echo " TEST 6 — POST /api/chat (AI provider DISCONNECTED -> fallback)"
echo "=============================================================="
for Q in "Why is this incident critical?" "What happened first?" "Which account was compromised?" \
         "What evidence indicates brute force?" "What did the attacker access?" \
         "What should the security team do first?"; do
  CODE=$(curl -s -o /tmp/t6.json -w "%{http_code}" -X POST "$BASE/api/chat" \
    -H 'Content-Type: application/json' -d "{\"incident_id\":\"$INC\",\"question\":\"$Q\"}")
  python3 - "$Q" "$CODE" <<'PY'
import json, sys
q, code = sys.argv[1], sys.argv[2]
d = json.load(open('/tmp/t6.json'))
ok = code == "200" and d['success'] and len(d['answer']) > 40 and d['sources']
print(f"  HTTP {code} mode={d.get('mode')} intent={d.get('intent')} sources={len(d['sources'])}")
print(f"  Q: {q}")
print(f"  A: {d['answer'][:230]}{'...' if len(d['answer'])>230 else ''}")
print(f"  -> {'PASS' if ok else 'FAIL'}")
PY
done

echo
echo "=============================================================="
echo " TEST 7 — input validation / abuse cases"
echo "=============================================================="
printf 'binary\x00\x01data' > /tmp/bad.bin
CODE=$(curl -s -o /tmp/e1.json -w "%{http_code}" -F "file=@/tmp/bad.bin" "$BASE/api/upload")
cat /tmp/e1.json; echo
[ "$CODE" = "400" ] && check 1 "unsupported extension -> 400 JSON" || check 0 "expected 400, got $CODE"

echo "unsupported content, allowed extension" > /tmp/weird.log
echo "%%% not a log at all %%%" > /tmp/weird.log
CODE=$(curl -s -o /tmp/e2.json -w "%{http_code}" -F "file=@/tmp/weird.log" "$BASE/api/upload")
cat /tmp/e2.json; echo

: > /tmp/empty.log
CODE=$(curl -s -o /tmp/e3.json -w "%{http_code}" -F "file=@/tmp/empty.log" "$BASE/api/upload")
cat /tmp/e3.json; echo
[ "$CODE" = "400" ] && check 1 "empty file -> 400 JSON" || check 0 "empty file handling"

CODE=$(curl -s -o /tmp/e4.json -w "%{http_code}" -X POST "$BASE/api/investigate" \
  -H 'Content-Type: application/json' -d '{"file_id":"FILE-999"}')
cat /tmp/e4.json; echo
[ "$CODE" = "404" ] && check 1 "unknown file_id -> 404 JSON" || check 0 "unknown file_id"

CODE=$(curl -s -o /tmp/e5.json -w "%{http_code}" -X POST "$BASE/api/simulate" \
  -H 'Content-Type: application/json' -d '{"scenario":"nope"}')
cat /tmp/e5.json; echo
[ "$CODE" = "400" ] && check 1 "unknown scenario -> 400 JSON" || check 0 "unknown scenario"

echo
echo "=============================================================="
echo " TEST 8 — JSON / CSV / key=value parser tolerance"
echo "=============================================================="
python3 - <<'PY'
import json, subprocess, os
B = "http://127.0.0.1:8000"

def upload(path, name):
    out = subprocess.run(["curl","-s","-X","POST",f"{B}/api/upload","-F",f"file=@{path};filename={name}"],
                         capture_output=True, text=True).stdout
    return json.loads(out)

# JSON array
json.dump([
  {"timestamp":"2026-10-02T10:42:01Z","source_ip":"185.42.18.91","destination_ip":"10.0.0.15",
   "username":"admin","event_type":"login_failed","status":"failed","message":"Failed login attempt for admin"},
]*6 + [
  {"timestamp":"2026-10-02T10:42:48Z","source_ip":"185.42.18.91","username":"admin",
   "event_type":"login_success","status":"success","message":"Successful login for admin"}
], open("/tmp/t.json","w"))
r = upload("/tmp/t.json", "t.json"); print("  JSON  ->", r.get("event_count"), "events, file", r.get("file_id"))

# NDJSON
with open("/tmp/t.ndjson","w") as f:
    for i in range(6):
        f.write(json.dumps({"ts":f"2026-10-02T10:42:0{i}Z","ip":"185.42.18.91","user":"admin",
                            "event_type":"login_failed","message":"Failed password for admin"})+"\n")
r = upload("/tmp/t.ndjson", "t_ndjson.log"); print("  NDJSON->", r.get("event_count"), "events")

# CSV
with open("/tmp/t.csv","w") as f:
    f.write("timestamp,source_ip,destination_ip,username,event_type,status,message\n")
    for i in range(6):
        f.write(f"2026-10-02T10:42:0{i}Z,185.42.18.91,10.0.0.15,admin,login_failed,failed,Failed login attempt for admin\n")
    f.write("2026-10-02T10:42:50Z,185.42.18.91,10.0.0.15,admin,login_success,success,Successful login for admin\n")
r = upload("/tmp/t.csv", "t.csv"); print("  CSV   ->", r.get("event_count"), "events")

# key=value text with syslog timestamp
with open("/tmp/t.log","w") as f:
    for i in range(6):
        f.write(f"Oct  2 10:42:0{i} auth01 sshd[1]: Failed password for admin from 185.42.18.91 port 5123{i} ssh2\n")
    f.write("Oct  2 10:42:50 auth01 sshd[1]: Accepted password for admin from 185.42.18.91 port 51999 ssh2\n")
r = upload("/tmp/t.log", "t.log"); print("  SYSLOG->", r.get("event_count"), "events")

# key=value
with open("/tmp/t2.log","w") as f:
    for i in range(6):
        f.write(f"ts=2026-10-02T10:42:0{i}Z src=185.42.18.91 dst=10.0.0.15 user=admin event=login_failed status=failed\n")
    f.write("ts=2026-10-02T10:42:50Z src=185.42.18.91 dst=10.0.0.15 user=admin event=login_success status=success\n")
r = upload("/tmp/t2.log", "t2.log"); print("  KV    ->", r.get("event_count"), "events")

for fid, label in [(r.get("file_id"), "KV")]:
    inv = subprocess.run(["curl","-s","-X","POST",f"{B}/api/investigate","-H","Content-Type: application/json",
                          "-d",json.dumps({"file_id":fid})], capture_output=True, text=True).stdout
    inc = json.loads(inv)["incident"]
    print(f"  investigate {label}: {inc['incident_id']} risk={inc['risk_score']} chain={[c['stage_label'] for c in inc['attack_chain']]}")
PY
[ $? = 0 ] && check 1 "all four formats parsed" || check 0 "format parsing"

echo
echo "=============================================================="
echo " TEST 9 — benign logs must NOT be flagged (false-positive control)"
echo "=============================================================="
python3 - <<'PY'
import subprocess, json
B = "http://127.0.0.1:8000"
lines = []
for i in range(30):
    if i % 3 == 0:
        lines.append(f"2026-10-02T10:{40+i//60:02d}:{i%60:02d}Z soc trace: health_check status=ok target=10.0.0.22 latency=4ms")
    elif i % 3 == 1:
        lines.append(f"2026-10-02T10:{40+i//60:02d}:{i%60:02d}Z 10.0.0.22 nginx: api_request GET /api/v1/items status=200 src=10.0.0.31 bytes=1200")
    else:
        lines.append(f"2026-10-02T10:{40+i//60:02d}:{i%60:02d}Z 10.0.0.15 sshd: Accepted password for j.okafor from 10.0.0.5 port 5100{i} ssh2")
open("/tmp/benign.log","w").write("\n".join(lines)+"\n")
up = json.loads(subprocess.run(["curl","-s","-X","POST",f"{B}/api/upload","-F","file=@/tmp/benign.log"],
                               capture_output=True,text=True).stdout)
inv = json.loads(subprocess.run(["curl","-s","-X","POST",f"{B}/api/investigate","-H","Content-Type: application/json",
                                 "-d",json.dumps({"file_id":up["file_id"]})],capture_output=True,text=True).stdout)["incident"]
susp = sum(1 for e in inv["events"] if e.get("suspicious"))
print(f"  30 benign events -> risk={inv['risk_score']} severity={inv['severity']} detections={len(inv['detections'])} suspicious_events={susp}")
print(f"  no_findings={inv.get('no_findings')}")
assert inv["risk_score"] == 0 and len(inv["detections"]) == 0 and susp == 0, "benign events were flagged!"
print("  -> PASS: zero false positives on clean traffic")
PY
[ $? = 0 ] && check 1 "clean log produces zero findings" || check 0 "false positives on benign traffic"

echo
echo "=============================================================="
echo " RESULTS: $PASS passed, $FAIL failed"
echo "=============================================================="
