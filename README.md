# TRACE — Threat Reconstruction & Analysis Cybersecurity Engine

TRACE is an AI-assisted cybersecurity incident investigation platform. It takes security
logs, detects suspicious activity, correlates related events into a single incident,
reconstructs the attack, maps behaviour to MITRE ATT&CK, calculates a transparent risk
score, and produces an incident report plus a response plan.

> TRACE doesn't just detect suspicious logs. It reconstructs the incident, correlates the
> evidence, explains the attack, maps it to known attack techniques, calculates transparent
> risk, and recommends the next response.

```
LOGS → CORRELATION → INCIDENT RECONSTRUCTION → ATTACK GRAPH → MITRE ATT&CK
     → EXPLAINABLE RISK → AI INVESTIGATION → RESPONSE PLAN
```

---

> New here? See **[HOW_TO_RUN.md](./HOW_TO_RUN.md)** for the condensed run steps and a 3-minute demo script.

## Quick start

Two terminals. No external services, no API keys, no database.

### 1. Backend (FastAPI)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate     # optional
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

API at `http://127.0.0.1:8000` · interactive docs at `http://127.0.0.1:8000/docs`

### 2. Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The dev server proxies `/api` to `127.0.0.1:8000`, so no CORS
configuration is needed locally.

### Production build

```bash
cd frontend
npm run build          # outputs frontend/dist
```

Point the built frontend at a remote backend by setting `VITE_API_URL` before building:

```bash
VITE_API_URL=https://trace-api.example.com npm run build
```

---

## Demo in under two minutes

1. Open the dashboard — TRACE logo, system status, event counters.
2. Click **⚡ Demo Attack** (or go to **Simulation** and pick *Brute Force → Account Compromise*).
3. Click **▶ Investigate**.
4. The pipeline runs: parsing → normalizing → detecting → correlating → building incident →
   generating investigation. Each step is driven by the backend response, not a timer.
5. The investigation page opens with the headline, risk score, confidence, source IP and
   affected user immediately visible.
6. Walk the tabs: **Attack Reconstruction**, **Timeline** (clickable), **Attack Graph**,
   **MITRE ATT&CK**, **Risk Analysis**, **Response**.
7. Open **Ask TRACE**, click *"Why is this incident critical?"*.
8. Click **⤓ Export Incident Report** → browser Print → Save as PDF.

---

## Feature overview

| Area | What it does |
|---|---|
| **Dashboard** | Event/incident counters, latest investigation, system status, activity feed |
| **Upload** | Drag & drop `.log` `.txt` `.csv` `.json`; size/type validation; live pipeline |
| **Simulation** | Four synthetic scenarios; Brute Force → Account Compromise fully supported |
| **Parser** | Syslog, key=value, CSV, JSON array and NDJSON → one normalized event schema |
| **Detection** | Brute force, account compromise, privilege escalation, sensitive data access, reconnaissance, exfiltration, suspicious external IP |
| **Correlation** | Union-find over source IP / username / destination → one incident, not four alerts |
| **Incident** | Attack chain, timeline, attack graph, IOCs, narrative summary |
| **Risk** | Transparent 0–100 score, itemised factors, clamped, with a written explanation |
| **MITRE** | T1110, T1078, T1068, T1548, T1005, T1213, T1046, T1041 — only when evidence supports them |
| **AI Investigator** | `POST /api/chat`; uses an LLM if configured, deterministic fallback otherwise |
| **Response** | IMMEDIATE / INVESTIGATE / MONITOR actions with reason + evidence. Advisory only |
| **Report** | Printable, sectioned incident report (browser Print → PDF) |

---

## API contract

Base URL: `VITE_API_URL` (frontend) · all paths are stable.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | `{status, service, version}` |
| `POST` | `/api/upload` | multipart `file` → `{success, file_id, filename, event_count}` |
| `POST` | `/api/investigate` | `{file_id}` → `{success, incident}` |
| `POST` | `/api/simulate` | `{scenario}` → `{success, file_id, incident}` |
| `GET` | `/api/incidents/{incident_id}` | complete incident object |
| `POST` | `/api/chat` | `{incident_id, question}` → `{success, answer, sources}` |

Supporting endpoints: `GET /api/incidents`, `GET /api/stats`, `GET /api/simulate`
(scenario catalogue), `GET /api/files/{file_id}`, `GET /api/chat/suggestions`,
`GET /api/config`, `POST /api/report/{incident_id}`, `POST /api/reset`.

### The incident object

```json
{
  "incident_id": "INC-001",
  "title": "Account Compromise Following Successful Brute Force",
  "headline": "Possible Account Compromise",
  "severity": "critical",
  "risk_score": 94,
  "confidence": 0.94,
  "summary": "An external address 185.42.18.91 ...",
  "events": [],
  "detections": [],
  "timeline": [],
  "attack_chain": [],
  "attack_graph": { "nodes": [], "edges": [], "summary": {} },
  "risk_factors": [],
  "risk_explanation": "Risk is the sum of the triggered factors: ...",
  "mitre_techniques": [],
  "indicators": [],
  "response_actions": []
}
```

### Example requests

```bash
curl http://127.0.0.1:8000/api/health

curl -F "file=@backend/demo_logs/demo_brute_force.log" http://127.0.0.1:8000/api/upload

curl -X POST http://127.0.0.1:8000/api/investigate \
  -H 'Content-Type: application/json' -d '{"file_id":"FILE-001"}'

curl -X POST http://127.0.0.1:8000/api/simulate \
  -H 'Content-Type: application/json' -d '{"scenario":"brute_force"}'

curl -X POST http://127.0.0.1:8000/api/chat \
  -H 'Content-Type: application/json' \
  -d '{"incident_id":"INC-001","question":"Why is this incident critical?"}'
```

---

## Log formats accepted

```
2026-10-02T10:42:01Z 10.0.0.15 sshd: Failed password for admin from 185.42.18.91 port 51234 ssh2
Oct  2 10:42:01 auth01 sshd[2211]: Failed password for admin from 185.42.18.91 port 51234 ssh2
ts=2026-10-02T10:42:01Z src=185.42.18.91 dst=10.0.0.15 user=admin event=login_failed status=failed
```

```csv
timestamp,source_ip,destination_ip,username,event_type,status,message
2026-10-02T10:42:01Z,185.42.18.91,10.0.0.15,admin,login_failed,failed,Failed login attempt for admin
```

```json
[{"timestamp":"2026-10-02T10:42:01Z","source_ip":"185.42.18.91","username":"admin",
  "event_type":"login_failed","status":"failed","message":"Failed login attempt for admin"}]
```

Field names are matched case-insensitively against common synonyms (`src_ip`, `client_ip`,
`account`, `msg`, `@timestamp`, …). Events without an explicit type are classified from their
message text. Anything unparseable returns HTTP 400 with:

> The uploaded file could not be parsed. Supported formats: LOG, TXT, CSV, JSON.

---

## Detection rules

| Detection | Trigger | Severity |
|---|---|---|
| `brute_force` | ≥5 failed logins, same IP + user, inside a 15-minute window (also detects spraying across ≥3 accounts) | high |
| `account_compromise` | ≥3 failures (≥5 across IPs) followed by a success for the same account inside 120 min | critical |
| `privilege_escalation` | `sudo` / root / admin-privilege / `setuid` indicators | high |
| `sensitive_data_access` | DB, credential, secret or confidential-data access by a compromised account | critical |
| `data_exfiltration` | ≥5 MB, or external destination with ≥1 MB, or explicitly flagged bulk transfer | critical |
| `reconnaissance` | port scan / probing / enumeration activity | medium |
| `suspicious_source_ip` | any non-RFC1918 address driving a detection | high |

Routine traffic is explicitly suppressed (e.g. a `metrics_db` stats query is not treated as
sensitive data access), and a log with no findings returns risk `0` with `no_findings: true`
rather than a fabricated incident.

## Risk model

```
Repeated authentication failures      +25
Successful login after failures       +20
Privilege escalation                  +20
Sensitive data access                 +20
Suspicious external source IP         +15
Pre-attack reconnaissance              +8
Bulk outbound data transfer           +15
-------------------------------------------
raw total, clamped to 0..100
```

Severity bands: `85+ critical · 70+ high · 45+ medium · 20+ low`.
Confidence is a severity-weighted mean of the contributing detections.

---

## Configuration

Backend (`backend/.env`, all optional — see `.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `TRACE_CORS_ORIGINS` | localhost:5173/4173 | allowed browser origins |
| `TRACE_MAX_UPLOAD_BYTES` | `5242880` | upload size cap (5 MB) |
| `TRACE_MAX_EVENTS` | `20000` | events parsed per file |
| `TRACE_LLM_API_KEY` | *(empty)* | **optional** — enables the LLM answer path |
| `TRACE_LLM_BASE_URL` | OpenAI | OpenAI-compatible endpoint |
| `TRACE_LLM_MODEL` | `gpt-4o-mini` | model name |
| `TRACE_LLM_TIMEOUT` | `12` | seconds before falling back |
| `TRACE_DEFAULT_LOG_YEAR` | `2026` | year for year-less syslog timestamps |

Frontend (`frontend/.env`, see `.env.example`): `VITE_API_URL`, `VITE_PROXY_TARGET`.

Leave `TRACE_LLM_API_KEY` empty and the AI Investigator runs its deterministic
evidence-grounded fallback. **Detection, correlation, risk, MITRE and the response plan never
depend on an LLM** — the platform behaves identically with or without a provider.

---

## Project structure

```
trace/
├── backend/
│   ├── app/
│   │   ├── main.py                 FastAPI app, CORS, exception handlers
│   │   ├── config.py               env-driven configuration
│   │   ├── routes/trace.py         /api/* endpoints
│   │   ├── services/
│   │   │   ├── investigation.py    orchestration: parse→detect→correlate→incident
│   │   │   └── chat.py             AI investigator + deterministic fallback
│   │   ├── engines/
│   │   │   ├── parser.py           multi-format log parser + normalizer
│   │   │   ├── detection.py        deterministic detection rules
│   │   │   ├── correlation.py      union-find incident correlation
│   │   │   ├── risk.py             transparent risk scoring
│   │   │   ├── mitre.py            evidence-gated ATT&CK mapping
│   │   │   ├── incident.py         chain, timeline, graph, IOCs, summary
│   │   │   ├── response.py         response plan
│   │   │   └── demo.py             synthetic attack log generator
│   │   ├── models/schemas.py       request/response models
│   │   └── utils/                  in-memory store, upload security
│   ├── demo_logs/                  generated demo logs + generate.py
│   ├── tests/acceptance.sh         end-to-end API acceptance test
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx, Layout.jsx, main.jsx
│   │   ├── components/             ui, RiskGauge, Timeline, AttackGraph, AIInvestigator, ReportView
│   │   ├── pages/                  Dashboard, UploadLog, Simulation, Incidents, Investigation
│   │   ├── services/api.js         single source of API URLs
│   │   ├── hooks/useBackend.js     health + stats polling hook
│   │   └── utils/format.js
│   ├── package.json, vite.config.js, .env.example,
└── .gitignore
```

---

## Testing

With the backend running:

```bash
bash backend/tests/acceptance.sh
```

Covers health, upload, investigate, all four simulations, incident retrieval, chat (six
questions), upload/parse error handling, four log formats, and a false-positive control that
asserts a clean 30-event log yields risk `0` with no detections.

---

## Security notes

- Uploads validated by extension, size and binary-content sniff; filenames sanitized to a safe
  basename (path traversal and null bytes rejected).
- Uploaded content is **never** executed, never passed to a shell, never written to disk.
- Logs and incidents live in backend memory only and are dropped on restart; `POST /api/reset`
  clears them on demand.
- API keys stay server-side in environment variables; the frontend never receives a secret.
- CORS is an explicit origin allow-list, not `*`.
- Response recommendations are advisory — TRACE executes no destructive action.
