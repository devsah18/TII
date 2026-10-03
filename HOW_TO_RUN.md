# TRACE — How to Run + Demo Script

## How to run (2 terminals, no API keys, no database)

1. **Backend:** `cd backend` then `python -m venv .venv` then `.venv\Scripts\Activate.ps1` then `pip install -r requirements.txt` then `uvicorn app.main:app --reload --port 8000` (API at http://127.0.0.1:8000, docs at /docs).
2. **Frontend:** `cd frontend` then `npm install` then `npm run dev`, and open http://localhost:5173 (the dev server proxies `/api` to the backend, so no CORS setup is needed).
3. **Optional AI explanations:** set `TRACE_LLM_API_KEY` (and `TRACE_LLM_BASE_URL`/`TRACE_LLM_MODEL`) in the environment; with no key the AI Investigator uses its deterministic, evidence-grounded fallback. Detection, correlation, risk, MITRE and the response plan are always deterministic and never call an LLM.

## Demo script (under 3 minutes)

1. Open http://localhost:5173  the dashboard shows live counters, system status and the latest investigation.
2. Pick a scenario from the **dropdown** (or use **⚡ Demo Attack**) and click **▶ Load scenario** — the backend generates the log and reconstructs the incident.
3. The investigation page opens: severity badge + risk score, the attack chain, then walk the tabs — **Timeline** (clickable), **Attack Graph** (External IP → Account → Server → Resource → Destination), **MITRE ATT&CK**, **Risk Analysis** ("why" breakdown), **Response** (immediate / investigation / monitoring).
4. Open **Ask TRACE** and click a chip (e.g. *"Why is this critical?"*) — answers cite the incident's own evidence; with no API key the deterministic fallback replies.
5. Repeat with **Brute Force**, **Account Compromise**, **Privilege Escalation** and **Data Exfiltration**; then **⤓ Export Incident Report** → Print → Save as PDF.
6. Optional CLI smoke test: `curl.exe http://127.0.0.1:8000/api/health` and `curl.exe -X POST http://127.0.0.1:8000/api/scenarios/brute_force/load`.—