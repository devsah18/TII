import React, { useState } from 'react'
import { Card, Alert } from './ui.jsx'
import { reanalyze, ApiError } from '../services/api.js'

/**
 * Detection rule tuning. The analyst moves the thresholds and re-runs the SAME
 * deterministic detection engine (POST /api/reanalyze); the incident and its
 * risk score update immediately. This proves the rules are real, tunable code.
 */
const DEFAULTS = {
  brute_force_min_failures: 5,
  brute_force_window_min: 15,
  exfil_bytes_threshold: 5 * 1024 * 1024,
}

export default function ThresholdPanel({ incident, onReanalyzed }) {
  const fileId = incident.source_file?.file_id
  const [t, setT] = useState(DEFAULTS)
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState('')
  const [error, setError] = useState('')

  async function run() {
    if (!fileId) return
    setBusy(true)
    setError('')
    setNote('')
    try {
      const res = await reanalyze(fileId, t)
      setNote(
        `Re-ran with min_failures=${t.brute_force_min_failures}: risk ${res.incident.risk_score}/100, ` +
          `${res.incident.detection_count} detection(s).`,
      )
      if (onReanalyzed) onReanalyzed(res.incident)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Re-analysis failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Detection Tuning" icon="🎛" note="Move the thresholds and re-run the deterministic engine">
      {!fileId ? (
        <Alert kind="warn" title="No source file">This incident has no attached file to re-analyse.</Alert>
      ) : (
        <div className="stack" style={{ gap: 14 }}>
          <Slider
            label="Brute-force min failures"
            value={t.brute_force_min_failures}
            min={2}
            max={20}
            step={1}
            onChange={(v) => setT((s) => ({ ...s, brute_force_min_failures: v }))}
          />
          <Slider
            label="Correlation window (minutes)"
            value={t.brute_force_window_min}
            min={1}
            max={60}
            step={1}
            onChange={(v) => setT((s) => ({ ...s, brute_force_window_min: v }))}
          />
          <Slider
            label="Exfil size threshold (MB)"
            value={Math.round(t.exfil_bytes_threshold / (1024 * 1024))}
            min={1}
            max={50}
            step={1}
            onChange={(v) => setT((s) => ({ ...s, exfil_bytes_threshold: v * 1024 * 1024 }))}
          />
          <div className="row" style={{ gap: 9 }}>
            <button className="btn btn-primary" onClick={run} disabled={busy}>
              {busy ? 'Re-analysing…' : '↻ Re-run detection'}
            </button>
            <button className="btn btn-ghost" onClick={() => setT(DEFAULTS)} disabled={busy}>
              Reset to defaults
            </button>
          </div>
          {note && <Alert kind="ok" title="Re-analysed">{note}</Alert>}
          {error && <Alert kind="error" title="Tuning failed">{error}</Alert>}
          <p className="card-note">
            Defaults: 5 failures · 15-minute window · 5 MB. Lowering a threshold makes detection more
            sensitive (higher risk); raising it makes it stricter.
          </p>
        </div>
      )}
    </Card>
  )
}

function Slider({ label, value, min, max, step, onChange }) {
  return (
    <div>
      <div className="spread">
        <span className="meta-label">{label}</span>
        <span className="mono" style={{ fontWeight: 700 }}>{value}</span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        style={{ width: '100%', marginTop: 6, accentColor: 'var(--accent)' }}
      />
    </div>
  )
}