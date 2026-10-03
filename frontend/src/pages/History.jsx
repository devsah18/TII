import React, { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, Alert, Spinner, Empty, SeverityBadge } from '../components/ui.jsx'
import { TopBar } from '../Layout.jsx'
import { getHistory, ApiError } from '../services/api.js'
import { relativeTime, fmtTime, scoreColour } from '../utils/format.js'

/**
 * Analysis history. Every automatic run (upload, scenario, pcap, live capture,
 * tuning) is listed newest-first with its outcome; click a run to open the
 * incident it produced.
 */
const SOURCE_LABEL = {
  upload: 'Upload',
  pcap: 'PCAP',
  simulation: 'Scenario',
  live: 'Live',
  reanalyze: 'Tuning',
}

export default function History({ online }) {
  const navigate = useNavigate()
  const [runs, setRuns] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState(null)
  const timer = useRef(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const res = await getHistory(60)
        if (!cancelled) {
          setRuns(res.runs || [])
          setError('')
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof ApiError ? err.message : 'Could not load history.')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    timer.current = setInterval(load, 5000)
    return () => {
      cancelled = true
      clearInterval(timer.current)
    }
  }, [])

  return (
    <>
      <TopBar
        title="Analysis History"
        subtitle="Every automatic analysis run, newest first — click a row to open its incident."
        online={online}
      >
        <button className="btn" onClick={() => setRuns((r) => [...r])}>
          ↻ Refresh
        </button>
      </TopBar>

      {error && (
        <div style={{ marginBottom: 16 }}>
          <Alert kind="error" title="Could not load history">{error}</Alert>
        </div>
      )}

      <Card
        title={`Runs (${runs.length})`}
        icon="🗃"
        note="Uploads, scenarios, packet captures, live captures and tuning runs"
      >
        {loading ? (
          <Spinner label="Loading history…" />
        ) : runs.length === 0 ? (
          <Empty>
            No analysis runs yet. Load a scenario, upload a log/pcap, or start a live capture.
          </Empty>
        ) : (
          <div className="stack" style={{ gap: 8 }}>
            {runs.map((r) => (
              <div key={r.run_id}>
                <div
                  className="history-row"
                  onClick={() => r.incident_id && navigate(`/incidents/${r.incident_id}`)}
                >
                  <span className={`history-src src-${r.source}`}>{SOURCE_LABEL[r.source] || r.source}</span>
                  <span className="mono" style={{ fontSize: '0.74rem' }}>{r.run_id}</span>
                  <span style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.label}
                  </span>
                  <span className="mono" style={{ color: scoreColour(r.risk_score || 0), fontWeight: 700 }}>
                    {r.risk_score ?? '—'}
                  </span>
                  <span className="card-note" style={{ fontSize: '0.72rem' }}>
                    {r.incident_id || '—'} · {relativeTime(r.at) || fmtTime(r.at)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </>
  )
}