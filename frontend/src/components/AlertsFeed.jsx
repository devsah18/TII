import React, { useEffect, useRef, useState } from 'react'
import { Card, Empty, Spinner } from './ui.jsx'
import { getAlerts, ackAlert, ApiError } from '../services/api.js'
import { relativeTime } from '../utils/format.js'

/**
 * Live alert feed. Polls GET /api/alerts every few seconds, so new detections
 * appear automatically as incidents are reconstructed. Alerts can be
 * acknowledged (POST /api/alerts/{id}/ack).
 */
const DOT = {
  critical: 'dot-bad',
  high: 'dot-warn',
  medium: 'dot-warn',
  low: 'dot-ok',
  info: 'dot-ok',
}

export default function AlertsFeed({ pollMs = 4000, onOpenIncident }) {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const timer = useRef(null)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const res = await getAlerts(40)
        if (!cancelled) {
          setAlerts(res.alerts || [])
          setError('')
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof ApiError ? err.message : 'Could not load alerts.')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    timer.current = setInterval(load, pollMs)
    return () => {
      cancelled = true
      clearInterval(timer.current)
    }
  }, [pollMs])

  async function ack(a) {
    try {
      await ackAlert(a.id)
      setAlerts((prev) => prev.map((x) => (x.id === a.id ? { ...x, acknowledged: true } : x)))
    } catch {
      /* keep it simple; next poll refreshes */
    }
  }

  const unacked = alerts.filter((a) => !a.acknowledged).length

  return (
    <Card
      title="Live Alerts"
      icon="🔔"
      note={`${unacked} unacknowledged · auto-refreshing every ${Math.round(pollMs / 1000)}s`}
    >
      {loading ? (
        <Spinner label="Loading alerts…" />
      ) : error ? (
        <Empty>{error}</Empty>
      ) : alerts.length === 0 ? (
        <Empty>No alerts yet. Load a scenario or upload a log to generate detections.</Empty>
      ) : (
        <div className="stack" style={{ gap: 8, maxHeight: 460, overflowY: 'auto' }}>
          {alerts.map((a) => (
            <div
              key={a.id}
              className="alert-item"
              style={{ opacity: a.acknowledged ? 0.5 : 1, cursor: a.incident_id ? 'pointer' : 'default' }}
              onClick={() => a.incident_id && onOpenIncident && onOpenIncident(a.incident_id)}
            >
              <span className={`dot ${DOT[a.level] || 'dot-ok'}`} style={{ marginTop: 6, flex: 'none' }} />
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="spread" style={{ gap: 8 }}>
                  <strong style={{ fontSize: '0.85rem' }}>{a.title}</strong>
                  <span className="badge badge-neutral mono" style={{ fontSize: '0.62rem' }}>{a.level}</span>
                </div>
                {a.detail ? (
                  <div className="card-note" style={{ fontSize: '0.75rem' }}>{a.detail}</div>
                ) : null}
                <div className="card-note" style={{ fontSize: '0.7rem' }}>
                  {a.incident_id ? <span className="mono">{a.incident_id}</span> : 'system'} ·{' '}
                  {a.source_ip ? <span className="mono">{a.source_ip}</span> : 'no source'} · {relativeTime(a.at) || a.at}
                </div>
              </div>
              {!a.acknowledged && (
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={(e) => {
                    e.stopPropagation()
                    ack(a)
                  }}
                >
                  Ack
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}