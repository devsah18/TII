import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, Alert, Spinner, Empty, SeverityBadge } from '../components/ui.jsx'
import { TopBar } from '../Layout.jsx'
import { listIncidents, ApiError } from '../services/api.js'
import { fmtTime, fmtPct, scoreColour } from '../utils/format.js'

export default function Incidents({ online }) {
  const navigate = useNavigate()
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  function load() {
    setLoading(true)
    listIncidents()
      .then((res) => {
        setIncidents(res.incidents || [])
        setError('')
      })
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Could not load incidents.'))
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  return (
    <>
      <TopBar
        title="Incidents"
        subtitle="Every investigation opened in this session, newest first."
        online={online}
      >
        <button className="btn" onClick={load} disabled={loading}>
          ↻ Refresh
        </button>
        <button className="btn btn-primary" onClick={() => navigate('/simulation')}>
          ⚡ New Simulation
        </button>
      </TopBar>

      {error && (
        <div style={{ marginBottom: 16 }}>
          <Alert kind="error" title="Could not load incidents">
            {error}
          </Alert>
        </div>
      )}

      <Card title={`Tracked incidents (${incidents.length})`} icon="◷">
        {loading ? (
          <Spinner label="Loading incidents…" />
        ) : incidents.length === 0 ? (
          <Empty>
            No incidents yet. Run a demo attack from the <strong>Simulation</strong> page, or upload a
            log from <strong>Upload Log</strong>.
          </Empty>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Incident</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Confidence</th>
                  <th>User</th>
                  <th>Source</th>
                  <th>Events</th>
                  <th>Detected</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((i) => (
                  <tr
                    key={i.incident_id}
                    style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/incidents/${i.incident_id}`)}
                  >
                    <td className="mono">{i.incident_id}</td>
                    <td>{i.title}</td>
                    <td>
                      <SeverityBadge severity={i.severity} />
                    </td>
                    <td className="mono" style={{ color: scoreColour(i.risk_score), fontWeight: 700 }}>
                      {i.risk_score}
                    </td>
                    <td>{fmtPct(i.confidence)}</td>
                    <td className="mono">{i.affected_user || '—'}</td>
                    <td className="mono">{i.source_ip || '—'}</td>
                    <td className="mono">{i.event_count}</td>
                    <td className="card-note">{fmtTime(i.first_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  )
}
