import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, StatCard, Alert, SeverityBadge, Spinner, Empty, Bar } from '../components/ui.jsx'
import { TopBar } from '../Layout.jsx'
import AlertsFeed from '../components/AlertsFeed.jsx'
import useBackend from '../hooks/useBackend.js'
import { simulate, listIncidents, listScenarioCatalog, loadScenario, ApiError } from '../services/api.js'
import { fmtTime, relativeTime, scoreColour, fmtPct } from '../utils/format.js'

export default function Dashboard() {
  const navigate = useNavigate()
  const { health, stats, error, loading, refresh, online } = useBackend()
  const [simulating, setSimulating] = useState(false)
  const [simError, setSimError] = useState('')
  const [incidents, setIncidents] = useState([])
  const [scenarios, setScenarios] = useState([])
  const [scenario, setScenario] = useState('brute_force')
  const [selectedPlaybook, setSelectedPlaybook] = useState('containment')
  const [selectedTask, setSelectedTask] = useState('account-compromise')

  const playbooks = [
    {
      id: 'containment',
      title: 'Containment & isolation',
      category: 'Immediate response',
      summary: 'Limit blast radius before the attack can spread to adjacent systems.',
      steps: ['Isolate affected endpoint and source IP ranges.', 'Reset compromised account credentials.', 'Block outbound exfiltration paths.'],
    },
    {
      id: 'investigation',
      title: 'Evidence collection',
      category: 'Forensics',
      summary: 'Capture the exact sequence of events and preserve forensic evidence.',
      steps: ['Pull authentication and firewall logs around the first failed login.', 'Review privilege changes and access to sensitive data.', 'Document the timeline for escalation owners.'],
    },
    {
      id: 'hardening',
      title: 'Credential hardening',
      category: 'Resilience',
      summary: 'Reduce the chance of reruns by tightening account security controls.',
      steps: ['Require MFA on implicated accounts.', 'Review password reset and session revocation.', 'Check for token reuse or suspicious admin activity.'],
    },
  ]

  const priorityQueue = [
    {
      id: 'account-compromise',
      title: 'Account compromise investigation',
      severity: 'critical',
      owner: 'SOC lead',
      eta: 'Next 15 min',
      detail: 'The login sequence shows a successful authentication after repeated failures from an external source IP.',
    },
    {
      id: 'privilege-escalation',
      title: 'Privilege escalation review',
      severity: 'high',
      owner: 'IR analyst',
      eta: 'Next 30 min',
      detail: 'Administrative command usage and elevated access indicators require immediate validation.',
    },
    {
      id: 'data-access',
      title: 'Sensitive data access check',
      severity: 'high',
      owner: 'Data protection',
      eta: 'Next 45 min',
      detail: 'Access to credential or confidential data should be verified and scoped to approved users only.',
    },
  ]

  const activePlaybook = playbooks.find((p) => p.id === selectedPlaybook) || playbooks[0]
  const activeTask = priorityQueue.find((t) => t.id === selectedTask) || priorityQueue[0]

  React.useEffect(() => {
    if (!online) return
    listScenarioCatalog()
      .then((list) => {
        if (list?.length) {
          setScenarios(list)
          setScenario((prev) => (list.some((s) => s.id === prev) ? prev : list[0].id))
        }
      })
      .catch(() => {})
  }, [online])

  React.useEffect(() => {
    if (!online) return
    listIncidents()
      .then((res) => setIncidents(res.incidents || []))
      .catch(() => setIncidents([]))
  }, [online, stats?.active_incidents])

  async function loadSelected() {
    setSimulating(true)
    setSimError('')
    try {
      const res = await loadScenario(scenario)
      await refresh()
      navigate(`/incidents/${res.incident.incident_id}`)
    } catch (err) {
      setSimError(err instanceof ApiError ? err.message : 'The scenario could not be loaded.')
    } finally {
      setSimulating(false)
    }
  }

  async function runDemo() {
    setSimulating(true)
    setSimError('')
    try {
      const res = await simulate('brute_force')
      await refresh()
      navigate(`/incidents/${res.incident.incident_id}`)
    } catch (err) {
      setSimError(err instanceof ApiError ? err.message : 'The simulation could not be run.')
    } finally {
      setSimulating(false)
    }
  }

  const latest = stats?.latest_investigation
  const status = stats?.system_status

  return (
    <>
      <TopBar
        title="Security Operations Dashboard"
        subtitle="Upload logs, reconstruct incidents and investigate evidence."
        online={online}
      >
        {scenarios.length > 0 && (
          <>
            <select
              className="select"
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
              disabled={simulating || !online}
              aria-label="Demo scenario"
            >
              {scenarios.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
            <button className="btn" onClick={loadSelected} disabled={simulating || !online}>
              {simulating ? 'Loading…' : '▶ Load scenario'}
            </button>
          </>
        )}
        <button className="btn" onClick={refresh} disabled={loading}>
          ↻ Refresh
        </button>
        <button className="btn btn-danger" onClick={runDemo} disabled={simulating || !online}>
          {simulating ? 'Simulating…' : '⚡ Demo Attack'}
        </button>
        <button className="btn btn-primary" onClick={() => navigate('/upload')} disabled={!online}>
          ⬆ Upload Log
        </button>
      </TopBar>

      {error && (
        <div style={{ marginBottom: 16 }}>
          <Alert kind="error" title="TRACE backend unavailable">
            {error.message} Start it with{' '}
            <span className="mono">uvicorn app.main:app --reload --port 8000</span> inside{' '}
            <span className="mono">backend/</span>, then refresh.
            {error.detail?.detail ? ` (${String(error.detail.detail).slice(0, 160)})` : ''}
          </Alert>
        </div>
      )}

      {simError && (
        <div style={{ marginBottom: 16 }}>
          <Alert kind="error" title="Simulation failed">
            {simError}
          </Alert>
        </div>
      )}

      <div className="grid grid-4" style={{ marginBottom: 15 }}>
        <StatCard
          label="Total Events"
          value={stats?.total_events ?? 0}
          foot="Events parsed across all tracked files"
          colour="#38bdf8"
          loading={loading}
        />
        <StatCard
          label="Suspicious Events"
          value={stats?.suspicious_events ?? 0}
          foot="Events matched by a detection rule"
          colour="#f97316"
          loading={loading}
        />
        <StatCard
          label="Active Incidents"
          value={stats?.active_incidents ?? 0}
          foot={`${stats?.high_incidents ?? 0} high severity`}
          colour="#a855f7"
          loading={loading}
        />
        <StatCard
          label="Critical Incidents"
          value={stats?.critical_incidents ?? 0}
          foot="Requiring immediate containment"
          colour="#ef4444"
          loading={loading}
        />
      </div>

      <div className="grid grid-7-5" style={{ marginBottom: 15 }}>
        <Card title="Latest Investigation" icon="🔎" note="Most recent incident reconstructed by TRACE">
          {loading ? (
            <Spinner label="Loading investigation…" />
          ) : !latest ? (
            <Empty>
              No investigations yet. Click <strong>Demo Attack</strong> above to run the built-in
              brute-force → account-compromise scenario, or upload your own log.
            </Empty>
          ) : (
            <>
              <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ minWidth: 0 }}>
                  <div className="hero-id">{latest.incident_id}</div>
                  <h2 style={{ marginTop: 4 }}>{latest.title}</h2>
                  <div className="card-note mt-8">
                    User <span className="mono">{latest.affected_user || '—'}</span> · Source{' '}
                    <span className="mono">{latest.source_ip || '—'}</span> · First seen{' '}
                    <span className="mono">{fmtTime(latest.first_seen)}</span>
                  </div>
                </div>
                <SeverityBadge severity={latest.severity} />
              </div>

              <div className="row mt-16" style={{ gap: 20 }}>
                <div style={{ minWidth: 168, flex: 1 }}>
                  <div className="meta-label">Risk score</div>
                  <div className="row" style={{ gap: 10 }}>
                    <span className="stat-value" style={{ color: scoreColour(latest.risk_score) }}>
                      {latest.risk_score}
                    </span>
                    <span className="card-note">/ 100</span>
                  </div>
                  <Bar value={latest.risk_score} />
                </div>
                <button
                  className="btn btn-primary"
                  onClick={() => navigate(`/incidents/${latest.incident_id}`)}
                >
                  Open Investigation →
                </button>
              </div>
            </>
          )}
        </Card>

        <Card title="System Status" icon="🛡" note="Pipeline components">
          {loading ? (
            <Spinner />
          ) : !status ? (
            <Empty>Status unavailable: the backend did not respond.</Empty>
          ) : (
            <div className="kv-list">
              {[
                ['API', status.api],
                ['Log parser', status.parser],
                ['Detection engine', status.detection],
                ['Correlation engine', status.correlation],
                ['AI investigator', status.ai_investigator],
                ['Storage', status.storage],
              ].map(([k, v]) => (
                <div className="kv-row" key={k}>
                  <span className="k">{k}</span>
                  <span className="row" style={{ gap: 7 }}>
                    <span
                      className={`dot ${
                        v === 'operational' || v === 'llm'
                          ? 'dot-ok'
                          : v === 'deterministic-fallback'
                            ? 'dot-warn'
                            : 'dot-bad'
                      }`}
                    />
                    <span className="mono" style={{ fontSize: '0.79rem' }}>
                      {v}
                    </span>
                  </span>
                </div>
              ))}
              <div className="kv-row">
                <span className="k">Version</span>
                <span className="mono" style={{ fontSize: '0.79rem' }}>
                  {status.service} v{status.version}
                </span>
              </div>
            </div>
          )}
        </Card>
      </div>

      {online && (
        <div style={{ marginTop: 16 }}>
          <AlertsFeed onOpenIncident={(id) => navigate(`/incidents/${id}`)} />
        </div>
      )}

      <div className="grid grid-7-5">
        <Card
          title="Incidents"
          icon="◷"
          note={`${incidents.length} incident(s) tracked in memory`}
          action={
            incidents.length > 0 ? (
              <button className="btn btn-sm" onClick={() => navigate('/incidents')}>
                View all
              </button>
            ) : null
          }
        >
          {incidents.length === 0 ? (
            <Empty>No incidents recorded yet.</Empty>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Confidence</th>
                  <th>User</th>
                  <th>Detected</th>
                </tr>
              </thead>
              <tbody>
                {incidents.slice(0, 6).map((i) => (
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
                    <td className="mono" style={{ color: scoreColour(i.risk_score) }}>
                      {i.risk_score}
                    </td>
                    <td>{fmtPct(i.confidence)}</td>
                    <td className="mono">{i.affected_user || '—'}</td>
                    <td className="card-note">{fmtTime(i.first_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card title="Recent Activity" icon="◌" note="Backend audit trail for this session">
          {!stats?.recent_activity?.length ? (
            <Empty>No activity yet.</Empty>
          ) : (
            <div className="stack" style={{ gap: 9 }}>
              {stats.recent_activity.map((a, i) => (
                <div key={i} className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
                  <span
                    className={`dot ${
                      a.kind === 'simulation' ? 'dot-warn' : a.kind === 'investigation' ? 'dot-bad' : 'dot-ok'
                    }`}
                    style={{ marginTop: 6 }}
                  />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: '0.85rem' }}>{a.message}</div>
                    <div className="card-note" style={{ fontSize: '0.72rem' }}>
                      {a.kind} · {relativeTime(a.at) || a.at}
                      {a.meta?.risk_score !== undefined ? ` · risk ${a.meta.risk_score}` : ''}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div className="grid grid-2 mt-16">
        <Card title="Priority queue" icon="🚨" note="Recommended triage order for active investigation">
          <div className="stack" style={{ gap: 10 }}>
            {priorityQueue.map((task) => (
              <button
                key={task.id}
                type="button"
                className={`task-card ${selectedTask === task.id ? 'selected' : ''}`}
                onClick={() => setSelectedTask(task.id)}
              >
                <div className="row spread" style={{ alignItems: 'flex-start' }}>
                  <div>
                    <div className="task-title">{task.title}</div>
                    <div className="task-meta">{task.owner} · {task.eta}</div>
                  </div>
                  <SeverityBadge severity={task.severity} />
                </div>
              </button>
            ))}
          </div>
        </Card>

        <Card title="Response playbooks" icon="🧩" note="Operational playbooks to apply from the SOC dashboard">
          <div className="chip-row" style={{ marginTop: 0, marginBottom: 14 }}>
            {playbooks.map((playbook) => (
              <button
                key={playbook.id}
                type="button"
                className={`chip ${selectedPlaybook === playbook.id ? 'selected' : ''}`}
                onClick={() => setSelectedPlaybook(playbook.id)}
              >
                {playbook.title}
              </button>
            ))}
          </div>

          <div className="playbook-panel">
            <div className="group-label">{activePlaybook.category}</div>
            <h3 style={{ marginTop: 8 }}>{activePlaybook.title}</h3>
            <p className="card-note mt-8">{activePlaybook.summary}</p>
            <ul className="playbook-list">
              {activePlaybook.steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
          </div>

          <div className="playbook-focus mt-16">
            <div className="group-label">Current focus</div>
            <div className="focus-title">{activeTask.title}</div>
            <p className="card-note mt-8">{activeTask.detail}</p>
          </div>
        </Card>
      </div>

      <Card
        title="How TRACE works"
        icon="🧭"
        note="One correlated incident instead of a pile of unrelated alerts"
        className="mt-16"
      >
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          {[
            'Logs',
            'Normalisation',
            'Detection',
            'Correlation',
            'Incident reconstruction',
            'Attack graph',
            'MITRE ATT&CK',
            'Explainable risk',
            'AI investigation',
            'Response plan',
          ].map((s, i, arr) => (
            <React.Fragment key={s}>
              <span className="pill" style={{ fontSize: '0.76rem' }}>
                {s}
              </span>
              {i < arr.length - 1 && <span style={{ color: '#38506f' }}>→</span>}
            </React.Fragment>
          ))}
        </div>
        <p className="card-note mt-12">
          Detection, correlation, risk scoring and MITRE mapping are deterministic rules over the
          normalized events, so every finding can be traced back to specific log lines. The AI layer
          only explains the evidence that already exists.
        </p>
      </Card>
    </>
  )
}
