import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, Alert, PipelineSteps, SeverityBadge, Spinner, Empty, Bar } from '../components/ui.jsx'
import { TopBar } from '../Layout.jsx'
import { getScenarios, simulate, ApiError } from '../services/api.js'
import { scoreColour } from '../utils/format.js'

const STEPS = [
  { id: 'generate', label: 'Generating synthetic log' },
  { id: 'parse', label: 'Parsing logs' },
  { id: 'normalize', label: 'Normalizing events' },
  { id: 'detect', label: 'Detecting anomalies' },
  { id: 'correlate', label: 'Correlating events' },
  { id: 'incident', label: 'Building incident' },
  { id: 'report', label: 'Generating investigation' },
]

const FALLBACK_SCENARIOS = [
  {
    id: 'brute_force',
    name: 'Brute Force → Account Compromise',
    description:
      'External brute force against the admin account, followed by a successful login, privilege escalation and sensitive data access.',
    primary: true,
    expected_severity: 'critical',
    expected_stages: [
      'Reconnaissance',
      'Brute Force',
      'Account Compromise',
      'Privilege Escalation',
      'Sensitive Data Access',
      'Data Exfiltration',
    ],
  },
  { id: 'account_compromise', name: 'Account Compromise', description: 'Credential stuffing against several accounts from one external address.', expected_severity: 'critical', expected_stages: ['Reconnaissance', 'Brute Force', 'Account Compromise'] },
  { id: 'privilege_escalation', name: 'Privilege Escalation', description: 'A valid session elevates to root via sudo and then reads sensitive files.', expected_severity: 'critical', expected_stages: ['Reconnaissance', 'Brute Force', 'Account Compromise', 'Privilege Escalation'] },
  { id: 'data_exfiltration', name: 'Data Exfiltration', description: 'An authorised account bulk-exports the customer database to an external host.', expected_severity: 'critical', expected_stages: ['Sensitive Data Access', 'Data Exfiltration'] },
]

export default function Simulation({ online, onInvestigated }) {
  const navigate = useNavigate()
  const [scenarios, setScenarios] = useState(FALLBACK_SCENARIOS)
  const [selected, setSelected] = useState('brute_force')
  const [steps, setSteps] = useState(() => STEPS.map((s) => ({ ...s, status: 'pending' })))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)

  useEffect(() => {
    getScenarios()
      .then((res) => {
        if (res?.scenarios?.length) setScenarios(res.scenarios)
      })
      .catch(() => {})
  }, [])

  function setStep(id, status, detail) {
    setSteps((prev) => prev.map((s) => (s.id === id ? { ...s, status, detail: detail ?? s.detail } : s)))
  }

  async function run() {
    setBusy(true)
    setError('')
    setResult(null)
    setSteps(STEPS.map((s) => ({ ...s, status: 'pending' })))
    try {
      setStep('generate', 'active')
      const res = await simulate(selected)
      const inc = res.incident
      setStep('generate', 'done', `${res.event_count} events`)
      setStep('parse', 'done', `file ${res.file_id}`)
      setStep('normalize', 'done', 'schema applied')
      setStep('detect', 'done', `${inc.detection_count} detection(s)`)
      setStep('correlate', 'done', `${inc.event_count} correlated`)
      setStep('incident', 'done', inc.incident_id)
      setStep('report', 'done', `${inc.mitre_techniques?.length || 0} techniques`)
      setResult(res)
      if (onInvestigated) onInvestigated(inc)
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'The simulation could not be completed.'
      setError(message)
      setSteps((prev) => prev.map((s) => (s.status === 'active' ? { ...s, status: 'failed' } : s)))
    } finally {
      setBusy(false)
    }
  }

  const active = scenarios.find((s) => s.id === selected) || scenarios[0]

  return (
    <>
      <TopBar
        title="Simulate Attack"
        subtitle="Generate a realistic synthetic security log and investigate it end to end."
        online={online}
      />

      <div className="grid grid-7-5">
        <Card title="Demo Attack Scenarios" icon="⚡" note="No external log required — the backend writes the log itself">
          <div className="stack" style={{ gap: 11 }}>
            {scenarios.map((s) => (
              <button
                key={s.id}
                className={`card card-pad ${selected === s.id ? '' : ''}`}
                onClick={() => setSelected(s.id)}
                disabled={busy}
                style={{
                  textAlign: 'left',
                  cursor: 'pointer',
                  borderColor: selected === s.id ? 'rgba(56,189,248,0.5)' : undefined,
                  background: selected === s.id ? 'rgba(56,189,248,0.08)' : undefined,
                  font: 'inherit',
                  color: 'inherit',
                }}
              >
                <div className="spread" style={{ gap: 12 }}>
                  <div style={{ minWidth: 0 }}>
                    <div className="row" style={{ gap: 9 }}>
                      <strong style={{ fontSize: '0.94rem' }}>{s.name}</strong>
                      {s.primary && <span className="badge badge-info">Primary</span>}
                    </div>
                    <div className="card-note mt-8">{s.description}</div>
                    {s.expected_stages?.length > 0 && (
                      <div className="row mt-8" style={{ gap: 6 }}>
                        {s.expected_stages.map((st) => (
                          <span key={st} className="badge badge-neutral">
                            {st}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <span className={`dot ${selected === s.id ? 'dot-ok' : ''}`} style={{ background: selected === s.id ? undefined : '#38506f' }} />
                </div>
              </button>
            ))}
          </div>

          <div className="row mt-16">
            <button className="btn btn-danger btn-lg" onClick={run} disabled={busy || !online}>
              {busy ? 'Running…' : '▶ Investigate'}
            </button>
            <span className="card-note">Scenario: <span className="mono">{selected}</span></span>
          </div>

          {error && (
            <div className="mt-16">
              <Alert kind="error" title="Simulation failed">
                {error}
              </Alert>
            </div>
          )}
        </Card>

        <Card title="Processing" icon="⚙" note="Live state from the backend response">
          {!online ? (
            <Alert kind="error" title="TRACE backend unavailable">
              Start the backend and retry the simulation.
            </Alert>
          ) : (
            <PipelineSteps steps={steps} />
          )}

          {result && (
            <>
              <div className="mt-16">
                <Alert kind="ok" title={`${result.incident.incident_id} — ${result.incident.title}`}>
                  {result.event_count} events generated and analysed. Risk {result.incident.risk_score}/100.
                </Alert>
              </div>
              <div className="row mt-12" style={{ gap: 9 }}>
                <SeverityBadge severity={result.incident.severity} />
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => navigate(`/incidents/${result.incident.incident_id}`)}
                >
                  Open Investigation →
                </button>
              </div>
              <div className="mt-12">
                <div className="meta-label">Risk score</div>
                <div className="row" style={{ gap: 10 }}>
                  <span className="stat-value" style={{ color: scoreColour(result.incident.risk_score) }}>
                    {result.incident.risk_score}
                  </span>
                  <span className="card-note">/ 100 · {result.incident.severity}</span>
                </div>
                <Bar value={result.incident.risk_score} />
              </div>
              <div className="mt-12">
                <div className="meta-label">Reconstructed chain</div>
                <div className="row mt-8" style={{ gap: 6 }}>
                  {(result.incident.attack_chain || []).map((c) => (
                    <span key={c.stage} className="badge badge-neutral">
                      {c.stage}. {c.stage_label}
                    </span>
                  ))}
                </div>
              </div>
            </>
          )}

          {!result && !busy && (
            <p className="card-note mt-16">
              Select a scenario and press <strong>Investigate</strong>. Each step above turns green
              only after the backend confirms it.
            </p>
          )}
        </Card>
      </div>

      {active && (
        <Card title={`What the "${active.name}" log contains`} icon="🧪" className="mt-16">
          <p className="card-note">
            The generator writes a realistic mixed log: benign health checks, normal API traffic and
            service logins, interleaved with the malicious sequence below. Benign entries are parsed
            but must <strong>not</strong> be flagged by the detection engine.
          </p>
          <div className="row mt-12" style={{ gap: 7, flexWrap: 'wrap' }}>
            {active.expected_stages.map((st, i) => (
              <React.Fragment key={st}>
                <span className="pill">{st}</span>
                {i < active.expected_stages.length - 1 && <span style={{ color: '#38506f' }}>→</span>}
              </React.Fragment>
            ))}
          </div>
          <p className="card-note mt-12">
            Every generated event is time-stamped within a single ~10 minute window so correlation by
            source IP, account and proximity has real data to work with.
          </p>
        </Card>
      )}
    </>
  )
}
