import React, { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Card, Alert, Spinner, Empty, SeverityBadge, TabBar, MetaItem, Bar,
} from '../components/ui.jsx'
import { TopBar } from '../Layout.jsx'
import Timeline from '../components/Timeline.jsx'
import AttackGraph from '../components/AttackGraph.jsx'
import AIInvestigator from '../components/AIInvestigator.jsx'
import ReportView from '../components/ReportView.jsx'
import RiskGauge from '../components/RiskGauge.jsx'
import AttackPlayback from '../components/AttackPlayback.jsx'
import ThreatIntel from '../components/ThreatIntel.jsx'
import ThresholdPanel from '../components/ThresholdPanel.jsx'
import { getIncident, ApiError } from '../services/api.js'
import {
  fmtTime, fmtDateTime, fmtPct, scoreColour, detectionLabel, eventTypeLabel,
} from '../utils/format.js'

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'playback', label: 'Playback' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'graph', label: 'Attack Graph' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'mitre', label: 'MITRE ATT&CK' },
  { id: 'intel', label: 'Threat Intel' },
  { id: 'risk', label: 'Risk Analysis' },
  { id: 'tuning', label: 'Tuning' },
  { id: 'response', label: 'Response' },
  { id: 'chat', label: 'Ask TRACE' },
]

/** Loads an incident by id from GET /api/incidents/{id}. */
export default function InvestigationLoader({ online }) {
  const { incidentId } = useParams()
  const [incident, setIncident] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError('')
    getIncident(incidentId)
      .then((res) => {
        if (!cancelled) setIncident(res)
      })
      .catch((err) => {
        if (cancelled) return
        if (err instanceof ApiError && err.status === 404) {
          setError(
            `Incident ${incidentId} was not found. Incidents live in backend memory only, so a backend restart clears them — run a demo attack or upload a log again.`,
          )
        } else {
          setError(err instanceof ApiError ? err.message : 'Could not load the incident.')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [incidentId])

  if (loading) {
    return (
      <>
        <TopBar title={`Investigation ${incidentId}`} subtitle="Reconstructing the incident…" online={online} />
        <Spinner label="Loading investigation from the backend…" />
      </>
    )
  }

  if (error) {
    return (
      <>
        <TopBar title="Investigation unavailable" online={online} />
        <Alert kind="error" title="This incident could not be loaded">
          {error}
        </Alert>
      </>
    )
  }

  return <InvestigationView incident={incident} online={online} />
}

/* -------------------------------------------------------------------------- */

export function InvestigationView({ incident, online }) {
  const navigate = useNavigate()
  const [tab, setTab] = useState('overview')
  const [live, setLive] = useState(incident)

  // Keep the view in sync when the loader swaps incidents, and allow the
  // Tuning panel to replace the incident with a freshly re-analysed one.
  React.useEffect(() => {
    setLive(incident)
  }, [incident])

  const incident_ = live

  const tabs = TABS.map((t) => ({
    ...t,
    count:
      t.id === 'timeline'
        ? incident_.timeline?.length
        : t.id === 'graph'
          ? incident_.attack_graph?.nodes?.length
          : t.id === 'evidence'
            ? incident_.detections?.length
            : t.id === 'mitre'
              ? incident_.mitre_techniques?.length
              : t.id === 'risk'
                ? incident_.risk_factors?.length
                : t.id === 'intel'
                  ? incident_.threat_intel?.length
                  : t.id === 'response'
                    ? incident_.response_actions?.length
                    : t.id === 'playback'
                      ? incident_.timeline?.length
                      : undefined,
  }))

  const score = incident_.risk_score ?? 0

  return (
    <>
      <TopBar
        title={`Investigation ${incident_.incident_id}`}
        subtitle={incident_.title}
        online={online}
      >
        <button className="btn" onClick={() => window.print()}>
          ⤓ Export Incident Report
        </button>
        <button className="btn" onClick={() => navigate('/incidents')}>
          ← All incidents
        </button>
      </TopBar>

      {/* ---------------------------------------------------------- hero */}
      <div className={`hero hero-${incident_.severity}`} style={{ marginBottom: 17 }}>
        <div className="hero-top">
          <div style={{ minWidth: 0, flex: '1 1 420px' }}>
            <div className="row" style={{ gap: 9 }}>
              <SeverityBadge severity={incident_.severity} />
              {incident_.no_findings && <span className="badge badge-neutral">No findings</span>}
              <span className="pill">
                <span className="dot dot-bad pulse" /> {incident_.status || 'open'}
              </span>
            </div>
            <h2 className="hero-title">{incident_.headline || incident_.title}</h2>
            <p className="hero-summary">{incident_.summary}</p>

            <div className="row" style={{ gap: 8, flexWrap: 'wrap', marginTop: 13 }}>
              {(incident_.attack_chain || []).map((c) => (
                <span key={c.stage} className="badge badge-neutral" title={c.description}>
                  {c.icon} {c.stage_label}
                </span>
              ))}
            </div>
          </div>

          <div className="row" style={{ gap: 22, alignItems: 'center', flexWrap: 'wrap' }}>
            <RiskGauge score={score} severity={incident_.severity} />
            <div style={{ minWidth: 132 }}>
              <div className="meta-label">Confidence</div>
              <div className="stat-value" style={{ fontSize: '1.5rem' }}>
                {fmtPct(incident_.confidence)}
              </div>
              <Bar value={(incident_.confidence || 0) * 100} colour="#38bdf8" />
              <div className="card-note" style={{ marginTop: 8 }}>
                {incident_.detection_count} detection(s) across {incident_.event_count} event(s)
              </div>
            </div>
          </div>
        </div>

        <div className="meta-grid" style={{ marginTop: 18 }}>
          <MetaItem label="Source IP" value={incident_.source_ip || '—'} mono />
          <MetaItem label="Affected User" value={incident_.affected_user || '—'} mono />
          <MetaItem label="First Seen" value={fmtTime(incident_.first_seen)} mono />
          <MetaItem label="Last Seen" value={fmtTime(incident_.last_seen)} mono />
          <MetaItem label="Affected Hosts" value={(incident_.affected_hosts || []).join(', ') || '—'} />
          <MetaItem label="Source File" value={incident_.source_file?.filename || '—'} mono />
        </div>
      </div>

      {incident_.correlation?.clusters_found > 1 && (
        <div style={{ marginBottom: 17 }}>
          <Alert kind="info" title="Correlation expanded beyond this incident">
            {incident_.correlation.note} {incident_.related_incidents?.length} additional cluster(s) were
            found with different entities — they are separate incidents and are not merged here.
          </Alert>
        </div>
      )}

      <TabBar tabs={tabs} active={tab} onChange={setTab} />

      {tab === 'overview' && <Overview incident={incident_} />}
      {tab === 'playback' && <AttackPlayback incident={incident_} />}
      {tab === 'timeline' && (
        <Card title="Incident Timeline" icon="🕒" note="Click any entry to inspect the raw event and its evidence">
          <Timeline timeline={incident_.timeline || []} />
        </Card>
      )}
      {tab === 'graph' && (
        <Card
          title="Attack Relationship Graph"
          icon="🕸"
          note="Nodes and edges are supplied by the backend correlation result"
        >
          <AttackGraph graph={incident_.attack_graph} />
        </Card>
      )}
      {tab === 'evidence' && <Evidence incident={incident_} />}
      {tab === 'mitre' && <Mitre incident={incident_} />}
      {tab === 'intel' && <ThreatIntel incident={incident_} />}
      {tab === 'risk' && (
        <>
          <RiskAnalysis incident={incident_} />
          <div style={{ marginTop: 16 }}>
            <ThresholdPanel incident={incident_} onReanalyzed={setLive} />
          </div>
        </>
      )}
      {tab === 'tuning' && <ThresholdPanel incident={incident_} onReanalyzed={setLive} />}
      {tab === 'response' && <Response incident={incident_} />}
      {tab === 'chat' && (
        <Card title="Ask TRACE" icon="💬" note="Answers are grounded in this incident's data">
          <AIInvestigator incidentId={incident_.incident_id} summary={incident_.summary} />
        </Card>
      )}

      <ReportView incident={incident_} />
    </>
  )
}

/* --------------------------------------------------------------- overview */
function Overview({ incident }) {
  return (
    <>
      <div className="grid grid-7-5" style={{ marginBottom: 15 }}>
        <Card title="Attack Reconstruction" icon="🧩" note="Stages are ordered by first observation time">
          {!incident.attack_chain?.length ? (
            <Empty>No attack stages were reconstructed for this incident.</Empty>
          ) : (
            <div className="stack" style={{ gap: 9 }}>
              {incident.attack_chain.map((c) => (
                <div
                  key={c.stage}
                  className="evidence-item"
                  style={{ '--sev': scoreColour(c.confidence * 100) }}
                >
                  <div className="evidence-head">
                    <div className="row" style={{ gap: 10 }}>
                      <span className="tl-node" style={{ width: 30, height: 30 }}>
                        {c.icon}
                      </span>
                      <div>
                        <div style={{ fontWeight: 650, fontSize: '0.9rem' }}>
                          Stage {c.stage} · {c.title}
                        </div>
                        <div className="card-note" style={{ fontSize: '0.75rem' }}>
                          {c.stage_label} · {fmtTime(c.timestamp)} · confidence {fmtPct(c.confidence)}
                        </div>
                      </div>
                    </div>
                    <SeverityBadge severity={c.severity} />
                  </div>
                  <p className="card-note" style={{ marginTop: 8 }}>
                    {c.description}
                  </p>
                  {c.evidence?.length > 0 && (
                    <ul className="evidence-list">
                      {c.evidence.map((e, i) => (
                        <li key={i}>{e}</li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          )}
        </Card>

        <div className="stack">
          <Card title="Detections" icon="🚨" note="Deterministic rules, each with its own confidence">
            {!incident.detections?.length ? (
              <Empty>No detection rule matched this log.</Empty>
            ) : (
              <div className="stack" style={{ gap: 9 }}>
                {incident.detections.map((d) => (
                  <div key={d.id} className="row" style={{ justifyContent: 'space-between', gap: 10 }}>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: '0.87rem', fontWeight: 600 }}>
                        {detectionLabel(d.type)}
                      </div>
                      <div className="card-note" style={{ fontSize: '0.74rem' }}>
                        {d.id} · {fmtPct(d.confidence)} · {d.event_ids?.length} event(s)
                      </div>
                    </div>
                    <SeverityBadge severity={d.severity} />
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="Indicators of Compromise" icon="🎯" note="Extracted from parsed events">
            {!incident.indicators?.length ? (
              <Empty>No indicators extracted.</Empty>
            ) : (
              <div className="stack" style={{ gap: 8 }}>
                {incident.indicators.slice(0, 8).map((i, idx) => (
                  <div key={idx} className="spread" style={{ gap: 10 }}>
                    <div style={{ minWidth: 0 }}>
                      <div className="mono" style={{ fontSize: '0.81rem', wordBreak: 'break-all' }}>
                        {i.value}
                      </div>
                      <div className="card-note" style={{ fontSize: '0.73rem' }}>
                        {i.role} · {i.evidence}
                      </div>
                    </div>
                    <span className="badge badge-info">{i.type}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      {incident.impact && (
        <Card title="Impact" icon="⚖" className="mt-16">
          <p className="card-note">{incident.impact}</p>
        </Card>
      )}
    </>
  )
}

/* ---------------------------------------------------------------- evidence */
function Evidence({ incident }) {
  if (!incident.detections?.length) {
    return <Empty>No evidence: no detection rule matched the parsed events.</Empty>
  }
  return (
    <div className="stack">
      {incident.detections.map((d) => (
        <Card
          key={d.id}
          title={`${d.id} · ${d.title}`}
          icon="🔬"
          note={`type: ${d.type} · ${d.event_ids?.length || 0} event(s)`}
          action={
            <div className="row" style={{ gap: 8 }}>
              <span className="pill">confidence {fmtPct(d.confidence)}</span>
              <SeverityBadge severity={d.severity} />
            </div>
          }
        >
          <p style={{ fontSize: '0.88rem', color: '#c9d6ea' }}>{d.description}</p>
          <div className="meta-label mt-12">Evidence</div>
          <ul className="evidence-list">
            {(d.evidence || []).map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
          <div className="meta-label mt-16">Contributing events</div>
          <div className="row" style={{ gap: 7, flexWrap: 'wrap' }}>
            {(d.event_ids || []).slice(0, 24).map((id) => (
              <span key={id} className="badge badge-neutral mono">
                {id}
              </span>
            ))}
            {d.event_ids?.length > 24 && (
              <span className="card-note">+{d.event_ids.length - 24} more</span>
            )}
          </div>
        </Card>
      ))}

      <Card title="Parsed Event Log" icon="📄" note={`${incident.events?.length || 0} event(s) attached to this incident`}>
        <div style={{ overflowX: 'auto' }}>
          <table className="data">
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Source</th>
                <th>Destination</th>
                <th>User</th>
                <th>Status</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {(incident.events || []).map((e) => (
                <tr key={e.id} style={{ background: e.suspicious ? 'rgba(239,68,68,0.05)' : undefined }}>
                  <td className="mono">{fmtTime(e.timestamp).replace(' UTC', '')}</td>
                  <td>
                    {e.suspicious && <span className="dot dot-bad" style={{ marginRight: 6 }} />}
                    {eventTypeLabel(e.event_type)}
                  </td>
                  <td className="mono">{e.source_ip || '—'}</td>
                  <td className="mono">{e.destination_ip || e.source || '—'}</td>
                  <td className="mono">{e.username || '—'}</td>
                  <td>{e.status}</td>
                  <td style={{ fontSize: '0.78rem', color: '#9fb3cf', maxWidth: 380, wordBreak: 'break-word' }}>
                    {e.raw_message}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="card-note mt-12">
          Rows with a red marker were matched by at least one detection rule; unmarked rows are
          routine activity that the engine intentionally left unflagged.
        </p>
      </Card>
    </div>
  )
}

/* ------------------------------------------------------------------- mitre */
function Mitre({ incident }) {
  const techs = incident.mitre_techniques || []
  if (!techs.length) {
    return (
      <Empty>
        No MITRE ATT&amp;CK techniques were mapped, because no detection evidence supported any.
      </Empty>
    )
  }
  return (
    <>
      <Alert kind="info" title="Evidence-gated mapping">
        Techniques are only listed when the detected behaviour actually supports them. Each entry cites
        the specific evidence behind the mapping.
      </Alert>
      <div className="grid grid-2 mt-16">
        {techs.map((t) => (
          <div className="tech-card" key={t.id}>
            <div className="spread">
              <a href={t.url} target="_blank" rel="noreferrer" className="tech-id">
                {t.id}
              </a>
              <span className="pill">confidence {fmtPct(t.confidence)}</span>
            </div>
            <div style={{ fontWeight: 650 }}>{t.name}</div>
            <div className="card-note">{t.tactic}</div>
            <ul className="evidence-list">
              {(t.evidence || []).map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </>
  )
}

/* -------------------------------------------------------------- risk panel */
function RiskAnalysis({ incident }) {
  const factors = incident.risk_factors || []
  return (
    <div className="grid grid-7-5">
      <Card title="Risk Breakdown" icon="📊" note="The score is the sum of the factors below">
        {!factors.length ? (
          <Empty>No risk factors were triggered, so the score is 0.</Empty>
        ) : (
          <div>
            {factors.map((f, i) => (
              <div className="factor-row" key={i}>
                <div>
                  <div className="factor-name">{f.name}</div>
                  <div className="factor-ev">{f.evidence}</div>
                  {f.detection_ids?.length > 0 && (
                    <div className="action-ev">detections: {f.detection_ids.join(', ')}</div>
                  )}
                </div>
                <div className="factor-pts">+{f.points}</div>
              </div>
            ))}
            <div className="factor-row" style={{ borderTop: '1px solid var(--border-strong)', marginTop: 4 }}>
              <div className="factor-name">Total risk score</div>
              <div className="factor-pts" style={{ color: scoreColour(incident.risk_score) }}>
                {incident.risk_score} / 100
              </div>
            </div>
          </div>
        )}
        <p className="card-note mt-16">{incident.risk_explanation}</p>
      </Card>

      <div className="stack">
        <Card title="Score" icon="🎚">
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <RiskGauge score={incident.risk_score || 0} severity={incident.severity} size={200} />
          </div>
          <div className="meta-grid mt-16">
            <MetaItem label="Severity" value={<SeverityBadge severity={incident.severity} />} />
            <MetaItem label="Confidence" value={fmtPct(incident.confidence)} />
            <MetaItem label="Factors triggered" value={factors.length} />
          </div>
        </Card>

        <Card title="Scoring Model" icon="🧮" note="Fixed weights, clamped to 0–100">
          <div className="kv-list">
            {[
              ['Repeated authentication failures', '+25'],
              ['Successful login after failures', '+20'],
              ['Privilege escalation', '+20'],
              ['Sensitive data access', '+20'],
              ['Suspicious external IP', '+15'],
              ['Pre-attack reconnaissance', '+8'],
              ['Bulk outbound data transfer', '+15'],
            ].map(([k, v]) => (
              <div className="kv-row" key={k}>
                <span className="k">{k}</span>
                <span className="mono">{v}</span>
              </div>
            ))}
          </div>
          <p className="card-note mt-12">
            Severity bands: 85+ critical · 70+ high · 45+ medium · 20+ low.
          </p>
        </Card>
      </div>
    </div>
  )
}

/* ---------------------------------------------------------------- response */
function Response({ incident }) {
  const actions = incident.response_actions || []
  if (!actions.length) return <Empty>No response actions were generated for this incident.</Empty>

  const groups = ['IMMEDIATE', 'INVESTIGATE', 'MONITOR']
  const meta = {
    IMMEDIATE: { icon: '🔴', colour: '#ef4444', label: 'Immediate — contain now' },
    INVESTIGATE: { icon: '🟠', colour: '#f97316', label: 'Investigate — establish scope' },
    MONITOR: { icon: '🟢', colour: '#22c55e', label: 'Monitor — watch for recurrence' },
  }

  return (
    <>
      <Alert kind="warn" title="Advisory only">
        These are recommendations. TRACE never executes a security action — apply them through your own
        tooling after human review.
      </Alert>

      {groups.map((g) => {
        const items = actions.filter((a) => a.priority === g)
        if (!items.length) return null
        return (
          <div key={g} style={{ marginTop: 17 }}>
            <div className="group-label">
              <span style={{ color: meta[g].colour }}>{meta[g].icon}</span>
              {g} · {meta[g].label}
              <span className="count">{items.length}</span>
            </div>
            <div className="action-group">
              {items.map((a) => (
                <div className="action-item" key={a.id} style={{ '--sev': meta[g].colour }}>
                  <div className="spread">
                    <div className="action-title">
                      {a.icon} {a.action}
                    </div>
                    <span className="card-note mono">{a.id}</span>
                  </div>
                  <div className="action-reason">{a.reason}</div>
                  {a.evidence?.length > 0 && (
                    <div className="action-ev">evidence: {a.evidence.join(' · ')}</div>
                  )}
                  <div className="card-note mt-8" style={{ fontSize: '0.73rem' }}>
                    Timeframe: {a.timeframe}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </>
  )
}
