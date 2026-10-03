import React from 'react'
import { fmtDateTime, fmtTime, fmtPct } from '../utils/format.js'

/**
 * Printable incident report. Rendered off-screen and revealed by the print
 * media query, so browser Print → Save as PDF produces a clean document.
 */
export default function ReportView({ incident }) {
  if (!incident) return null

  return (
    <div className="print-report">
      <h1>TRACE Incident Report</h1>
      <p className="meta-line">
        <strong>Incident ID:</strong> {incident.incident_id} &nbsp;|&nbsp;{' '}
        <strong>Generated:</strong> {new Date().toUTCString()} &nbsp;|&nbsp;{' '}
        <strong>Severity:</strong> {String(incident.severity).toUpperCase()} &nbsp;|&nbsp;{' '}
        <strong>Risk score:</strong> {incident.risk_score}/100 ({fmtPct(incident.confidence)} confidence)
      </p>

      <h2>1. Incident Summary</h2>
      <div className="pr-box pr-critical">
        <strong>{incident.title}</strong>
        <div className="meta-line" style={{ marginTop: 4 }}>
          First seen {fmtDateTime(incident.first_seen)} · Last seen {fmtDateTime(incident.last_seen)}
          {incident.source_ip ? ` · Source ${incident.source_ip}` : ''}
          {incident.affected_user ? ` · Affected user ${incident.affected_user}` : ''}
        </div>
        <p>{incident.summary}</p>
        {incident.impact && <p className="meta-line">{incident.impact}</p>}
      </div>

      <h2>2. Attack Timeline</h2>
      <table>
        <thead>
          <tr>
            <th style={{ width: '15%' }}>Time (UTC)</th>
            <th style={{ width: '22%' }}>Event</th>
            <th style={{ width: '18%' }}>Source IP</th>
            <th style={{ width: '15%' }}>User</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {(incident.timeline || []).map((t) => (
            <tr key={t.event_id}>
              <td className="pr-mono">{t.time_display}</td>
              <td>
                {t.label}
                {t.suspicious ? ' *' : ''}
              </td>
              <td className="pr-mono">{t.source_ip || '—'}</td>
              <td>{t.username || '—'}</td>
              <td>{t.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="meta-line">* flagged by the detection engine</p>

      <h2>3. Attack Chain</h2>
      <table>
        <thead>
          <tr>
            <th style={{ width: '8%' }}>Stage</th>
            <th style={{ width: '20%' }}>Phase</th>
            <th style={{ width: '34%' }}>Finding</th>
            <th style={{ width: '14%' }}>Time (UTC)</th>
            <th>Confidence</th>
          </tr>
        </thead>
        <tbody>
          {(incident.attack_chain || []).map((c) => (
            <tr key={c.stage}>
              <td>{c.stage}</td>
              <td>{c.stage_label}</td>
              <td>
                <strong>{c.title}</strong>
                <div>{c.description}</div>
              </td>
              <td className="pr-mono">{c.timestamp ? fmtTime(c.timestamp) : '—'}</td>
              <td>{fmtPct(c.confidence)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>4. Indicators of Compromise</h2>
      <table>
        <thead>
          <tr>
            <th style={{ width: '18%' }}>Type</th>
            <th style={{ width: '30%' }}>Value</th>
            <th style={{ width: '16%' }}>Role</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {(incident.indicators || []).map((i, idx) => (
            <tr key={idx}>
              <td>{i.type}</td>
              <td className="pr-mono">{i.value}</td>
              <td>{i.role}</td>
              <td>{i.evidence}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>5. MITRE ATT&amp;CK Techniques</h2>
      <table>
        <thead>
          <tr>
            <th style={{ width: '12%' }}>ID</th>
            <th style={{ width: '26%' }}>Technique</th>
            <th style={{ width: '18%' }}>Tactic</th>
            <th style={{ width: '10%' }}>Confidence</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {(incident.mitre_techniques || []).map((t) => (
            <tr key={t.id}>
              <td className="pr-mono">{t.id}</td>
              <td>{t.name}</td>
              <td>{t.tactic}</td>
              <td>{fmtPct(t.confidence)}</td>
              <td>{(t.evidence || []).join('; ')}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>6. Risk Assessment</h2>
      <div className="pr-box">
        <strong>Risk score {incident.risk_score}/100 — {String(incident.severity).toUpperCase()}</strong>
        <div className="meta-line">{incident.risk_explanation}</div>
        <table>
          <thead>
            <tr>
              <th style={{ width: '45%' }}>Factor</th>
              <th style={{ width: '12%' }}>Points</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {(incident.risk_factors || []).map((f, i) => (
              <tr key={i}>
                <td>{f.name}</td>
                <td>+{f.points}</td>
                <td>{f.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>7. Detections and Evidence</h2>
      {(incident.detections || []).map((d) => (
        <div className="pr-box" key={d.id}>
          <strong>
            {d.id} · {d.title} · {String(d.severity).toUpperCase()} · {fmtPct(d.confidence)}
          </strong>
          <div>{d.description}</div>
          <ul>
            {(d.evidence || []).map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      ))}

      <h2>8. Recommended Actions</h2>
      {(incident.response_actions || []).map((a) => (
        <div className="pr-box" key={a.id}>
          <strong>
            [{a.priority}] {a.action}
          </strong>
          <div>{a.reason}</div>
          <div className="meta-line">
            Timeframe: {a.timeframe}
            {a.evidence?.length ? ` · Evidence: ${a.evidence.join('; ')}` : ''}
          </div>
        </div>
      ))}
      <p className="meta-line">
        These are recommendations only. TRACE never executes security actions.
      </p>

      <h2>9. Technical Appendix</h2>
      <p className="meta-line">
        <strong>Source file:</strong> {incident.source_file?.filename || 'n/a'} (
        {incident.source_file?.file_id || 'n/a'}) · <strong>Events in incident:</strong>{' '}
        {incident.event_count} · <strong>Detections:</strong> {incident.detection_count} ·{' '}
        <strong>Affected hosts:</strong> {(incident.affected_hosts || []).join(', ') || 'n/a'}
      </p>
    </div>
  )
}
