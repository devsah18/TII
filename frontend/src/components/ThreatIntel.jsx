import React from 'react'
import { Card, Empty, Alert } from './ui.jsx'

/**
 * Threat-intelligence panel. Every IOC (source IP, compromised account) is
 * enriched by the backend with scope, geo, reputation and a risk badge.
 * Pure presentation — all decisions are made deterministically server-side.
 */
const RISK_BADGE = {
  critical: 'badge badge-critical',
  high: 'badge badge-high',
  medium: 'badge badge-medium',
  low: 'badge badge-low',
  info: 'badge badge-info',
}

export default function ThreatIntel({ incident }) {
  const intel = incident.threat_intel || []
  const summary = incident.threat_intel_summary

  if (!intel.length) {
    return <Empty>No indicators were extracted, so there is nothing to enrich.</Empty>
  }

  const verdictKind = summary?.known_malicious > 0 ? 'error' : 'info'

  return (
    <div className="stack" style={{ gap: 14 }}>
      {summary && (
        <Alert kind={verdictKind} title={`Threat-intel verdict — max risk ${String(summary.max_risk).toUpperCase()}`}>
          {summary.verdict}. {summary.total_iocs} indicator(s) enriched ·{' '}
          {summary.known_malicious} known-malicious · {summary.external} external.
        </Alert>
      )}

      <div className="grid grid-2">
        {intel.map((i, idx) => (
          <Card
            key={`${i.value}-${idx}`}
            title={i.value}
            icon={i.type === 'ipv4' ? '🌐' : '👤'}
            note={`${i.type} · ${i.scope}`}
            action={<span className={RISK_BADGE[i.risk] || RISK_BADGE.info}>{String(i.risk).toUpperCase()}</span>}
          >
            <div className="kv-list">
              <Row k="Reputation" v={i.reputation} />
              {i.geo ? <Row k="Geography" v={i.geo} /> : null}
              <Row k="Known malicious" v={i.known_malicious ? 'YES' : 'no'} />
              <Row k="Role" v={i.role || '—'} />
            </div>
            {i.note ? <p className="card-note mt-8">{i.note}</p> : null}
          </Card>
        ))}
      </div>

      <p className="card-note">
        Enrichment is offline and deterministic — it classifies scope, geography and reputation from
        local threat-intel data. No external service is queried.
      </p>
    </div>
  )
}

function Row({ k, v }) {
  return (
    <div className="kv-row">
      <span className="k">{k}</span>
      <span className="mono" style={{ fontSize: '0.8rem' }}>{v ?? '—'}</span>
    </div>
  )
}