import React, { useState } from 'react'
import { SeverityBadge, Empty } from './ui.jsx'
import { fmtTime, detectionLabel } from '../utils/format.js'

/**
 * Clickable incident timeline. Selecting an entry reveals the full event record
 * (timestamp, type, source IP, user, evidence, raw log line).
 */
export default function Timeline({ timeline = [], title = 'Incident Timeline' }) {
  const [selectedId, setSelectedId] = useState(timeline[0]?.event_id || null)
  const selected = timeline.find((t) => t.event_id === selectedId) || null

  if (!timeline.length) {
    return <Empty>No events are attached to this incident.</Empty>
  }

  return (
    <div className="grid grid-8-4">
      <div className="timeline">
        {timeline.map((t) => (
          <div
            key={t.event_id}
            className={`tl-item sev-${t.severity} ${selectedId === t.event_id ? 'selected' : ''}`}
            onClick={() => setSelectedId(t.event_id)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') setSelectedId(t.event_id)
            }}
          >
            <div className="tl-rail">
              <span className="tl-node" aria-hidden="true">
                {t.icon}
              </span>
            </div>
            <div className="tl-time">{t.time_display}</div>
            <div className="tl-main">
              <div className="tl-label">
                {t.label}
                {t.suspicious && <SeverityBadge severity={t.severity} />}
              </div>
              <div className="tl-desc">{t.description}</div>
            </div>
          </div>
        ))}
      </div>

      <aside className="detail-panel">
        {!selected ? (
          <Empty>Select a timeline entry to inspect it.</Empty>
        ) : (
          <>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <h3 style={{ fontSize: '0.96rem' }}>
                {selected.icon} {selected.label}
              </h3>
              <SeverityBadge severity={selected.severity} />
            </div>

            <div className="detail-list">
              <Detail k="Event ID" v={<span className="mono">{selected.event_id}</span>} />
              <Detail k="Timestamp" v={<span className="mono">{fmtTime(selected.timestamp)}</span>} />
              <Detail k="Event type" v={<span className="mono">{selected.event_type}</span>} />
              <Detail k="Source IP" v={selected.source_ip ? <span className="mono">{selected.source_ip}</span> : '—'} />
              {selected.destination_ip && (
                <Detail k="Destination" v={<span className="mono">{selected.destination_ip}</span>} />
              )}
              <Detail k="Username" v={selected.username || '—'} />
              <Detail k="Host / source" v={selected.host || '—'} />
              <Detail k="Status" v={selected.status || '—'} />
              {selected.detection_types?.length > 0 && (
                <Detail
                  k="Detections"
                  v={
                    <span className="row" style={{ gap: 5 }}>
                      {selected.detection_types.map((d) => (
                        <span key={d} className="badge badge-info">
                          {detectionLabel(d)}
                        </span>
                      ))}
                    </span>
                  }
                />
              )}
            </div>

            {selected.evidence?.length > 0 && (
              <>
                <div className="meta-label mt-16">Evidence</div>
                <ul className="evidence-list">
                  {[...new Set(selected.evidence)].slice(0, 5).map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              </>
            )}

            <div className="meta-label mt-16">Raw log entry</div>
            <pre className="raw-log">{selected.raw_message}</pre>
          </>
        )}
      </aside>
    </div>
  )
}

function Detail({ k, v }) {
  return (
    <div className="detail-row">
      <span className="k">{k}</span>
      <span className="v">{v}</span>
    </div>
  )
}
