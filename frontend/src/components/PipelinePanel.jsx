import React, { useEffect, useRef, useState } from 'react'

/**
 * Pipeline panel. Renders the deterministic analysis stages as a vertical
 * stepper. Pass `live` to animate them lighting up in sequence (used while a
 * run is in progress); pass `stages` to render a completed record truthfully.
 */
export const DEFAULT_STAGES = [
  { id: 'ingest', label: 'Ingest', detail: 'read source' },
  { id: 'normalize', label: 'Normalize', detail: 'unified schema' },
  { id: 'detect', label: 'Detect', detail: 'rule engine' },
  { id: 'correlate', label: 'Correlate', detail: 'merge entities' },
  { id: 'reconstruct', label: 'Reconstruct', detail: 'build incident' },
  { id: 'mitre', label: 'MITRE map', detail: 'ATT&CK techniques' },
  { id: 'respond', label: 'Response', detail: 'plan actions' },
]

export default function PipelinePanel({ stages = DEFAULT_STAGES, activeCount = -1, title = 'Analysis Pipeline', note }) {
  return (
    <div className="pipe-panel">
      <div className="pipe-panel-head">
        <span className="card-title" style={{ fontSize: '0.9rem' }}>⚙ {title}</span>
        {note && <span className="card-note">{note}</span>}
      </div>
      <div className="pipe-track">
        {stages.map((s, i) => {
          const done = activeCount < 0 ? s.status === 'done' : i < activeCount
          const active = activeCount >= 0 && i === activeCount
          return (
            <div key={s.id} className="pipe-node">
              <div className={`pipe-bullet ${done ? 'done' : active ? 'active' : ''}`}>
                {done ? '✓' : active ? <span className="spinner" /> : i + 1}
              </div>
              {i < stages.length - 1 && <div className={`pipe-link ${done ? 'done' : ''}`} />}
              <div className="pipe-text">
                <div className="pipe-name">{s.label}</div>
                <div className="pipe-sub">{s.detail}</div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/** A self-driving animated pipeline for "automatic analysis" moments. */
export function AutoPipeline({ running, onDone, stages = DEFAULT_STAGES, title }) {
  const [active, setActive] = useState(running ? 0 : -1)
  const timer = useRef(null)
  useEffect(() => {
    if (!running) {
      setActive(-1)
      return undefined
    }
    setActive(0)
    let i = 0
    timer.current = setInterval(() => {
      i += 1
      if (i >= stages.length) {
        clearInterval(timer.current)
        setActive(stages.length)
        if (onDone) onDone()
      } else {
        setActive(i)
      }
    }, 260)
    return () => clearInterval(timer.current)
  }, [running, stages.length, onDone])

  return <PipelinePanel stages={stages} activeCount={active} title={title} note={running ? 'analysing…' : undefined} />
}