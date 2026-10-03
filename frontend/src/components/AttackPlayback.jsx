import React, { useEffect, useRef, useState } from 'react'
import { Card, Empty, SeverityBadge } from './ui.jsx'
import { fmtTime, scoreColour } from '../utils/format.js'

/**
 * Attack playback. Steps through the incident timeline automatically, revealing
 * the attack as it unfolded. Everything comes from the deterministic backend
 * data (incident.timeline) — this component only decides *when* to reveal it.
 */
export default function AttackPlayback({ incident }) {
  const timeline = incident.timeline || []
  const [step, setStep] = useState(timeline.length ? 0 : -1)
  const [playing, setPlaying] = useState(false)
  const speedRef = useRef(1200)
  const timer = useRef(null)

  useEffect(() => {
    setStep(timeline.length ? 0 : -1)
    setPlaying(false)
  }, [incident.incident_id, timeline.length])

  useEffect(() => {
    if (!playing) return undefined
    timer.current = setInterval(() => {
      setStep((s) => {
        if (s >= timeline.length - 1) {
          setPlaying(false)
          return s
        }
        return s + 1
      })
    }, speedRef.current)
    return () => clearInterval(timer.current)
  }, [playing, timeline.length])

  if (!timeline.length) {
    return <Empty>No timeline events to play for this incident.</Empty>
  }

  const visible = timeline.slice(0, step + 1)
  const current = timeline[step]
  const progress = Math.round(((step + 1) / timeline.length) * 100)

  function play() {
    if (step >= timeline.length - 1) setStep(0)
    setPlaying(true)
  }

  return (
    <Card title="Attack Playback" icon="▶" note="Watch the incident unfold step by step">
      <div className="playback-controls">
        <button className="btn btn-primary" onClick={() => (playing ? setPlaying(false) : play())}>
          {playing ? '⏸ Pause' : '▶ Play'}
        </button>
        <button className="btn" onClick={() => { setPlaying(false); setStep(0) }} disabled={step === 0}>
          ⏮ Restart
        </button>
        <button
          className="btn"
          onClick={() => { setPlaying(false); setStep((s) => Math.max(0, s - 1)) }}
          disabled={step <= 0}
        >
          ⏪ Prev
        </button>
        <button
          className="btn"
          onClick={() => { setPlaying(false); setStep((s) => Math.min(timeline.length - 1, s + 1)) }}
          disabled={step >= timeline.length - 1}
        >
          ⏩ Next
        </button>
        <span className="card-note">
          Step {step + 1} / {timeline.length} · {fmtTime(current?.timestamp)}
        </span>
      </div>

      <div className="bar" style={{ marginTop: 10 }}>
        <div className="bar-fill" style={{ width: `${progress}%`, background: scoreColour(progress) }} />
      </div>

      {current && (
        <div
          className="playback-current"
          style={{ borderColor: scoreColour(current.severity === 'critical' ? 90 : current.suspicious ? 60 : 10) }}
        >
          <div className="spread">
            <strong style={{ fontSize: '0.94rem' }}>
              {current.icon} {current.label}
            </strong>
            <SeverityBadge severity={current.severity} />
          </div>
          <div className="card-note mt-8">{current.description}</div>
          <div className="card-note" style={{ fontSize: '0.73rem' }}>
            <span className="mono">{current.event_id}</span> · {current.event_type} ·{' '}
            src <span className="mono">{current.source_ip || '—'}</span> · user{' '}
            <span className="mono">{current.username || '—'}</span>
          </div>
          {current.raw_message ? <pre className="raw-log mt-8">{current.raw_message}</pre> : null}
        </div>
      )}

      <div className="meta-label mt-16">Revealed so far ({visible.length})</div>
      <div className="stack" style={{ gap: 5, marginTop: 6 }}>
        {visible.map((t, i) => (
          <div
            key={t.event_id}
            className={`playback-row ${i === step ? 'active' : ''}`}
            style={{ opacity: t.suspicious ? 1 : 0.55 }}
          >
            <span className="mono" style={{ fontSize: '0.74rem', minWidth: 62 }}>{t.time_display}</span>
            <span className={`dot ${t.suspicious ? 'dot-bad' : 'dot-ok'}`} />
            <span style={{ fontSize: '0.82rem' }}>{t.label}</span>
          </div>
        ))}
      </div>
    </Card>
  )
}