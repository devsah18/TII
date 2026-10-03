import React, { useEffect, useRef, useState } from 'react'
import { SEVERITY_LABEL, severityClass, scoreColour } from '../utils/format.js'

/** Smoothly animates a number from 0 to `value` whenever it changes. */
function useCountUp(value, duration = 700) {
  const [display, setDisplay] = useState(0)
  const fromRef = useRef(0)
  useEffect(() => {
    const target = Number(value) || 0
    const from = fromRef.current
    const start = performance.now()
    let raf
    const tick = (now) => {
      const t = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - t, 3)
      setDisplay(Math.round(from + (target - from) * eased))
      if (t < 1) raf = requestAnimationFrame(tick)
      else fromRef.current = target
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [value, duration])
  return display
}

export function SeverityBadge({ severity, label }) {
  const s = String(severity || 'info').toLowerCase()
  return <span className={severityClass(s)}>{label || SEVERITY_LABEL[s] || s.toUpperCase()}</span>
}

export function Card({ title, icon, note, action, children, className = '' }) {
  return (
    <section className={`card ${className}`}>
      {(title || action) && (
        <div className="card-head">
          <div>
            <div className="card-title">
              {icon && <span className="icon">{icon}</span>}
              {title}
            </div>
            {note && <div className="card-note">{note}</div>}
          </div>
          {action}
        </div>
      )}
      <div className="card-body">{children}</div>
    </section>
  )
}

export function StatCard({ label, value, foot, colour = '#38bdf8', loading }) {
  const animated = useCountUp(value)
  return (
    <div className="card stat" style={{ '--stat-colour': colour }}>
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={{ color: colour }}>
        {loading ? '—' : animated}
      </div>
      {foot && <div className="stat-foot">{foot}</div>}
    </div>
  )
}

export function StatusPill({ state, children }) {
  return (
    <span className="pill">
      <span className={`dot ${state === 'ok' ? 'dot-ok' : state === 'bad' ? 'dot-bad' : 'dot-warn'} ${state === 'ok' ? 'pulse' : ''}`} />
      {children}
    </span>
  )
}

export function Alert({ kind = 'info', title, children, icon }) {
  const icons = { error: '⛔', warn: '⚠', info: 'ℹ', ok: '✓' }
  return (
    <div className={`alert alert-${kind}`} role={kind === 'error' ? 'alert' : undefined}>
      <span className="alert-icon">{icon || icons[kind]}</span>
      <div className="alert-body">
        {title && <strong>{title}</strong>}
        <div>{children}</div>
      </div>
    </div>
  )
}

export function Spinner({ label }) {
  return (
    <div className="loading-block">
      <span className="spinner" />
      <span>{label || 'Loading…'}</span>
    </div>
  )
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>
}

export function MetaItem({ label, value, mono }) {
  return (
    <div className="meta-item">
      <div className="meta-label">{label}</div>
      <div className={`meta-value ${mono ? 'mono' : ''}`}>{value === null || value === undefined || value === '' ? '—' : value}</div>
    </div>
  )
}

export function Bar({ value, max = 100, colour }) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0
  return (
    <div className="bar">
      <div className="bar-fill" style={{ width: `${pct}%`, background: colour || scoreColour(value) }} />
    </div>
  )
}

/** Pipeline visualisation. Steps are driven by real API responses, never a timer. */
export function PipelineSteps({ steps }) {
  const icons = { pending: '○', active: '◌', done: '✓', failed: '✕' }
  return (
    <div className="pipeline">
      {steps.map((s) => (
        <div key={s.id} className={`pipe-step ${s.status}`}>
          <span className="pipe-icon">
            {s.status === 'active' ? <span className="spinner" /> : icons[s.status]}
          </span>
          <span className="pipe-label">{s.label}</span>
          <span className="pipe-detail">
            {s.status === 'active' ? 'in progress…' : s.detail || (s.status === 'done' ? 'done' : '')}
          </span>
        </div>
      ))}
    </div>
  )
}

export function TabBar({ tabs, active, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={active === t.id}
          className={`tab ${active === t.id ? 'active' : ''}`}
          onClick={() => onChange(t.id)}
        >
          {t.label}
          {t.count !== undefined && t.count !== null && <span className="count">{t.count}</span>}
        </button>
      ))}
    </div>
  )
}
