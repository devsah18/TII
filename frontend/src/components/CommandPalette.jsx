import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { listIncidents } from '../services/api.js'

/**
 * Command palette (Ctrl/Cmd + K). Fuzzy-jumps to pages and incidents and can
 * run quick actions. Entirely keyboard driven for a fast, "power tool" feel.
 */
const PAGES = [
  { id: 'nav:/', label: 'Dashboard', hint: 'Operations overview', icon: '◈' },
  { id: 'nav:/upload', label: 'Upload Log', hint: 'Parse & investigate a file', icon: '⬆' },
  { id: 'nav:/simulation', label: 'Simulation', hint: 'Run a demo attack', icon: '⚡' },
  { id: 'nav:/incidents', label: 'Incidents', hint: 'All tracked incidents', icon: '◷' },
]

export default function CommandPalette({ open, onClose }) {
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  const [incidents, setIncidents] = useState([])
  const [active, setActive] = useState(0)
  const inputRef = useRef(null)

  useEffect(() => {
    if (!open) return
    setQ('')
    setActive(0)
    listIncidents()
      .then((res) => setIncidents(res.incidents || []))
      .catch(() => setIncidents([]))
    setTimeout(() => inputRef.current?.focus(), 30)
  }, [open])

  const items = useMemo(() => {
    const inc = incidents.map((i) => ({
      id: `inc:${i.incident_id}`,
      label: `${i.incident_id} — ${i.title}`,
      hint: `risk ${i.risk_score} · ${i.severity}`,
      icon: '🔎',
      to: `/incidents/${i.incident_id}`,
    }))
    const all = [...PAGES.map((p) => ({ ...p, to: p.id.replace('nav:', '') })), ...inc]
    if (!q.trim()) return all.slice(0, 9)
    const needle = q.toLowerCase()
    return all.filter((x) => (x.label + ' ' + (x.hint || '')).toLowerCase().includes(needle)).slice(0, 9)
  }, [q, incidents])

  useEffect(() => setActive(0), [q])

  function go(item) {
    if (!item) return
    onClose()
    navigate(item.to)
  }

  function onKey(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((a) => Math.min(items.length - 1, a + 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((a) => Math.max(0, a - 1))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      go(items[active])
    } else if (e.key === 'Escape') {
      onClose()
    }
  }

  if (!open) return null

  return (
    <div className="cmdk-overlay no-print" onClick={onClose}>
      <div className="cmdk" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Command palette">
        <div className="cmdk-input-row">
          <span className="cmdk-search">⌕</span>
          <input
            ref={inputRef}
            className="cmdk-input"
            placeholder="Jump to a page or incident…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
            aria-label="Search"
          />
          <kbd className="cmdk-kbd">ESC</kbd>
        </div>
        <div className="cmdk-list">
          {items.length === 0 ? (
            <div className="cmdk-empty">No matches for “{q}”.</div>
          ) : (
            items.map((it, i) => (
              <button
                key={it.id}
                className={`cmdk-item ${i === active ? 'active' : ''}`}
                onMouseEnter={() => setActive(i)}
                onClick={() => go(it)}
              >
                <span className="cmdk-icon">{it.icon}</span>
                <span className="cmdk-label">{it.label}</span>
                {it.hint && <span className="cmdk-hint">{it.hint}</span>}
              </button>
            ))
          )}
        </div>
        <div className="cmdk-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> open</span>
          <span><kbd>esc</kbd> close</span>
        </div>
      </div>
    </div>
  )
}