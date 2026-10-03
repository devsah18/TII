import React, { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { BASE_DISPLAY } from './services/api.js'
import { StatusPill } from './components/ui.jsx'
import useTheme from './hooks/useTheme.js'

const NAV = [
  { to: '/', icon: '◈', label: 'Dashboard' },
  { to: '/upload', icon: '⬆', label: 'Upload Log' },
  { to: '/simulation', icon: '⚡', label: 'Simulation' },
  { to: '/live', icon: '📡', label: 'Live Capture' },
  { to: '/incidents', icon: '◷', label: 'Incidents' },
  { to: '/history', icon: '🗃', label: 'History' },
]

export default function Layout({ online, health, children, onOpenPalette }) {
  const { pathname } = useLocation()
  const { theme, toggle } = useTheme()
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div className={`app-shell ${collapsed ? 'collapsed' : ''}`}>
      <aside className="sidebar no-print">
        <div className="brand">
          <div className="brand-mark">TR</div>
          <div className="brand-text collapse-hide">
            <span className="brand-title">TRACE</span>
            <span className="brand-sub">Incident Investigator</span>
          </div>
          <button
            className="theme-toggle"
            onClick={toggle}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            aria-label="Toggle colour theme"
          >
            {theme === 'dark' ? '☀' : '🌙'}
          </button>
        </div>

        <button className="palette-trigger" onClick={onOpenPalette} title="Open command palette (Ctrl+K)">
          <span className="pt-icon">⌕</span>
          <span className="collapse-hide" style={{ flex: 1, textAlign: 'left' }}>Search or jump to…</span>
          <kbd className="collapse-hide">Ctrl K</kbd>
        </button>

        <nav className="nav" aria-label="Primary">
          <div className="nav-group-label collapse-hide">Operations</div>
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              title={n.label}
              className={({ isActive }) =>
                `nav-link ${isActive || (n.to === '/incidents' && pathname.startsWith('/incidents')) ? 'active' : ''}`
              }
            >
              <span className="nav-icon" aria-hidden="true">
                {n.icon}
              </span>
              <span className="collapse-hide">{n.label}</span>
            </NavLink>
          ))}
        </nav>

        <button
          className="collapse-btn"
          onClick={() => setCollapsed((c) => !c)}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? '»' : '«'} <span className="collapse-hide">Collapse</span>
        </button>

        <div className="sidebar-foot">
          <div className="card card-pad collapse-hide" style={{ padding: '12px 13px' }}>
            <div className="meta-label">Backend</div>
            <div className="row mt-8" style={{ gap: 7 }}>
              <span className={`dot ${online ? 'dot-ok pulse' : 'dot-bad'}`} />
              <span style={{ fontSize: '0.82rem', fontWeight: 600 }}>
                {online ? 'Connected' : 'Unavailable'}
              </span>
            </div>
            <div className="card-note mt-8" style={{ fontSize: '0.72rem', wordBreak: 'break-all' }}>
              {BASE_DISPLAY}
            </div>
            {health && (
              <div className="card-note" style={{ fontSize: '0.72rem', marginTop: 4 }}>
                {health.service} v{health.version}
              </div>
            )}
          </div>
          <div className="card-note" style={{ fontSize: '0.7rem', padding: '0 6px 6px' }}>
            Detection and correlation run locally and deterministically. Recommendations are advisory
            only.
          </div>
        </div>
      </aside>

      <main className="main">{children}</main>
    </div>
  )
}

export function TopBar({ title, subtitle, children, online }) {
  return (
    <header className="topbar no-print">
      <div className="topbar-left">
        <div>
          <h1>{title}</h1>
          {subtitle && <div className="page-sub">{subtitle}</div>}
        </div>
      </div>
      <div className="topbar-right">
        {online !== undefined && (
          <StatusPill state={online ? 'ok' : 'bad'}>{online ? 'System online' : 'Backend offline'}</StatusPill>
        )}
        {children}
      </div>
    </header>
  )
}
