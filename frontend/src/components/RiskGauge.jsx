import React from 'react'
import { scoreColour } from '../utils/format.js'

/** Risk gauge: an arc whose fill and colour are derived from the real score. */
export default function RiskGauge({ score = 0, severity = 'info', size = 168 }) {
  const pct = Math.max(0, Math.min(100, Number(score) || 0))
  const r = 62
  const circumference = Math.PI * r // half circle
  const filled = (pct / 100) * circumference
  const colour = scoreColour(pct)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <svg width={size} height={size * 0.62} viewBox="0 0 160 100" role="img" aria-label={`Risk score ${pct} out of 100`}>
        <path d="M 18 88 A 62 62 0 0 1 142 88" fill="none" stroke="rgba(143,162,192,0.16)" strokeWidth="12" strokeLinecap="round" />
        <path
          d="M 18 88 A 62 62 0 0 1 142 88"
          fill="none"
          stroke={colour}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          style={{ transition: 'stroke-dasharray .7s ease' }}
        />
        <text x="80" y="72" textAnchor="middle" fill="#e8eefb" fontSize="34" fontWeight="700">
          {pct}
        </text>
        <text x="80" y="90" textAnchor="middle" fill="#6b7f9e" fontSize="11">
          / 100
        </text>
      </svg>
      <div style={{ fontSize: '0.74rem', letterSpacing: '0.11em', textTransform: 'uppercase', color: colour, fontWeight: 700 }}>
        {String(severity).toUpperCase()}
      </div>
    </div>
  )
}
