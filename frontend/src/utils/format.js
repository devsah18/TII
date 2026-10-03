export const SEVERITY_LABEL = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
}

export const SEVERITY_COLOUR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f5b21a',
  low: '#22c55e',
  info: '#38bdf8',
}

export function severityClass(s) {
  return `badge badge-${SEVERITY_LABEL[s] ? s : 'neutral'}`
}

export function scoreColour(score) {
  if (score >= 85) return '#ef4444'
  if (score >= 70) return '#f97316'
  if (score >= 45) return '#f5b21a'
  if (score >= 20) return '#22c55e'
  return '#38bdf8'
}

export function fmtTime(ts) {
  if (!ts || ts.length < 19) return ts || '—'
  return ts.slice(11, 19) + ' UTC'
}

export function fmtDateTime(ts) {
  if (!ts || ts.length < 19) return ts || '—'
  return `${ts.slice(0, 10)} ${ts.slice(11, 19)} UTC`
}

export function fmtBytes(n) {
  if (n === null || n === undefined) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export function fmtPct(v) {
  if (v === null || v === undefined) return '—'
  const n = Number(v)
  return `${Math.round(n * 100)}%`
}

export function eventTypeLabel(t) {
  return String(t || '')
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
}

export function detectionLabel(t) {
  return (
    {
      brute_force: 'Brute Force',
      account_compromise: 'Account Compromise',
      privilege_escalation: 'Privilege Escalation',
      sensitive_data_access: 'Sensitive Data Access',
      data_exfiltration: 'Data Exfiltration',
      reconnaissance: 'Reconnaissance',
      suspicious_source_ip: 'Suspicious Source IP',
    }[t] || eventTypeLabel(t)
  )
}

export function relativeTime(iso) {
  if (!iso) return ''
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return ''
  const diff = Math.max(0, Date.now() - then)
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs} h ago`
  return `${Math.floor(hrs / 24)} d ago`
}
