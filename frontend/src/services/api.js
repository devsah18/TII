/**
 * TRACE API service — the single place that knows backend URLs.
 * Every endpoint here matches the contract in the spec exactly.
 */
const RAW_BASE = (import.meta.env.VITE_API_URL || '').trim()
export const API_BASE = RAW_BASE.replace(/\/+$/, '')
export const BASE_DISPLAY = API_BASE || 'same-origin (/api via dev proxy)'

const DEFAULT_TIMEOUT = 25000

export class ApiError extends Error {
  constructor(message, { status = 0, kind = 'error', detail = null } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.kind = kind // offline | timeout | http | parse | unknown
    this.detail = detail
  }
}

function url(path) {
  return `${API_BASE}${path}`
}

async function request(path, { method = 'GET', body, headers = {}, timeout = DEFAULT_TIMEOUT } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)

  try {
    const res = await fetch(url(path), {
      method,
      headers,
      body,
      signal: controller.signal,
    })

    const text = await res.text()
    let data = null
    if (text) {
      try {
        data = JSON.parse(text)
      } catch {
        data = null
      }
    }

    if (!res.ok) {
      const detail =
        (data && (data.detail || data.error)) ||
        (text && text.slice(0, 240)) ||
        `HTTP ${res.status}`
      throw new ApiError(String(detail), { status: res.status, kind: 'http', detail: data })
    }

    if (data === null) {
      throw new ApiError('The backend returned a response that could not be read.', {
        status: res.status,
        kind: 'parse',
      })
    }
    return data
  } catch (err) {
    if (err instanceof ApiError) throw err
    if (err.name === 'AbortError') {
      throw new ApiError(
        `The request timed out after ${Math.round(timeout / 1000)}s. The backend may be overloaded.`,
        { kind: 'timeout' },
      )
    }
    throw new ApiError(
      'TRACE backend unavailable. Check that the backend is running and reachable at the configured API URL.',
      { kind: 'offline' },
    )
  } finally {
    clearTimeout(timer)
  }
}

const jsonHeaders = { 'Content-Type': 'application/json' }

/* ------------------------------------------------------------------ health */
export const getHealth = () => request('/api/health', { timeout: 6000 })

export const getConfig = () => request('/api/config', { timeout: 6000 })

export const getStats = () => request('/api/stats')

/* ------------------------------------------------------------------ upload */
export async function uploadLog(file, onProgress) {
  const form = new FormData()
  form.append('file', file)
  if (onProgress) onProgress('uploading')
  const res = await request('/api/upload', {
    method: 'POST',
    body: form,
    timeout: 60000,
  })
  if (onProgress) onProgress('parsed')
  return res
}

/* ------------------------------------------------------------- investigate */
export const investigate = (fileId) =>
  request('/api/investigate', {
    method: 'POST',
    headers: jsonHeaders,
    body: JSON.stringify({ file_id: fileId }),
    timeout: 45000,
  })

/* ---------------------------------------------------------------- simulate */
export const getScenarios = () => request('/api/simulate')

export const simulate = (scenario = 'brute_force') =>
  request('/api/simulate', {
    method: 'POST',
    headers: jsonHeaders,
    body: JSON.stringify({ scenario }),
    timeout: 45000,
  })

/* ------------------------------------------------------------- scenarios */
// Spec-named endpoints. `listScenarioCatalog` maps GET /api/scenarios and
// `loadScenario` maps POST /api/scenarios/{name}/load (both backed by the same
// deterministic demo engine as /api/simulate).
export const listScenarioCatalog = () =>
  request('/api/scenarios', { timeout: 8000 }).then((res) => res?.scenarios || [])

export const loadScenario = (name) =>
  request(`/api/scenarios/${encodeURIComponent(name)}/load`, {
    method: 'POST',
    timeout: 45000,
  })

/* --------------------------------------------------------------- incidents */
export const listIncidents = () => request('/api/incidents')

export const getIncident = (incidentId) =>
  request(`/api/incidents/${encodeURIComponent(incidentId)}`)

export const getFile = (fileId) => request(`/api/files/${encodeURIComponent(fileId)}`)

/* -------------------------------------------------------------------- chat */
export const getChatSuggestions = () => request('/api/chat/suggestions', { timeout: 6000 })

export const askTrace = (incidentId, question) =>
  request('/api/chat', {
    method: 'POST',
    headers: jsonHeaders,
    body: JSON.stringify({ incident_id: incidentId, question }),
    timeout: 30000,
  })

/* ------------------------------------------------------------------ report */
export const buildReport = (incidentId) =>
  request(`/api/report/${encodeURIComponent(incidentId)}`, { method: 'POST', timeout: 20000 })

/* ------------------------------------------------------------------ alerts */
export const getAlerts = (limit = 30) => request(`/api/alerts?limit=${limit}`, { timeout: 8000 })

export const ackAlert = (alertId) =>
  request(`/api/alerts/${encodeURIComponent(alertId)}/ack`, { method: 'POST', timeout: 8000 })

/* ------------------------------------------------------- detection tuning */
export const reanalyze = (fileId, thresholds) =>
  request('/api/reanalyze', {
    method: 'POST',
    headers: jsonHeaders,
    body: JSON.stringify({ file_id: fileId, thresholds: thresholds || {} }),
    timeout: 45000,
  })
