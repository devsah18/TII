import React, { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, Alert, StatCard, SeverityBadge, Spinner, Empty } from '../components/ui.jsx'
import { TopBar } from '../Layout.jsx'
import { useToast } from '../components/Toast.jsx'
import PipelinePanel, { DEFAULT_STAGES } from '../components/PipelinePanel.jsx'
import {
  getLiveStatus,
  startLiveCapture,
  stopLiveCapture,
  listIncidents,
  ApiError,
} from '../services/api.js'

/**
 * Live Capture page. Drives POST /api/live/start|stop and polls status so the
 * packet/event counters move in real time. Captured packets flow through the
 * same deterministic pipeline, so incidents appear here as they are built.
 */
export default function LiveCapturePage({ online }) {
  const navigate = useNavigate()
  const toast = useToast()
  const [status, setStatus] = useState(null)
  const [incidents, setIncidents] = useState([])
  const [iface, setIface] = useState('')
  const [bpf, setBpf] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const timer = useRef(null)

  useEffect(() => {
    let cancelled = false
    async function poll() {
      try {
        const s = await getLiveStatus()
        if (cancelled) return
        setStatus(s)
        if (!iface && s.interfaces?.length) {
          // Prefer a real adapter over the loopback if available.
          const real = s.interfaces.find((i) => /wi-fi|ethernet/i.test(i.label)) || s.interfaces[0]
          setIface(real.name)
        }
        if (s.running) {
          const list = await listIncidents()
          if (!cancelled) setIncidents((list.incidents || []).filter((x) => true).slice(0, 8))
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof ApiError ? err.message : 'Live service unavailable.')
      }
    }
    poll()
    timer.current = setInterval(poll, 2500)
    return () => {
      cancelled = true
      clearInterval(timer.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function start() {
    setBusy(true)
    setError('')
    try {
      const res = await startLiveCapture(iface, bpf)
      toast.push(`Live capture started on ${res.interface}`, 'ok')
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Could not start capture.'
      setError(msg)
      toast.push(msg, 'error')
    } finally {
      setBusy(false)
    }
  }

  async function stop() {
    setBusy(true)
    try {
      const res = await stopLiveCapture()
      toast.push(`Capture stopped — ${res.packets} packets, ${res.events} events`, 'info')
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : 'Could not stop capture.', 'error')
    } finally {
      setBusy(false)
    }
  }

  const running = status?.running
  const interfaces = status?.interfaces || []
  const tsharkOk = status?.tshark_available !== false

  return (
    <>
      <TopBar
        title="Live Capture"
        subtitle="Stream packets from a network interface into the TRACE pipeline in real time."
        online={online}
      >
        {running ? (
          <button className="btn btn-danger" onClick={stop} disabled={busy}>
            ⏹ Stop capture
          </button>
        ) : (
          <button className="btn btn-primary" onClick={start} disabled={busy || !online || !iface}>
            {busy ? 'Starting…' : '⏺ Start capture'}
          </button>
        )}
      </TopBar>

      {!tsharkOk && (
        <Alert kind="warn" title="tshark not available">
          Live capture requires Wireshark's tshark on the server. Install Wireshark, then restart the
          backend.
        </Alert>
      )}

      {error && (
        <div style={{ marginBottom: 16 }}>
          <Alert kind="error" title="Live capture error">{error}</Alert>
        </div>
      )}

      <div className="grid grid-4" style={{ marginBottom: 15 }}>
        <StatCard
          label="Capture state"
          value={running ? '● LIVE' : '○ Idle'}
          foot={running ? status.interface : 'Not capturing'}
          colour={running ? '#ef4444' : '#38bdf8'}
        />
        <StatCard label="Packets" value={status?.packets ?? 0} foot="Captured this session" colour="#38bdf8" />
        <StatCard label="Events" value={status?.events ?? 0} foot="Normalized network events" colour="#a855f7" />
        <StatCard
          label="Elapsed"
          value={`${status?.elapsed_seconds ?? 0}s`}
          foot="Capture duration"
          colour="#22c55e"
        />
      </div>

      <div className="grid grid-7-5">
        <Card title="Capture source" icon="🎛" note="Choose an interface and optional BPF filter">
          {!status ? (
            <Spinner label="Querying capture interfaces…" />
          ) : interfaces.length === 0 ? (
            <Empty>No capture interfaces were found. Is Npcap installed and is the backend elevated?</Empty>
          ) : (
            <div className="stack" style={{ gap: 12 }}>
              <div>
                <label className="meta-label" htmlFor="iface">Network interface</label>
                <select
                  id="iface"
                  className="select"
                  style={{ width: '100%', marginTop: 6 }}
                  value={iface}
                  onChange={(e) => setIface(e.target.value)}
                  disabled={running}
                >
                  {interfaces.map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.index}. {i.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="meta-label" htmlFor="bpf">BPF filter (optional)</label>
                <input
                  id="bpf"
                  className="input"
                  style={{ width: '100%', marginTop: 6 }}
                  placeholder="e.g. tcp port 22 or host 10.0.0.5"
                  value={bpf}
                  onChange={(e) => setBpf(e.target.value)}
                  disabled={running}
                />
              </div>
              {running && (
                <Alert kind="ok" title="Capturing now">
                  Streaming from <span className="mono">{status.interface}</span>
                  {status.bpf_filter ? ` · filter: ${status.bpf_filter}` : ''}. New incidents appear as
                  traffic is classified.
                </Alert>
              )}
              <p className="card-note">
                Live capture reads a real interface, so on Windows the backend must run as
                Administrator (Npcap requirement). Detection stays deterministic and local.
              </p>
            </div>
          )}
        </Card>

        <Card title="Live incidents" icon="📡" note="Incidents built from captured traffic">
          {!running ? (
            <Empty>Start a capture to see live incidents.</Empty>
          ) : incidents.length === 0 ? (
            <Spinner label="Waiting for traffic to be classified…" />
          ) : (
            <div className="stack" style={{ gap: 8 }}>
              {incidents.map((i) => (
                <div
                  key={i.incident_id}
                  className="alert-item"
                  style={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/incidents/${i.incident_id}`)}
                >
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div className="spread" style={{ gap: 8 }}>
                      <strong style={{ fontSize: '0.84rem' }}>{i.incident_id}</strong>
                      <SeverityBadge severity={i.severity} />
                    </div>
                    <div className="card-note" style={{ fontSize: '0.75rem' }}>
                      risk {i.risk_score}/100 · {i.title}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div style={{ marginTop: 16 }}>
        <PipelinePanel
          stages={DEFAULT_STAGES}
          activeCount={running ? (status?.events > 0 ? 6 : 3) : -1}
          title="Automatic analysis pipeline"
          note={
            running
              ? `streaming · ${status?.packets ?? 0} packets · ${status?.events ?? 0} events classified`
              : 'idle — start a capture to analyse traffic automatically'
          }
        />
      </div>
    </>
  )
}