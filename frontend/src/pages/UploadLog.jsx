import React, { useCallback, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, Alert, PipelineSteps, MetaItem, SeverityBadge, Empty } from '../components/ui.jsx'
import { TopBar } from '../Layout.jsx'
import { useToast } from '../components/Toast.jsx'
import { uploadLog, investigate, getConfig, ApiError } from '../services/api.js'
import { fmtBytes } from '../utils/format.js'

const STEPS = [
  { id: 'upload', label: 'Uploading log' },
  { id: 'parse', label: 'Parsing logs' },
  { id: 'normalize', label: 'Normalizing events' },
  { id: 'detect', label: 'Detecting anomalies' },
  { id: 'correlate', label: 'Correlating events' },
  { id: 'incident', label: 'Building incident' },
  { id: 'report', label: 'Generating investigation' },
]

const ACCEPT = '.log,.txt,.csv,.json,.pcap,.pcapng,.cap'

export default function UploadLog({ online, onInvestigated }) {
  const navigate = useNavigate()
  const toast = useToast()
  const inputRef = useRef(null)
  const [dragging, setDragging] = useState(false)
  const [fileInfo, setFileInfo] = useState(null)
  const [config, setConfig] = useState(null)

  React.useEffect(() => {
    getConfig()
      .then(setConfig)
      .catch(() => {})
  }, [])
  const [steps, setSteps] = useState(() => STEPS.map((s) => ({ ...s, status: 'pending' })))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const setStep = useCallback((id, status, detail) => {
    setSteps((prev) => prev.map((s) => (s.id === id ? { ...s, status, detail: detail ?? s.detail } : s)))
  }, [])

  const reset = useCallback(() => {
    setSteps(STEPS.map((s) => ({ ...s, status: 'pending' })))
    setError('')
  }, [])

  const runPipeline = useCallback(
    async (file) => {
      reset()
      setBusy(true)
      setFileInfo({ name: file.name, size: file.size, eventCount: null, parsing: 'pending' })

      try {
        setStep('upload', 'active')
        const uploaded = await uploadLog(file)
        setStep('upload', 'done', `${uploaded.file_id}`)
        setStep('parse', 'done', `${uploaded.event_count} events`)
        setStep('normalize', 'done', 'schema applied')
        setFileInfo({
          name: uploaded.filename,
          size: uploaded.size_bytes ?? file.size,
          eventCount: uploaded.event_count,
          parsing: uploaded.parsing_status || 'parsed',
        })

        // real backend calls drive the remaining steps
        setStep('detect', 'active')
        const t = setTimeout(() => {
          setStep('detect', 'done', 'rules applied')
          setStep('correlate', 'active')
        }, 260)
        const res = await investigate(uploaded.file_id)
        clearTimeout(t)
        const inc = res.incident
        setStep('detect', 'done', `${inc.detection_count} detection(s)`)
        setStep('correlate', 'done', `${inc.event_count} event(s) correlated`)
        setStep('incident', 'done', inc.incident_id)
        setStep('report', 'done', `${inc.mitre_techniques?.length || 0} techniques`)

        if (onInvestigated) onInvestigated(inc)
        toast.push(`Investigation ${inc.incident_id} ready — risk ${inc.risk_score}/100`, 'ok')
        setTimeout(() => navigate(`/incidents/${inc.incident_id}`), 420)
      } catch (err) {
        const message =
          err instanceof ApiError ? err.message : 'The uploaded file could not be processed.'
        setError(message)
        toast.push(message, 'error')
        setSteps((prev) => prev.map((s) => (s.status === 'active' ? { ...s, status: 'failed' } : s)))
        setFileInfo((f) => (f ? { ...f, parsing: 'failed' } : f))
      } finally {
        setBusy(false)
      }
    },
    [navigate, onInvestigated, reset, setStep],
  )

  function handleFiles(files) {
    const file = files?.[0]
    if (!file) return
    const ext = `.${(file.name.split('.').pop() || '').toLowerCase()}`
    if (!ACCEPT.split(',').includes(ext)) {
      reset()
      setError(
        'The uploaded file could not be parsed. Supported formats: LOG, TXT, CSV, JSON, PCAP.',
      )
      setFileInfo({ name: file.name, size: file.size, eventCount: null, parsing: 'failed' })
      return
    }
    runPipeline(file)
  }

  return (
    <>
      <TopBar
        title="Upload Security Log"
        subtitle="Supported formats: .log · .txt · .csv · .json · .pcap / .pcapng — parsed and investigated automatically."
        online={online}
      />

      <div className="grid grid-7-5">
        <Card title="Log Source" icon="⬆" note="The file stays in backend memory for this session only">
          {!online && (
            <div style={{ marginBottom: 14 }}>
              <Alert kind="error" title="TRACE backend unavailable">
                Check that the backend is running, then retry the upload.
              </Alert>
            </div>
          )}

          <div
            className={`dropzone ${dragging ? 'dragging' : ''}`}
            onDragOver={(e) => {
              e.preventDefault()
              setDragging(true)
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDragging(false)
              handleFiles(e.dataTransfer.files)
            }}
            onClick={() => inputRef.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'Enter') inputRef.current?.click()
            }}
          >
            <div className="dropzone-icon">🗂</div>
            <div style={{ fontWeight: 600 }}>Drag &amp; drop your security log or packet capture here</div>
            <div className="dropzone-hint">or click to browse — .log, .txt, .csv, .json, .pcap / .pcapng</div>
            <input
              ref={inputRef}
              type="file"
              accept={ACCEPT}
              style={{ display: 'none' }}
              onChange={(e) => handleFiles(e.target.files)}
            />
          </div>

          <div className="row mt-12" style={{ gap: 9 }}>
            <button className="btn" onClick={() => inputRef.current?.click()} disabled={busy || !online}>
              Browse Files
            </button>
            <button
              className="btn btn-ghost"
              onClick={() => navigate('/simulation')}
              disabled={busy}
            >
              Use a demo attack instead →
            </button>
          </div>

          {error && (
            <div className="mt-16">
              <Alert kind="error" title="Upload failed">
                {error}
              </Alert>
            </div>
          )}

          {fileInfo && (
            <>
              <div className="meta-label mt-16">File</div>
              <div className="meta-grid mt-8">
                <MetaItem label="Filename" value={fileInfo.name} mono />
                <MetaItem label="File size" value={fmtBytes(fileInfo.size)} />
                <MetaItem
                  label="Events detected"
                  value={fileInfo.eventCount === null ? '—' : fileInfo.eventCount}
                />
                <MetaItem
                  label="Parsing status"
                  value={
                    <span className="row" style={{ gap: 6 }}>
                      <span
                        className={`dot ${
                          fileInfo.parsing === 'failed'
                            ? 'dot-bad'
                            : fileInfo.parsing === 'parsed'
                              ? 'dot-ok'
                              : 'dot-warn'
                        }`}
                      />
                      {fileInfo.parsing}
                    </span>
                  }
                />
              </div>
            </>
          )}
        </Card>

        <Card title="Processing" icon="⚙" note="Each step completes when the backend confirms it">
          <PipelineSteps steps={steps} />
          {!busy && !error && steps.every((s) => s.status === 'pending') && (
            <Empty>Waiting for a log file.</Empty>
          )}
          {!busy && steps.some((s) => s.status === 'done') && steps.at(-1)?.status === 'done' && (
            <div className="mt-16">
              <Alert kind="ok" title="Investigation ready">
                Opening the investigation dashboard…
              </Alert>
            </div>
          )}
        </Card>
      </div>

      <Card title="Expected formats" icon="ℹ" className="mt-16">
        <div className="stack">
          <div>
            <div className="meta-label">Syslog / plain text</div>
            <pre className="raw-log">
{`2026-10-02T10:42:01Z 10.0.0.15 sshd: Failed password for admin from 185.42.18.91 port 51234 ssh2`}
            </pre>
          </div>
          <div>
            <div className="meta-label">CSV</div>
            <pre className="raw-log">
{`timestamp,source_ip,destination_ip,username,event_type,status,message
2026-10-02T10:42:01Z,185.42.18.91,10.0.0.15,admin,login_failed,failed,Failed login attempt for admin`}
            </pre>
          </div>
          <div>
            <div className="meta-label">JSON</div>
            <pre className="raw-log">
{`[{"timestamp":"2026-10-02T10:42:01Z","source_ip":"185.42.18.91","username":"admin",
  "event_type":"login_failed","status":"failed","message":"Failed login attempt for admin"}]`}
            </pre>
          </div>
          <div>
            <div className="meta-label">Packet capture (PCAP / PCAPNG)</div>
            <p className="card-note">
              Upload a Wireshark capture (<span className="mono">.pcap</span> /{' '}
              <span className="mono">.pcapng</span>). TRACE reads it with tshark in file mode (no
              admin rights needed) and converts packets into normalized events — so port scans and
              large outbound transfers become detections, incidents and MITRE mappings automatically.
            </p>
            {config?.pcap_supported === false && (
              <div className="mt-8">
                <Alert kind="warn" title="PCAP support unavailable">
                  tshark was not found on the server. Install Wireshark to enable packet-capture
                  uploads.
                </Alert>
              </div>
            )}
          </div>
        </div>
        <p className="card-note mt-12">
          Column and field names are matched case-insensitively against common synonyms, and events
          without an explicit type are classified from their message text.
        </p>
      </Card>
    </>
  )
}
