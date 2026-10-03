import React, { useEffect, useRef, useState } from 'react'
import { askTrace, getChatSuggestions, ApiError } from '../services/api.js'

/**
 * "Ask TRACE" panel. Every question is sent to POST /api/chat with the incident
 * id; answers are grounded in the incident data returned by the backend.
 */
export default function AIInvestigator({ incidentId, summary }) {
  const [messages, setMessages] = useState([])
  const [suggestions, setSuggestions] = useState([
    'Why is this incident critical?',
    'What happened first?',
    'Which account was compromised?',
    'What evidence indicates brute force?',
    'What did the attacker access?',
    'What should the security team do first?',
  ])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const logRef = useRef(null)

  useEffect(() => {
    let cancelled = false
    getChatSuggestions()
      .then((res) => {
        if (!cancelled && res?.questions?.length) setSuggestions(res.questions)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [messages, busy])

  async function send(question) {
    const q = (question ?? input).trim()
    if (!q || busy) return
    setInput('')
    setError('')
    setMessages((m) => [...m, { role: 'user', text: q }])
    setBusy(true)
    try {
      const res = await askTrace(incidentId, q)
      setMessages((m) => [
        ...m,
        { role: 'assistant', text: res.answer, sources: res.sources || [], mode: res.mode },
      ])
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.message
          : 'The investigator could not answer that question.'
      setError(msg)
      setMessages((m) => [
        ...m,
        { role: 'assistant', text: `I could not answer that: ${msg}`, sources: [], failed: true },
      ])
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="alert alert-info no-print" style={{ marginBottom: 14 }}>
        <span className="alert-icon">🤖</span>
        <div className="alert-body">
          <strong>Ask TRACE about incident {incidentId}</strong>
          Answers are generated from this incident's parsed events, detections, risk factors, MITRE
          mappings and response plan. If no external AI provider is configured, the deterministic
          investigator answers from the same data.
        </div>
      </div>

      {summary && (
        <div className="card-note" style={{ marginBottom: 12 }}>
          <strong style={{ color: '#c9d6ea' }}>Context in use:</strong> {summary}
        </div>
      )}

      <div className="chat-log" ref={logRef}>
        {messages.length === 0 && (
          <div className="chat-msg assistant">
            <div className="chat-avatar">TR</div>
            <div className="chat-bubble">
              I have analysed incident <span className="mono">{incidentId}</span>. Ask me about the
              attack sequence, the evidence, the affected account, the risk score or the response
              plan.
            </div>
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`chat-msg ${m.role}`}>
            <div className="chat-avatar">{m.role === 'user' ? 'YOU' : 'TR'}</div>
            <div className="chat-bubble">
              {m.text}
              {m.sources?.length > 0 && (
                <div className="chat-sources">
                  <div className="chat-sources-label">Sources</div>
                  {m.sources.map((s, j) => (
                    <div key={j} className="chat-source">
                      {s}
                    </div>
                  ))}
                </div>
              )}
              {m.mode && !m.failed && (
                <div className="chat-sources-label" style={{ marginTop: 7 }}>
                  mode: {m.mode === 'llm' ? 'AI provider' : 'deterministic fallback'}
                </div>
              )}
            </div>
          </div>
        ))}
        {busy && (
          <div className="chat-msg assistant">
            <div className="chat-avatar">TR</div>
            <div className="chat-bubble">
              <span className="spinner" style={{ display: 'inline-block', verticalAlign: 'middle' }} />{' '}
              Analysing the incident…
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="alert alert-warn mt-12">
          <span className="alert-icon">⚠</span>
          <div className="alert-body">{error}</div>
        </div>
      )}

      <div className="chip-row">
        {suggestions.slice(0, 6).map((s) => (
          <button key={s} className="chip" onClick={() => send(s)} disabled={busy}>
            {s}
          </button>
        ))}
      </div>

      <form
        className="chat-input-row"
        onSubmit={(e) => {
          e.preventDefault()
          send()
        }}
      >
        <input
          className="input"
          placeholder="Ask about this incident…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={busy}
          aria-label="Ask TRACE a question"
        />
        <button className="btn btn-primary" type="submit" disabled={busy || !input.trim()}>
          {busy ? 'Asking…' : 'Ask TRACE'}
        </button>
      </form>
    </>
  )
}
