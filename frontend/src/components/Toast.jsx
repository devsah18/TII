import React, { createContext, useCallback, useContext, useRef, useState } from 'react'

/**
 * Lightweight toast system. `useToast().push(message, kind)` shows a transient
 * notification in the corner. No dependencies — a small context + timers.
 */
const ToastCtx = createContext(null)

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const seq = useRef(0)

  const push = useCallback((message, kind = 'info', ttl = 3800) => {
    seq.current += 1
    const id = seq.current
    setToasts((t) => [...t, { id, message, kind }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), ttl)
  }, [])

  const dismiss = useCallback((id) => setToasts((t) => t.filter((x) => x.id !== id)), [])

  return (
    <ToastCtx.Provider value={{ push }}>
      {children}
      <div className="toast-stack no-print" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.kind}`} onClick={() => dismiss(t.id)}>
            <span className="toast-bar" />
            <span className="toast-msg">{t.message}</span>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

export function useToast() {
  const ctx = useContext(ToastCtx)
  // Safe fallback so components don't crash outside the provider.
  return ctx || { push: () => {} }
}