import { useCallback, useEffect, useState } from 'react'

/**
 * Dark/Light theme with persistence.
 *
 * The theme is applied by setting `data-theme` on <html>. All colours are CSS
 * variables, so switching the attribute re-themes the whole app instantly with
 * no re-render of React components.
 */
const STORAGE_KEY = 'trace-theme'

function initial() {
  if (typeof window === 'undefined') return 'dark'
  const saved = window.localStorage.getItem(STORAGE_KEY)
  if (saved === 'light' || saved === 'dark') return saved
  // Respect the OS preference the first time.
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

export default function useTheme() {
  const [theme, setTheme] = useState(initial)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try {
      window.localStorage.setItem(STORAGE_KEY, theme)
    } catch {
      /* ignore storage failures (private mode) */
    }
  }, [theme])

  const toggle = useCallback(() => setTheme((t) => (t === 'dark' ? 'light' : 'dark')), [])

  return { theme, setTheme, toggle }
}