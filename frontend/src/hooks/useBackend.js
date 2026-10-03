import { useCallback, useEffect, useState } from 'react'
import { getHealth, getStats, ApiError } from '../services/api.js'

/** Backend health + dashboard aggregates, with graceful offline handling. */
export default function useBackend() {
  const [health, setHealth] = useState(null)
  const [stats, setStats] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const h = await getHealth()
      setHealth(h)
      setError(null)
      try {
        const s = await getStats()
        setStats(s)
      } catch (err) {
        if (err instanceof ApiError) setError(err)
      }
    } catch (err) {
      setHealth(null)
      setStats(null)
      setError(err instanceof ApiError ? err : new ApiError('Backend unavailable'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  return { health, stats, error, loading, refresh, online: Boolean(health?.status === 'ok') }
}
