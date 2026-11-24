import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../services/api'

const REFRESH_MS = 60_000

/** Fetches a dashboard endpoint, refreshes every minute and whenever `refreshKey` or params change. */
export function useApi<T>(path: string | null, params?: Record<string, string | number | undefined | null>, refreshKey = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(true)
  const key = JSON.stringify(params ?? {})
  const seq = useRef(0)

  const load = useCallback(async () => {
    if (!path) return
    const mine = ++seq.current
    try {
      const d = await api.get<T>(path, JSON.parse(key))
      if (mine === seq.current) { setData(d); setError(null) }
    } catch (e) {
      if (mine === seq.current) setError(e instanceof ApiError ? e : new ApiError(0, 'Cannot reach the API'))
    } finally {
      if (mine === seq.current) setLoading(false)
    }
  }, [path, key])

  useEffect(() => {
    setLoading(true)
    void load()
    const t = setInterval(() => void load(), REFRESH_MS)
    return () => clearInterval(t)
  }, [load, refreshKey])

  return { data, error, loading, reload: load }
}
