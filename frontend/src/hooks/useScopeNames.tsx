import { useEffect, useState } from 'react'
import { api } from '../services/api'

type Names = Record<string, Record<string, string>>
let cache: Names | null = null
let pending: Promise<Names> | null = null
let loadedAt = 0
const TTL = 5 * 60_000

function load(): Promise<Names> {
  if (cache && Date.now() - loadedAt < TTL) return Promise.resolve(cache)
  pending ??= api.get<Names>('/accounts/names').then((d) => { cache = d; loadedAt = Date.now(); return d }).catch(() => cache ?? {}).finally(() => { pending = null })
  return pending
}

/** Account / subscription / project display names, shared by every page (one request, refreshed every 5 minutes). */
export function useScopeNames() {
  const [names, setNames] = useState<Names>(cache ?? {})
  useEffect(() => { let live = true; void load().then((d) => { if (live) setNames(d) }); return () => { live = false } }, [])
  return (provider: string | null | undefined, id: string | null | undefined): string | null => {
    if (!id) return null
    if (provider && names[provider]?.[id]) return names[provider][id]
    for (const p of Object.values(names)) if (p[id]) return p[id]
    return null
  }
}

/** Shows the subscription / account / project name; the raw ID stays in the tooltip and as small secondary text when asked. */
export function ScopeName({ provider, id, name: given, showId = false, className }: { provider?: string | null; id?: string | null; name?: string | null; showId?: boolean; className?: string }) {
  const nameOf = useScopeNames()
  if (!id || id === '*' || id === '-') return <span className={className}>{id && id !== '-' ? 'All' : '—'}</span>
  const name = given || nameOf(provider, id)
  return (
    <span className={className} title={id}>
      {name ?? id}
      {name && showId && <span className="ml-1 text-[10.5px] text-ink-3">({id.length > 14 ? `${id.slice(0, 8)}…` : id})</span>}
    </span>
  )
}
