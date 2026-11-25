import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'

export interface Filters {
  provider: string; scope: string; region: string; environment: string
  dateFrom: string; dateTo: string; severity: string; reviewStatus: string; search: string
}
const EMPTY: Filters = { provider: '', scope: '', region: '', environment: '', dateFrom: '', dateTo: '', severity: '', reviewStatus: '', search: '' }

interface FilterState { filters: Filters; set: (patch: Partial<Filters>) => void; reset: () => void; refreshKey: number; refresh: () => void }
const Ctx = createContext<FilterState | null>(null)

export function FilterProvider({ children }: { children: ReactNode }) {
  const [filters, setFilters] = useState(EMPTY)
  const [refreshKey, setRefreshKey] = useState(0)
  const value = useMemo<FilterState>(() => ({
    filters, refreshKey,
    set: (patch) => setFilters((f) => ({ ...f, ...patch })),
    reset: () => setFilters(EMPTY),
    refresh: () => setRefreshKey((k) => k + 1),
  }), [filters, refreshKey])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useFilters(): FilterState {
  const v = useContext(Ctx)
  if (!v) throw new Error('FilterProvider missing')
  return v
}
