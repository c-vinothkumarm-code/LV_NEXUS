/** Cost arithmetic shared by Dashboard, FinOps and Overview. Pure functions over rows returned by /dashboard/finops. */
export type DailyRow = { date: string; provider: string; cost_usd: number }

const iso = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`

export function monthWindow(today = new Date()) {
  const cur = new Date(today.getFullYear(), today.getMonth(), 1)
  const prev = new Date(today.getFullYear(), today.getMonth() - 1, 1)
  const daysPrev = new Date(today.getFullYear(), today.getMonth(), 0).getDate()
  const daysCur = new Date(today.getFullYear(), today.getMonth() + 1, 0).getDate()
  return { curStart: iso(cur), prevStart: iso(prev), today: iso(today), curMonth: iso(cur).slice(0, 7), prevMonth: iso(prev).slice(0, 7), daysPrev, daysCur }
}

export const monthLabel = (ym: string) => new Date(`${ym}-01T00:00:00`).toLocaleDateString('en-IN', { month: 'short', year: 'numeric' })
export const dayLabel = (d: string) => new Date(`${d}T00:00:00`).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' })

/**
 * Month-to-date versus the same days of the previous month. Billing data lags by a day or two, so "the same days"
 * means up to the last day that has current-month data, never up to today: comparing a 15-day month with a 17-day
 * month would show a false drop.
 */
export function monthCompare(rows: DailyRow[], today = new Date()) {
  const w = monthWindow(today)
  const cur = rows.filter((r) => r.date.startsWith(w.curMonth))
  const prev = rows.filter((r) => r.date.startsWith(w.prevMonth))
  const lastDay = cur.reduce((m, r) => Math.max(m, Number(r.date.slice(8, 10))), 0)
  const providers = [...new Set(rows.map((r) => r.provider))]
  const sum = (xs: DailyRow[], p?: string) => xs.filter((r) => !p || r.provider === p).reduce((a, r) => a + (r.cost_usd || 0), 0)
  const prevSame = prev.filter((r) => Number(r.date.slice(8, 10)) <= lastDay)
  const by = Object.fromEntries(providers.map((p) => {
    const c = sum(cur, p), b = sum(prevSame, p)
    return [p, { current: c, previousSame: b, previousFull: sum(prev, p), pct: lastDay && b > 0 ? (100 * (c - b)) / b : null }]
  }))
  const current = sum(cur), previousSame = sum(prevSame)
  return {
    window: w, lastDay, providers, by,
    total: { current, previousSame, previousFull: sum(prev), pct: lastDay && previousSame > 0 ? (100 * (current - previousSame)) / previousSame : null },
    hasPrevious: prev.length > 0,
  }
}

/** Day-of-month columns: current month vs previous month totals (null where a day has no data yet). */
export function dayOfMonthSeries(rows: DailyRow[], provider?: string, today = new Date()) {
  const w = monthWindow(today)
  const tot = (ym: string) => {
    const m = new Map<number, number>()
    for (const r of rows) if (r.date.startsWith(ym) && (!provider || r.provider === provider)) m.set(Number(r.date.slice(8, 10)), (m.get(Number(r.date.slice(8, 10))) ?? 0) + r.cost_usd)
    return m
  }
  const c = tot(w.curMonth), p = tot(w.prevMonth)
  const days = Math.max(w.daysCur, w.daysPrev)
  return Array.from({ length: days }, (_, i) => ({ day: String(i + 1).padStart(2, '0'), current: c.get(i + 1) ?? null, previous: p.get(i + 1) ?? null }))
}

/** Rows pivoted to one row per date with a column per provider. */
export function pivotByProvider(rows: DailyRow[], from?: string) {
  const m = new Map<string, Record<string, string | number>>()
  for (const r of rows) {
    if (from && r.date < from) continue
    const row = m.get(r.date) ?? { date: r.date }
    row[r.provider] = Math.round(((Number(row[r.provider]) || 0) + r.cost_usd) * 100) / 100
    m.set(r.date, row)
  }
  return [...m.values()].sort((a, b) => String(a.date).localeCompare(String(b.date)))
}

/** Cumulative month-to-date points, with the previous month's cumulative value at the same day for comparison. */
export function cumulative(rows: DailyRow[], provider?: string, today = new Date()) {
  const s = dayOfMonthSeries(rows, provider, today)
  let a = 0, b = 0
  const out: { x: string; y: number; prev: number | null }[] = []
  for (const d of s) {
    b += d.previous ?? 0
    if (d.current === null) continue
    a += d.current
    out.push({ x: d.day, y: Math.round(a * 100) / 100, prev: b || null })
  }
  return out
}
