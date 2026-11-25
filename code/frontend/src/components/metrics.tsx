import { ArrowUpRight, Info, X } from 'lucide-react'
import { useEffect, useId, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useCountUp } from '../hooks/useMotion'
import { fmtAgo, fmtInt, fmtTime, fmtUsd, fmtUsdShort, PROVIDER_LABEL } from './ui'

export interface MetricDef {
  key: string; section: string; label: string; value: number | null; unit: 'count' | 'usd' | 'percent' | 'minutes' | 'hours'
  definition: string; source: string; calculation: string; as_of: string | null; scope: string
  availability: 'available' | 'not_collected' | 'stale' | 'failed' | 'not_applicable'; reason: string | null
  breakdown: Record<string, number> | null; link: string; tone: 'good' | 'warning' | 'serious' | 'critical' | null; note: string | null
}
export interface MetricsResponse { generated_at: string; sections: { key: string; label: string; link: string }[]; metrics: MetricDef[] }

const TONE: Record<string, string> = { good: 'var(--good)', warning: 'var(--warning)', serious: 'var(--serious)', critical: 'var(--critical)' }
const AVAIL: Record<string, { text: string; color: string }> = {
  not_collected: { text: 'Not collected', color: 'var(--unknown)' },
  stale: { text: 'Stale', color: 'var(--warning)' },
  failed: { text: 'Last collection failed', color: 'var(--critical)' },
  not_applicable: { text: 'Not applicable', color: 'var(--unknown)' },
}

export function fmtMetric(v: number | null, unit: MetricDef['unit'], short = true): string {
  if (v === null || v === undefined || Number.isNaN(v)) return '—'
  if (unit === 'usd') return v < 0 ? `−${short ? fmtUsdShort(-v) : fmtUsd(-v)}` : short ? fmtUsdShort(v) : fmtUsd(v)
  if (unit === 'percent') return `${v.toFixed(v >= 99.95 || Number.isInteger(v) ? 0 : 1)}%`
  if (unit === 'minutes') return v < 90 ? `${v.toFixed(v < 10 ? 1 : 0)} min` : `${(v / 60).toFixed(1)} h`
  if (unit === 'hours') return `${v.toFixed(1)} h`
  return fmtInt(Math.round(v))
}

/** The "how is this calculated" panel: definition, source, calculation, scope, timestamp and availability. */
function MetricInfo({ m, onClose, id }: { m: MetricDef; onClose: () => void; id: string }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    const onDown = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) onClose() }
    document.addEventListener('keydown', onKey); document.addEventListener('mousedown', onDown)
    ref.current?.focus()
    return () => { document.removeEventListener('keydown', onKey); document.removeEventListener('mousedown', onDown) }
  }, [onClose])
  const rows: [string, string | null][] = [['Definition', m.definition], ['Source', m.source], ['Calculation', m.calculation], ['Scope', m.scope],
    ['Data as of', m.as_of ? `${fmtTime(m.as_of)} (${fmtAgo(m.as_of)})` : 'never collected'],
    ['Availability', m.availability === 'available' ? 'Available' : AVAIL[m.availability]?.text ?? m.availability], ['Reason', m.reason], ['Note', m.note]]
  return (
    <div ref={ref} id={id} role="dialog" aria-label={`${m.label}: definition and source`} tabIndex={-1}
      className="cn-card cn-float-in absolute left-0 top-full z-30 mt-2 w-[min(92vw,360px)] p-4 text-left text-xs text-ink-2 outline-none" style={{ boxShadow: 'var(--shadow-2)' }}>
      <div className="mb-2 flex items-start justify-between gap-2"><div className="text-sm font-semibold text-ink">{m.label}</div>
        <button className="rounded p-0.5 text-ink-3 hover:bg-surface-2" onClick={onClose} aria-label="Close"><X size={14} /></button></div>
      <dl className="space-y-1.5">{rows.filter(([, v]) => v).map(([k, v]) => <div key={k}><dt className="font-semibold text-ink">{k}</dt><dd>{v}</dd></div>)}</dl>
      {m.breakdown && Object.keys(m.breakdown).length > 0 && (
        <div className="mt-2 border-t border-line pt-2"><div className="font-semibold text-ink">Breakdown</div>
          <ul className="mt-1 grid grid-cols-2 gap-x-3">{Object.entries(m.breakdown).map(([k, v]) => <li key={k} className="flex justify-between gap-2">
            <span>{PROVIDER_LABEL[k] ?? k.replace(/_/g, ' ').toLowerCase()}</span><b className="tabular text-ink">{m.unit === 'usd' ? fmtUsd(v) : fmtInt(v)}</b></li>)}</ul></div>)}
    </div>
  )
}

/** KPI card: counts up to the collected value, states clearly when the value is missing, stale or failed, and explains itself. */
export function MetricCard({ m }: { m: MetricDef }) {
  const [open, setOpen] = useState(false)
  const id = useId()
  const shown = useCountUp(m.value)
  const missing = m.value === null
  const avail = m.availability !== 'available' ? AVAIL[m.availability] : null
  return (
    <div className="cn-card cn-lift relative flex min-h-[124px] flex-col p-4" style={open ? { zIndex: 40 } : undefined}>
      <div className="flex items-start justify-between gap-2">
        <span className="text-[12.5px] font-medium text-ink-2">{m.label}</span>
        <button className="-mr-1 -mt-1 rounded-full p-1 text-ink-3 hover:bg-surface-2 hover:text-accent" onClick={() => setOpen((o) => !o)}
          aria-expanded={open} aria-controls={id} aria-label={`How "${m.label}" is calculated`}><Info size={14} /></button>
      </div>
      <Link to={m.link} className="group mt-1 flex items-baseline gap-2" aria-label={`${m.label}: ${missing ? 'no data' : fmtMetric(m.value, m.unit, false)}. Open details`}>
        <span className="cn-kpi" style={{ color: !missing && m.tone && m.tone !== 'good' ? TONE[m.tone] : undefined }}>{missing ? '—' : fmtMetric(shown, m.unit)}</span>
        <ArrowUpRight size={14} className="text-ink-3 opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
      </Link>
      <div className="mt-auto flex flex-wrap items-center gap-x-2 gap-y-1 pt-2 text-[11.5px] text-ink-3">
        {avail ? <span className="inline-flex items-center gap-1 font-medium" style={{ color: avail.color }}><span className="h-1.5 w-1.5 rounded-full" style={{ background: avail.color }} aria-hidden />{avail.text}</span>
          : m.tone ? <span className="h-1.5 w-1.5 rounded-full" style={{ background: TONE[m.tone] }} aria-hidden /> : null}
        <span>{m.as_of ? `as of ${fmtAgo(m.as_of)}` : missing ? 'no data collected' : 'collection time not recorded'}</span>
      </div>
      {open && <MetricInfo m={m} id={id} onClose={() => setOpen(false)} />}
    </div>
  )
}
