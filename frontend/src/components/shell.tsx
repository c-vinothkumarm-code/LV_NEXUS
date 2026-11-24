import { CheckCircle2, CircleAlert, CircleDashed, Clock3 } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { fmtAgo, fmtTime } from './ui'

export interface Freshness { updated_at: string | null; status: 'fresh' | 'stale' | 'never' | 'degraded'; reason: string | null }

const FRESH: Record<Freshness['status'], { label: string; color: string; Icon: typeof Clock3 }> = {
  fresh: { label: 'Up to date', color: 'var(--good)', Icon: CheckCircle2 },
  stale: { label: 'Stale', color: '#c27c00', Icon: Clock3 },
  degraded: { label: 'Last run failed', color: 'var(--critical)', Icon: CircleAlert },
  never: { label: 'Not collected yet', color: 'var(--ink-3)', Icon: CircleDashed },
}

/** "Last updated" chip shown on every section: last successful collection time, plus why it may be old. */
export function FreshnessChip({ f }: { f: Freshness }) {
  const s = FRESH[f.status]
  const title = [f.updated_at ? `Last successful collection ${fmtTime(f.updated_at)}` : 'No successful collection yet', f.reason].filter(Boolean).join(' · ')
  return (
    <span title={title} className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line bg-surface px-2.5 py-1 text-[11px] font-medium text-ink-2">
      <s.Icon size={12} aria-hidden style={{ color: s.color }} />
      {f.updated_at ? `Updated ${fmtAgo(f.updated_at)}` : s.label}
      {f.status !== 'fresh' && f.updated_at && <span style={{ color: s.color }}>· {s.label.toLowerCase()}</span>}
    </span>
  )
}

/** Card with a title, optional "view all" link and the freshness chip; the body always renders (last good data). */
export function SectionCard({ title, subtitle, to, toLabel = 'Open', fresh, children, className = '' }: {
  title: string; subtitle?: string; to?: string; toLabel?: string; fresh?: Freshness; children: ReactNode; className?: string
}) {
  return (
    <section className={`cn-card flex flex-col p-5 ${className}`} aria-label={title}>
      <header className="mb-3">
        <div className="flex items-start justify-between gap-2">
          <h2 className="min-w-0 text-[15px] font-semibold tracking-tight text-ink">{title}</h2>
          {to && <Link to={to} className="shrink-0 text-xs font-semibold text-accent hover:underline">{toLabel} →</Link>}
        </div>
        {(subtitle || fresh) && <div className="mt-1 flex flex-wrap items-center justify-between gap-2">
          {subtitle ? <p className="text-xs text-ink-3">{subtitle}</p> : <span />}{fresh && <FreshnessChip f={fresh} />}</div>}
      </header>
      <div className="min-h-0 flex-1">{children}</div>
    </section>
  )
}

/** Large figure with label and a quiet note; `null` renders as an em dash with the note (never as zero). */
export function Metric({ label, value, note, tone }: { label: string; value: ReactNode; note?: ReactNode; tone?: string }) {
  return (
    <div className="min-w-0">
      <div className="text-[11.5px] font-medium uppercase tracking-wide text-ink-3">{label}</div>
      <div className="tabular mt-1 truncate text-[26px] font-semibold leading-tight tracking-tight" style={{ color: tone }}>{value ?? '—'}</div>
      {note && <div className="mt-0.5 truncate text-[11.5px] text-ink-3">{note}</div>}
    </div>
  )
}
