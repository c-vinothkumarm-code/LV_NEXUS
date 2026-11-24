import { AlertTriangle, ArrowUpRight, CheckCircle2, CircleDashed, CircleSlash, Clock, Download, HelpCircle, Info, OctagonAlert, RefreshCw, XCircle } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useCountUp } from '../hooks/useMotion'
import type { Collection } from '../services/api'
import { BRAND } from '../theme/brand'

export const PROVIDER_LABEL: Record<string, string> = { aws: 'AWS', gcp: 'GCP', azure: 'Azure' }
export const PROVIDER_NAME: Record<string, string> = { aws: 'Amazon Web Services', gcp: 'Google Cloud', azure: 'Microsoft Azure' }
export const PROVIDER_COLOR: Record<string, string> = { azure: 'var(--series-azure)', aws: 'var(--series-aws)', gcp: 'var(--series-gcp)' }
export const SCOPE_NOUN: Record<string, string> = { aws: 'accounts', gcp: 'projects', azure: 'subscriptions' }
export const PROVIDERS = ['aws', 'azure', 'gcp'] as const

/* ---- formatting ------------------------------------------------------------------------------------- */
export const fmtInt = (n: number | null | undefined) => (n === null || n === undefined ? '—' : Math.round(n).toLocaleString('en-IN'))
export const fmtUsd = (n: number | null | undefined) =>
  n === null || n === undefined ? '—' : n.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: Math.abs(n) >= 1000 ? 0 : 2 })
export const fmtUsdShort = (n: number) => (Math.abs(n) >= 1e6 ? `$${(n / 1e6).toFixed(1)}M` : Math.abs(n) >= 1e3 ? `$${(n / 1e3).toFixed(1)}k` : `$${n.toFixed(0)}`)
export const fmtPct = (n: number | null | undefined, digits = 1) => (n === null || n === undefined ? '—' : `${n.toFixed(digits)}%`)
export function fmtTime(iso: string | null | undefined) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false }) + ' IST'
}
export function fmtAgo(iso: string | null | undefined) {
  if (!iso) return 'never'
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return `${Math.floor(s / 86400)} d ago`
}
export const fmtBytes = (n: number | null | undefined) => {
  if (n === null || n === undefined) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0, v = n
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`
}

/* ---- layout primitives -------------------------------------------------------------------------------- */
export function Card({ title, subtitle, action, children, className = '', bodyClass = 'px-5 pb-5 pt-3', id, icon }: {
  title?: ReactNode; subtitle?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; id?: string; icon?: ReactNode
}) {
  return (
    <section id={id} className={`cn-card ${className}`} aria-label={typeof title === 'string' ? title : undefined}>
      {(title || action) && (
        <header className="flex flex-wrap items-center justify-between gap-3 px-5 pt-4">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="cn-icon-badge" aria-hidden>{icon ?? <span className="h-2 w-2 rounded-full bg-current" />}</span>
            <div className="min-w-0">
              {title && <h2 className="cn-h-card">{title}</h2>}
              {subtitle && <p className="text-[11.5px] text-ink-3">{subtitle}</p>}
            </div>
          </div>
          {action}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  )
}

export function PageHeader({ title, description, action, eyebrow }: { title: string; description: string; action?: ReactNode; eyebrow?: string }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div>
        {eyebrow && <div className="mb-1 text-[11px] font-semibold uppercase tracking-[.14em] text-accent">{eyebrow}</div>}
        <h1 className="cn-h-page">{title}</h1>
        <p className="mt-0.5 max-w-3xl text-sm text-ink-2">{description}</p>
      </div>
      {action}
    </div>
  )
}

/** "Data as of …" plus a refresh button. Shows when the figures on screen were collected, not when the page loaded. */
export function Freshness({ at, label = 'Data collected', onRefresh, state }: { at: string | null | undefined; label?: string; onRefresh?: () => void; state?: string | null }) {
  const stale = at ? (Date.now() - new Date(at).getTime()) / 60000 > 60 : true
  return (
    <div className="flex items-center gap-2 text-xs text-ink-3">
      <span className={`inline-block h-2 w-2 rounded-full ${at ? (stale ? 'bg-warning' : 'bg-good cn-live') : 'bg-neutral-400'}`} aria-hidden />
      <span>{label} <span className="font-medium text-ink-2">{at ? fmtTime(at) : 'never'}</span>{at && ` · ${fmtAgo(at)}`}{state && state !== 'success' ? ` · last run ${state}` : ''}</span>
      {onRefresh && <button className="cn-btn cn-btn-ghost h-7 px-2" onClick={onRefresh} aria-label="Refresh data"><RefreshCw size={13} /></button>}
    </div>
  )
}

/* ---- KPI tile ------------------------------------------------------------------------------------------- */
type Tone = 'neutral' | 'good' | 'warning' | 'serious' | 'critical'
const TONE_ICON: Record<Tone, ReactNode> = {
  neutral: null,
  good: <CheckCircle2 size={14} className="text-good" aria-hidden />,
  warning: <AlertTriangle size={14} className="text-warning" aria-hidden />,
  serious: <AlertTriangle size={14} className="text-serious" aria-hidden />,
  critical: <OctagonAlert size={14} className="text-critical" aria-hidden />,
}

/** A headline figure. `null` renders "—" with its note: never a zero that looks like a real reading. `num` animates the value. */
export function StatTile({ label, value, note, tone = 'neutral', to, num, fmt, icon }: {
  label: string; value?: string | null; note?: ReactNode; tone?: Tone; to?: string; num?: number | null; fmt?: (n: number) => string; icon?: ReactNode
}) {
  const animated = useCountUp(num)
  const shown = num !== undefined ? (animated === null ? null : (fmt ?? fmtInt)(animated)) : value
  const body = (
    <>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-[12.5px] font-semibold text-ink">{TONE_ICON[tone] ? <span className="cn-icon-badge">{TONE_ICON[tone]}</span> : <span className="cn-icon-badge" aria-hidden><span className="h-2 w-2 rounded-full bg-current" /></span>}{label}</div>
        {icon ? <span className="text-ink-3">{icon}</span> : to && <ArrowUpRight size={14} className="text-ink-3 opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />}
      </div>
      <div className="tabular mt-2.5 text-[26px] font-semibold leading-none tracking-tight">{shown ?? '—'}</div>
      {note && <div className="mt-1.5 text-xs text-ink-3">{note}</div>}
    </>
  )
  return to
    ? <Link to={to} className="cn-card cn-card-link group block px-4 py-4" aria-label={`${label}: ${shown ?? 'no data'}. Open details`}>{body}</Link>
    : <div className="cn-card cn-lift px-4 py-4">{body}</div>
}

/* ---- status --------------------------------------------------------------------------------------------- */
const STATUS_STYLE: Record<string, { icon: ReactNode; cls: string }> = {
  good: { icon: <CheckCircle2 size={13} />, cls: 'text-good' },
  warning: { icon: <AlertTriangle size={13} />, cls: 'text-warning' },
  serious: { icon: <AlertTriangle size={13} />, cls: 'text-serious' },
  critical: { icon: <XCircle size={13} />, cls: 'text-critical' },
  muted: { icon: <CircleSlash size={13} />, cls: 'text-ink-3' },
  pending: { icon: <Clock size={13} />, cls: 'text-ink-3' },
  unknown: { icon: <HelpCircle size={13} />, cls: 'text-ink-3' },
  info: { icon: <CircleDashed size={13} />, cls: 'text-accent' },
}
const STATUS_TONE: Record<string, keyof typeof STATUS_STYLE> = {
  'Fully Onboarded': 'good', 'Partially Onboarded': 'warning', 'Pending Configuration': 'warning', 'Pending Access': 'serious',
  'Access Failed': 'critical', Discovered: 'info', 'Monitoring Disabled': 'muted', Inactive: 'muted',
  success: 'good', partial: 'warning', failed: 'critical', running: 'info', skipped_overlap: 'muted',
  pass: 'good', fail: 'critical', unknown: 'unknown', not_applicable: 'muted',
  pending_approval: 'pending', approved: 'info', rejected: 'muted', resolved: 'good',
  Critical: 'critical', High: 'serious', Medium: 'warning', Low: 'info', Informational: 'muted',
  healthy: 'good', critical: 'critical', queued: 'pending', sent: 'good', warning: 'warning', stopped: 'muted',
  exceeded: 'critical', high: 'serious', info: 'info', within: 'good', recorded: 'muted', open: 'serious',
  degraded: 'warning', failing: 'critical', not_connected: 'muted', pending: 'pending', active: 'good', stale: 'critical', never_run: 'unknown',
  'Pending Review': 'pending', 'Under Investigation': 'info', 'Confirmed Legitimate': 'good', 'Confirmed Suspicious': 'critical',
  'Remediation Required': 'serious', Escalated: 'critical', Closed: 'muted',
}

/** Status is always icon + label; colour never carries the meaning alone. */
export function StatusBadge({ status, label }: { status: string; label?: string }) {
  const s = STATUS_STYLE[STATUS_TONE[status] ?? 'unknown']
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap text-xs font-medium text-ink">
      <span className={s.cls} aria-hidden>{s.icon}</span>{label ?? status.replace(/_/g, ' ')}
    </span>
  )
}

export function ProviderTag({ provider, full = false }: { provider: string; full?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium">
      <span className="h-2 w-2 rounded-sm" style={{ background: PROVIDER_COLOR[provider] ?? 'var(--neutral-mark)' }} aria-hidden />
      {(full ? PROVIDER_NAME : PROVIDER_LABEL)[provider] ?? provider}
    </span>
  )
}

export function Meter({ value, max = 100, tone, label }: { value: number | null; max?: number; tone?: string; label?: string }) {
  if (value === null || value === undefined) return <span className="text-xs text-ink-3">no data</span>
  const pct = Math.max(0, Math.min(100, (100 * value) / max))
  const color = tone ?? (pct >= 100 ? 'var(--critical)' : pct >= 90 ? 'var(--serious)' : pct >= 80 ? 'var(--warning)' : 'var(--accent)')
  return (
    <div className="flex min-w-24 items-center gap-2" aria-label={label}>
      <div className="cn-bar-track flex-1"><div className="cn-bar-fill" style={{ width: `${pct}%`, background: color }} /></div>
      <span className="tabular w-11 text-right text-xs text-ink-2">{value.toFixed(value >= 100 ? 0 : 1)}%</span>
    </div>
  )
}

/* ---- states ----------------------------------------------------------------------------------------------- */
export function EmptyState({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-1.5 rounded-[var(--radius-md)] border border-dashed border-line px-4 py-8 text-center">
      <span className="text-ink-3">{icon ?? <Info size={18} />}</span>
      <div className="text-sm font-medium">{title}</div>
      {children && <div className="max-w-md text-xs text-ink-2">{children}</div>}
    </div>
  )
}

/** Shown on pages whose collector has never succeeded, so empty figures are not read as "all healthy". */
export function CollectionNotice({ collection, what }: { collection: Collection; phase?: number; what: string }) {
  if (collection.state === 'collected') return null
  const failed = collection.state === 'failed'
  return (
    <div className="flex items-start gap-2.5 rounded-[var(--radius-md)] border px-3.5 py-2.5 text-sm"
      style={{ borderColor: failed ? 'var(--critical)' : 'var(--line)', background: failed ? 'color-mix(in srgb, var(--critical) 7%, var(--surface-1))' : 'var(--surface-1)' }}>
      {failed ? <XCircle size={16} className="mt-0.5 shrink-0 text-critical" /> : <Info size={16} className="mt-0.5 shrink-0 text-accent" />}
      <div>
        <span className="font-medium">{failed ? `Collection of ${what} has not succeeded yet.` : `No ${what} has been collected yet.`}</span>{' '}
        <span className="text-ink-2">
          {failed ? `The last run at ${fmtTime(collection.last_run_at)} failed; Monitoring › Automation shows the reason.` : `Run the ${collection.job} job from Monitoring › Automation once a cloud is connected.`}{' '}
          Figures below are empty, not healthy.
        </span>
      </div>
    </div>
  )
}

export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-center gap-2 rounded-[var(--radius-md)] border px-3.5 py-2.5 text-sm"
      style={{ borderColor: 'var(--critical)', background: 'color-mix(in srgb, var(--critical) 6%, var(--surface-1))' }}>
      <XCircle size={15} className="shrink-0 text-critical" /><span className="flex-1">{message}</span>
      {onRetry && <button className="cn-btn cn-btn-ghost h-7" onClick={onRetry}>Try again</button>}
    </div>
  )
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`cn-skeleton ${className}`} aria-hidden />
}

export function PageSkeleton({ tiles = 4 }: { tiles?: number }) {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Loading">
      <Skeleton className="h-7 w-64" /><Skeleton className="h-4 w-96 max-w-full" />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{Array.from({ length: tiles }, (_, i) => <Skeleton key={i} className="h-24" />)}</div>
      <div className="grid gap-4 lg:grid-cols-3"><Skeleton className="h-64 lg:col-span-2" /><Skeleton className="h-64" /></div>
    </div>
  )
}

/* ---- tables + export ---------------------------------------------------------------------------------------- */
export function Table({ head, rows, empty, dense = false, maxHeight, label }: { head: string[]; rows: ReactNode[][]; empty: string; dense?: boolean; maxHeight?: number; label?: string }) {
  if (rows.length === 0) return <EmptyState title={empty} />
  // A scrollable region must be reachable from the keyboard (WCAG 2.1.1), so it takes focus and a name.
  return (
    <div className="overflow-auto" style={maxHeight ? { maxHeight } : undefined} tabIndex={0} role="region" aria-label={label ?? `Table: ${head.join(', ')}`}>
      <table className="cn-table w-full text-left text-sm">
        <thead>
          <tr className="border-b border-line text-[11px] uppercase tracking-wide text-ink-3">{head.map((h) => <th key={h} scope="col" className="px-2.5 py-2 font-semibold">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-b border-line/70 last:border-0">
              {r.map((c, j) => <td key={j} className={`px-2.5 align-top ${dense ? 'py-1.5' : 'py-2.5'}`}>{c}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** CSV download built from data already on screen. The file carries the product name and the export time. */
export function ExportButton({ name, head, rows }: { name: string; head: string[]; rows: (string | number | null | undefined)[][] }) {
  const download = () => {
    const esc = (v: unknown) => {
      const s = v === null || v === undefined ? '' : String(v)
      const safe = /^[=+\-@]/.test(s) ? `'${s}` : s  // stop spreadsheet formula injection from log-derived text
      return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe
    }
    const meta = [`# ${BRAND.fullName} - ${name}`, `# Exported ${new Date().toISOString()} (UTC)`]
    const csv = [...meta, head.map(esc).join(','), ...rows.map((r) => r.map(esc).join(','))].join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
    const a = Object.assign(document.createElement('a'), { href: url, download: `cloudnexus-${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${new Date().toISOString().slice(0, 10)}.csv` })
    a.click()
    URL.revokeObjectURL(url)
  }
  return <button className="cn-btn cn-btn-ghost h-7 px-2.5 text-xs" onClick={download} disabled={!rows.length} aria-label={`Export ${name} as CSV`}><Download size={13} />Export</button>
}
