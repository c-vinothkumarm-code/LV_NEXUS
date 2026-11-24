/**
 * Phase 12 layout kit: the shared "hero" composition used at the top of every module.
 *
 *   KPI cards (left) · large analytics card (centre) · floating trend panel (right)
 *   floating distribution donut (left, lifted) · provider cards (bottom)
 *
 * Every component renders only what it is given. A missing figure is shown as "—" or an explicit
 * "not collected" note; nothing here invents a value.
 */
import { ArrowDownRight, ArrowRight, ArrowUpRight, BarChart3, LineChart as LineIcon, Minus } from 'lucide-react'
import { useId, useMemo, useState, type ReactNode } from 'react'
import { Link, NavLink } from 'react-router-dom'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { prefersReducedMotion, useCountUp } from '../hooks/useMotion'
import { PROVIDER_COLOR, PROVIDER_NAME, fmtInt } from './ui'

const animate = () => !prefersReducedMotion()
const axis = { fontSize: 11, fill: 'var(--text-muted)' }

/* ---- small parts ---------------------------------------------------------------------------------------------- */
export function IconBadge({ children }: { children: ReactNode }) {
  return <span className="cn-icon-badge" aria-hidden>{children}</span>
}

/** Generic provider badge: initials on the provider's series colour. Third-party logos are deliberately not drawn. */
export function ProviderBadge({ provider, size = 30 }: { provider: string; size?: number }) {
  const txt = { azure: 'Az', aws: 'AWS', gcp: 'GCP' }[provider] ?? provider.slice(0, 3).toUpperCase()
  return (
    <span className="inline-grid shrink-0 place-items-center rounded-full font-bold text-white" aria-hidden
      style={{ width: size, height: size, background: `color-mix(in srgb, ${PROVIDER_COLOR[provider] ?? 'var(--neutral-mark)'} 66%, #0b1020)`, fontSize: size * (txt.length > 2 ? 0.3 : 0.38) }}>
      {txt}
    </span>
  )
}

/** Change against a comparison period. `upIsBad` for cost and findings; null renders nothing (no comparison data). */
export function Delta({ pct, upIsBad = true, suffix }: { pct: number | null | undefined; upIsBad?: boolean; suffix?: string }) {
  if (pct === null || pct === undefined || !Number.isFinite(pct)) return null
  const flat = Math.abs(pct) < 0.05
  const up = pct > 0
  const cls = flat ? 'cn-delta-flat' : up === upIsBad ? 'cn-delta-up-bad' : 'cn-delta-down-good'
  const Icon = flat ? Minus : up ? ArrowUpRight : ArrowDownRight
  return (
    <span className="inline-flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs text-ink-3">
      <span className={`cn-delta ${cls}`}><Icon size={11} aria-hidden />{Math.abs(pct).toFixed(Math.abs(pct) >= 10 ? 0 : 1)}%<span className="sr-only">{flat ? ' unchanged' : up ? ' increase' : ' decrease'}</span></span>
      {suffix && <span className="whitespace-nowrap">{suffix}</span>}
    </span>
  )
}

/** Card with the reference header: round icon badge, title, optional right-hand action. */
export function Panel({ icon, title, subtitle, action, children, className = '', bodyClass = 'px-5 pb-5 pt-3', float = false, id }: {
  icon?: ReactNode; title: ReactNode; subtitle?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; bodyClass?: string; float?: boolean; id?: string
}) {
  return (
    <section id={id} className={`cn-card ${float ? 'cn-float cn-float-in' : ''} ${className}`} aria-label={typeof title === 'string' ? title : undefined}>
      <header className="flex flex-wrap items-center justify-between gap-3 px-5 pt-4">
        <div className="flex min-w-0 items-center gap-2.5">
          {icon && <IconBadge>{icon}</IconBadge>}
          <div className="min-w-0">
            <h2 className="cn-h-card text-ink">{title}</h2>
            {subtitle && <p className="text-[11.5px] text-ink-3">{subtitle}</p>}
          </div>
        </div>
        {action}
      </header>
      <div className={bodyClass}>{children}</div>
    </section>
  )
}

/** Tiny inline trend line for a KPI card (pure SVG: cheap to render). */
function Sparkline({ values, color = 'var(--compare-current)' }: { values: number[]; color?: string }) {
  if (values.length < 2) return null
  const max = Math.max(...values), min = Math.min(...values), span = max - min || 1
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * 100},${28 - ((v - min) / span) * 24}`).join(' ')
  return (
    <svg viewBox="0 0 100 30" preserveAspectRatio="none" className="mt-2 h-7 w-full" aria-hidden>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
    </svg>
  )
}

/** KPI card: icon, label, animated value, change chip, optional sparkline. `num === null` shows "—" with its note. */
export function KpiCard({ icon, label, num, fmt = fmtInt, delta, upIsBad = true, deltaLabel = 'vs last period', note, spark, to }: {
  icon: ReactNode; label: string; num: number | null | undefined; fmt?: (n: number) => string; delta?: number | null; upIsBad?: boolean
  deltaLabel?: string; note?: ReactNode; spark?: number[]; to?: string
}) {
  const animated = useCountUp(num ?? null)
  const shown = num === null || num === undefined ? '—' : fmt(animated ?? num)
  const body = (
    <>
      <div className="flex items-center gap-2"><IconBadge>{icon}</IconBadge><span className="text-[12.5px] font-semibold text-ink">{label}</span></div>
      <div className="tabular mt-2.5 text-[26px] font-semibold leading-none tracking-tight text-ink">{shown}</div>
      <div className="mt-2 min-h-[18px]">{delta !== undefined && delta !== null ? <Delta pct={delta} upIsBad={upIsBad} suffix={deltaLabel} /> : note && <span className="text-xs text-ink-3">{note}</span>}</div>
      {spark && <Sparkline values={spark} />}
    </>
  )
  return to
    ? <Link to={to} className="cn-card cn-card-link block px-4 py-3.5" aria-label={`${label}: ${shown}. Open details`}>{body}</Link>
    : <div className="cn-card cn-lift px-4 py-3.5">{body}</div>
}

/* ---- hero layout ------------------------------------------------------------------------------------------------- */
/** KPI column, main chart, trend and donut panels. Panels sit side by side and never overlap; on smaller screens everything stacks. */
export function HeroLayout({ kpis, main, trend, donut, bottom }: { kpis: ReactNode; main: ReactNode; trend?: ReactNode; donut?: ReactNode; bottom?: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-12">
      <div className="cn-stagger grid grid-cols-2 content-start gap-3 sm:grid-cols-3 xl:grid-cols-6 md:col-span-2 2xl:col-span-3 2xl:grid-cols-2">{kpis}</div>
      <div className={`md:col-span-2 ${trend ? '2xl:col-span-6' : '2xl:col-span-9'}`}>{main}</div>
      {trend && <div className="md:col-span-1 2xl:col-span-3">{trend}</div>}
      {donut && <div className="md:col-span-1 2xl:col-span-3">{donut}</div>}
      {bottom && <div className={`cn-stagger grid grid-cols-1 gap-4 md:col-span-2 md:grid-cols-3 ${donut ? '2xl:col-span-9' : '2xl:col-span-12'}`}>{bottom}</div>}
    </div>
  )
}

/* ---- charts ------------------------------------------------------------------------------------------------------- */
export interface HeroSeries { key: string; label: string; color: string }
type Fmt = (n: number) => string

function ChartTooltip({ active, payload, label, series, fmt, labelFmt }: {
  active?: boolean; payload?: { dataKey: string; value: number }[]; label?: string; series: HeroSeries[]; fmt: Fmt; labelFmt?: (l: string) => string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-xl border border-line bg-surface px-3 py-2.5 text-xs" style={{ boxShadow: 'var(--shadow-2)' }}>
      <div className="mb-1.5 font-semibold text-ink">{labelFmt ? labelFmt(String(label)) : label}</div>
      {series.map((s) => {
        const p = payload.find((x) => x.dataKey === s.key)
        if (!p || p.value === null || p.value === undefined) return null
        return (
          <div key={s.key} className="flex items-start gap-2 py-0.5">
            <span className="mt-[3px] h-2.5 w-2.5 rounded-full ring-2 ring-white" style={{ background: s.color }} aria-hidden />
            <div><div className="text-[11px] text-ink-3">{s.label}</div><div className="tabular font-semibold text-ink">{fmt(Number(p.value))}</div></div>
          </div>
        )
      })}
    </div>
  )
}

export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { value: T; label: string; icon?: ReactNode }[]; label: string }) {
  return (
    <div className="cn-seg" role="group" aria-label={label}>
      {options.map((o) => <button key={o.value} type="button" aria-pressed={value === o.value} onClick={() => onChange(o.value)}>{o.icon}{o.label}</button>)}
    </div>
  )
}

export function Legend({ series }: { series: HeroSeries[] }) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-2">
      {series.map((s) => <span key={s.key} className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: s.color }} aria-hidden />{s.label}</span>)}
    </div>
  )
}

/** Large analytics chart with a Columns / Line switch, rounded columns and a hover card. */
export function ComparisonChart({ data, x, series, height = 300, fmt = (n) => n.toLocaleString('en-IN'), xFmt, stacked = false, defaultMode = 'columns', extraControls, empty }: {
  data: Record<string, string | number | null>[]; x: string; series: HeroSeries[]; height?: number; fmt?: Fmt; xFmt?: (v: string) => string
  stacked?: boolean; defaultMode?: 'columns' | 'line'; extraControls?: ReactNode; empty?: ReactNode
}) {
  const [mode, setMode] = useState<'columns' | 'line'>(defaultMode)
  const hasData = data.some((r) => series.some((s) => Number(r[s.key]) > 0))
  const common = { data, margin: { top: 10, right: 6, bottom: 0, left: 0 } }
  const xAxis = <XAxis dataKey={x} tick={axis} axisLine={false} tickLine={false} minTickGap={14} tickFormatter={xFmt} interval={data.length <= 12 ? 0 : 'preserveStartEnd'} />
  const yAxis = <YAxis tick={axis} axisLine={false} tickLine={false} width={54} tickFormatter={fmt} allowDecimals={false} />
  const grid = <CartesianGrid stroke="var(--line)" strokeDasharray="3 5" vertical={false} />
  const tip = <Tooltip cursor={mode === 'columns' ? { fill: 'var(--accent-soft)', radius: 8 } as never : { stroke: 'var(--text-muted)', strokeDasharray: '3 3' }}
    content={(p) => <ChartTooltip {...(p as unknown as object)} series={series} fmt={fmt} labelFmt={xFmt} />} />
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <Legend series={series} />
        <div className="flex flex-wrap items-center gap-2">
          {extraControls}
          <Segmented label="Chart type" value={mode} onChange={setMode}
            options={[{ value: 'columns', label: 'Columns', icon: <BarChart3 size={13} aria-hidden /> }, { value: 'line', label: 'Line', icon: <LineIcon size={13} aria-hidden /> }]} />
        </div>
      </div>
      {!hasData ? (empty ?? <div className="grid place-items-center text-xs text-ink-3" style={{ height }}>No data collected for this period.</div>) : (
        <ResponsiveContainer width="100%" height={height}>
          {mode === 'columns' ? (
            <BarChart {...common} barCategoryGap="22%" barGap={4}>
              {grid}{xAxis}{yAxis}{tip}
              {series.map((s, i) => (
                <Bar key={s.key} dataKey={s.key} name={s.label} fill={s.color} stackId={stacked ? 'a' : undefined} maxBarSize={stacked ? 34 : 18}
                  radius={!stacked || i === series.length - 1 ? [8, 8, 8, 8] : [0, 0, 0, 0]} stroke={stacked ? 'var(--surface-1)' : undefined} strokeWidth={stacked ? 2 : 0}
                  isAnimationActive={animate()} animationDuration={650} />
              ))}
            </BarChart>
          ) : (
            <LineChart {...common}>
              {grid}{xAxis}{yAxis}{tip}
              {series.map((s) => (
                <Line key={s.key} type="monotone" dataKey={s.key} name={s.label} stroke={s.color} strokeWidth={2.2} dot={false} connectNulls={false}
                  activeDot={{ r: 5, stroke: 'var(--surface-1)', strokeWidth: 2 }} isAnimationActive={animate()} animationDuration={650} />
              ))}
            </LineChart>
          )}
        </ResponsiveContainer>
      )}
      {hasData && (
        <details className="mt-1 text-xs text-ink-2">
          <summary className="cursor-pointer select-none text-ink-3">View as table</summary>
          <div className="mt-2 max-h-48 overflow-auto" tabIndex={0} role="region" aria-label="Chart data">
            <table className="tabular w-full text-left">
              <thead><tr className="text-ink-3"><th scope="col" className="py-1 pr-3 font-medium">{x}</th>{series.map((s) => <th key={s.key} scope="col" className="py-1 pr-3 font-medium">{s.label}</th>)}</tr></thead>
              <tbody>{data.map((r, i) => <tr key={i} className="border-t border-line/60"><td className="py-1 pr-3">{xFmt ? xFmt(String(r[x])) : r[x]}</td>{series.map((s) => <td key={s.key} className="py-1 pr-3">{r[s.key] === null || r[s.key] === undefined ? '—' : fmt(Number(r[s.key]))}</td>)}</tr>)}</tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  )
}

/** Open-arc donut with rounded, separated segments, the total in the centre and a legend underneath. */
export function ArcDonut({ items, centre, centreNote, fmt = fmtInt, emptyText = 'No data collected yet.' }: {
  items: { key: string; label: string; value: number; color: string }[]; centre: string; centreNote?: ReactNode; fmt?: Fmt; emptyText?: string
}) {
  const shown = items.filter((i) => i.value > 0)
  const total = shown.reduce((a, b) => a + b.value, 0)
  return (
    <div>
      {total === 0 ? <div className="grid h-[210px] place-items-center text-center text-xs text-ink-3">{emptyText}</div> : (
        <div className="relative h-[210px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={shown} dataKey="value" nameKey="label" startAngle={215} endAngle={-35} innerRadius="74%" outerRadius="100%" paddingAngle={3} cornerRadius={7}
                stroke="none" isAnimationActive={animate()} animationDuration={700}>
                {shown.map((i) => <Cell key={i.key} fill={i.color} />)}
              </Pie>
              <Tooltip content={({ active, payload }) => active && payload?.[0] ? (
                <div className="rounded-xl border border-line bg-surface px-3 py-2 text-xs" style={{ boxShadow: 'var(--shadow-2)' }}>
                  <div className="font-semibold">{String(payload[0].name)}</div>
                  <div className="tabular text-ink-2">{fmt(Number(payload[0].value))} · {((100 * Number(payload[0].value)) / total).toFixed(1)}%</div>
                </div>) : null} />
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
            <div><div className="tabular text-[24px] font-semibold tracking-tight text-ink">{centre}</div>{centreNote && <div className="mt-1 flex justify-center text-xs text-ink-3">{centreNote}</div>}</div>
          </div>
        </div>
      )}
      <ul className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 text-xs">
        {items.map((i) => (
          <li key={i.key} className="flex items-center gap-2 text-ink-2">
            <span className="h-3 w-1 rounded-full" style={{ background: i.color }} aria-hidden />
            <span className="min-w-0 flex-1 truncate">{i.label}</span>
            <span className="tabular font-semibold text-ink">{total ? `${((100 * i.value) / total).toFixed(0)}%` : '—'}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Trend panel: hatched area with a callout for the hovered (default: latest) point and its change against `compareTo`. */
export function TrendArea({ points, fmt = fmtInt, compare, upIsBad = true, height = 210, xFmt }: {
  points: { x: string; y: number }[]; fmt?: Fmt; compare?: (index: number) => number | null; upIsBad?: boolean; height?: number; xFmt?: (x: string) => string
}) {
  const id = `cn-hatch-${useId().replace(/[^a-zA-Z0-9-]/g, '')}`
  const [active, setActive] = useState<number | null>(null)
  const idx = active ?? points.length - 1
  const pt = points[idx]
  const pct = useMemo(() => {
    const base = compare?.(idx)
    return base && pt ? (100 * (pt.y - base)) / base : null
  }, [compare, idx, pt])
  if (points.length < 2) return <div className="grid place-items-center text-xs text-ink-3" style={{ height }}>Not enough data points for a trend yet.</div>
  return (
    <div className="relative">
      <div className="absolute right-0 top-0 z-10 rounded-xl border border-line bg-surface px-3 py-2" style={{ boxShadow: 'var(--shadow-1)' }} aria-live="polite">
        <div className="text-[11px] text-ink-3">{xFmt ? xFmt(pt.x) : pt.x}</div>
        <div className="flex items-center gap-2"><span className="tabular text-[20px] font-semibold tracking-tight">{fmt(pt.y)}</span><Delta pct={pct} upIsBad={upIsBad} /></div>
      </div>
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={points} margin={{ top: 64, right: 4, bottom: 0, left: 0 }}
          onMouseMove={(s) => { const i = Number((s as { activeTooltipIndex?: number | string }).activeTooltipIndex); if (Number.isFinite(i)) setActive(i) }}
          onMouseLeave={() => setActive(null)}>
          <defs>
            <pattern id={id} width="5" height="5" patternUnits="userSpaceOnUse">
              <line x1="2" y1="0" x2="2" y2="5" stroke="var(--compare-current)" strokeWidth="1" opacity=".5" />
            </pattern>
          </defs>
          <YAxis tick={axis} axisLine={false} tickLine={false} width={46} tickFormatter={fmt} />
          <XAxis dataKey="x" hide />
          <Tooltip content={() => null} cursor={{ stroke: 'var(--compare-current)', strokeWidth: 1.5 }} />
          <Area type="monotone" dataKey="y" stroke="var(--compare-current)" strokeWidth={2.2} fill={`url(#${id})`}
            activeDot={{ r: 5, fill: 'var(--surface-1)', stroke: 'var(--compare-current)', strokeWidth: 2.5 }} isAnimationActive={animate()} animationDuration={700} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ---- provider cards ---------------------------------------------------------------------------------------------- */
export function ProviderCard({ provider, value, valueLabel, side, split, delta, upIsBad = true, deltaLabel, to, action = 'View details', note, extra, onAction }: {
  provider: string; value: string; valueLabel: string; side?: { value: string; label: string }
  split?: { left: { label: string; value: string }; right: { label: string; value: string }; ratio: number | null } | null
  delta?: number | null; upIsBad?: boolean; deltaLabel?: string; to: string; action?: string; note?: ReactNode; extra?: ReactNode; onAction?: () => void
}) {
  const ratio = split?.ratio === null || split?.ratio === undefined ? null : Math.max(0, Math.min(1, split.ratio))
  return (
    <section className="cn-card cn-lift flex flex-col p-5" aria-label={PROVIDER_NAME[provider] ?? provider}>
      <header className="flex items-center gap-2.5"><ProviderBadge provider={provider} size={28} /><h3 className="text-[14px] font-semibold">{PROVIDER_NAME[provider] ?? provider}</h3></header>
      <div className="mt-4 flex items-end justify-between gap-3">
        <div className="min-w-0"><div className="tabular truncate text-[26px] font-semibold leading-none tracking-tight">{value}</div><div className="mt-1.5 text-[11.5px] text-ink-3">{valueLabel}</div></div>
        {side && <div className="text-right"><div className="tabular text-[26px] font-semibold leading-none tracking-tight">{side.value}</div><div className="mt-1.5 text-[11.5px] text-ink-3">{side.label}</div></div>}
      </div>
      <div className="mt-4 flex-1 rounded-2xl bg-surface-2 p-3.5">
        {split ? (
          <>
            <div className="flex justify-between text-xs font-semibold"><span className="tabular">{split.left.value}</span><span className="tabular">{split.right.value}</span></div>
            {ratio === null ? <div className="mt-2 h-2.5 rounded-full bg-surface-3" aria-hidden /> : (
              <div className="mt-2 flex h-2.5 gap-[3px]" role="img" aria-label={`${split.left.label} ${split.left.value}, ${split.right.label} ${split.right.value}`}>
                <div className="rounded-full transition-[width] duration-700" style={{ width: `${ratio * 100}%`, background: 'var(--compare-current)' }} />
                <div className="flex-1 rounded-full" style={{ background: 'var(--compare-previous)' }} />
              </div>
            )}
            <div className="mt-1.5 flex justify-between text-[11px] text-ink-3"><span>{split.left.label}</span><span>{split.right.label}</span></div>
          </>
        ) : null}
        <div className={split ? 'mt-2.5' : ''}>{delta !== undefined && delta !== null ? <Delta pct={delta} upIsBad={upIsBad} suffix={deltaLabel} /> : note && <div className="text-xs text-ink-3">{note}</div>}</div>
      </div>
      {extra && <div className="mt-3 space-y-1 text-xs text-ink-2">{extra}</div>}
      {onAction
        ? <button type="button" onClick={onAction} className="cn-btn cn-btn-dark mt-4 h-10 w-full justify-center">{action}<ArrowRight size={14} aria-hidden /></button>
        : <Link to={to} className="cn-btn cn-btn-dark mt-4 h-10 w-full justify-center">{action}<ArrowRight size={14} aria-hidden /></Link>}
    </section>
  )
}

/** The three provider cards in the reference order. */
export const CARD_ORDER = ['azure', 'gcp', 'aws'] as const

/** Secondary navigation inside a module (for example Monitoring: resources and VMs / automation jobs). */
export function SubTabs({ items }: { items: { to: string; label: string }[] }) {
  return (
    <nav aria-label="Section" className="cn-seg max-w-full overflow-x-auto">
      {items.map((i) => (
        <NavLink key={i.to} to={i.to} end className={({ isActive }) => `inline-flex h-8 shrink-0 items-center whitespace-nowrap rounded-full px-4 text-[12.5px] font-medium transition-colors ${isActive ? 'bg-surface text-accent shadow-[0_0_0_1px_color-mix(in_srgb,var(--accent)_45%,transparent)]' : 'text-ink-2 hover:text-ink'}`}>
          {i.label}
        </NavLink>
      ))}
    </nav>
  )
}
export const MONITORING_TABS = [{ to: '/monitoring', label: 'Resources and VMs' }, { to: '/automation', label: 'Automation jobs' }]
