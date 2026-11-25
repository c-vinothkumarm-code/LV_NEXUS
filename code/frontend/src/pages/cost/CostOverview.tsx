import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArcDonut, ComparisonChart, Segmented, type HeroSeries } from '../../components/hero'
import { Metric, SectionCard } from '../../components/shell'
import { ErrorNote, ExportButton, PageSkeleton, PROVIDER_COLOR, PROVIDER_LABEL, fmtAgo, fmtUsd, fmtUsdShort } from '../../components/ui'
import { useApi } from '../../hooks/useApi'

/** Simplified cost page for all three clouds. Actual and forecast are always shown separately; anything not collected shows
 *  an em dash with the reason, never zero. Advanced slicing stays on /cost/analysis. */
interface Analysis {
  period: { label: string; includes_today: boolean }; collected: boolean
  summary: { actual_usd: number | null; previous_period_usd: number | null; variance_pct: number | null; forecast_month_usd: number | null; forecast_method: string | null
    approved_budget_usd: number | null; remaining_budget_usd: number | null; budget_utilisation_pct: number | null }
  groups: { key: string; label: string; cost_usd: number; providers?: string[] }[]
  daily: Record<string, string | number>[]
  by_service: { service: string; cost_usd: number }[]; by_scope: { provider: string; scope: string; name: string; cost_usd: number }[]
  by_resource_group: { resource_group: string; scope: string; cost_usd: number }[]; by_region: { region: string; cost_usd: number }[]
  top_resources: { resource_id: string; name: string | null; provider: string; scope: string; cost_usd: number }[]
  freshness: Record<string, { last_usage_date?: string; last_collected_at?: string; detail_refreshed_at?: string }>; notes: string[]
}
const PERIODS = [['this_month', 'This month'], ['last_30_days', 'Last 30 days'], ['previous_month', 'Last month'], ['year_to_date', 'Year to date']] as const
type Period = typeof PERIODS[number][0]
const usd = (v: number | null | undefined) => (v === null || v === undefined ? null : fmtUsd(v))

function Bars({ rows, empty }: { rows: { label: string; sub?: string; value: number }[]; empty: string }) {
  if (!rows.length) return <p className="py-8 text-center text-sm text-ink-3">{empty}</p>
  const max = Math.max(...rows.map((r) => r.value), 1)
  return (
    <ul className="space-y-2.5">{rows.map((r, i) => (
      <li key={`${i}-${r.label}`} className="text-sm">
        <div className="flex items-baseline justify-between gap-3"><span className="min-w-0 truncate" title={r.label}>{r.label}{r.sub && <span className="ml-1.5 text-[11px] text-ink-3">{r.sub}</span>}</span>
          <span className="tabular shrink-0 font-medium">{fmtUsd(r.value)}</span></div>
        <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-2"><div className="h-full rounded-full bg-accent" style={{ width: `${(r.value / max) * 100}%` }} /></div>
      </li>))}</ul>
  )
}

export default function CostOverview() {
  const [period, setPeriod] = useState<Period>('this_month')
  const [provider, setProvider] = useState<'all' | 'azure' | 'aws' | 'gcp'>('all')
  const { data, error, reload } = useApi<Analysis>('/cost/analysis', { period, group_by: 'provider', provider: provider === 'all' ? undefined : provider })
  const tone = (pct: number | null) => (pct === null ? undefined : pct > 0 ? 'var(--critical)' : 'var(--good)')
  if (error && !data) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton />
  const s = data.summary
  const series: HeroSeries[] = (['azure', 'aws', 'gcp'] as const).filter((p) => provider === 'all' || p === provider).map((p) => ({ key: p, label: PROVIDER_LABEL[p], color: PROVIDER_COLOR[p] }))
  const fresh = Object.entries(data.freshness).map(([p, f]) => `${PROVIDER_LABEL[p] ?? p}: billing to ${f.last_usage_date ?? '—'}${f.last_collected_at ? `, collected ${fmtAgo(f.last_collected_at)}` : ''}`)
  const rgOrRegion = provider === 'azure' || (provider === 'all' && data.by_resource_group.length)
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><p className="text-[11px] font-semibold uppercase tracking-[.14em] text-accent">FinOps</p>
          <h1 className="mt-1 text-[28px] font-semibold tracking-tight">What we spend, and where</h1>
          <p className="mt-1 text-sm text-ink-3">{data.period.label} · USD · actual billed cost from AWS Cost Explorer, Azure Cost Management and the GCP billing export.{data.period.includes_today ? ' Today is partial.' : ''}</p></div>
        <div className="flex flex-wrap gap-2">
          <Segmented label="Cloud" value={provider} onChange={setProvider} options={[{ value: 'all', label: 'All clouds' }, ...(['azure', 'aws', 'gcp'] as const).map((p) => ({ value: p, label: PROVIDER_LABEL[p] }))]} />
          <Segmented label="Period" value={period} onChange={setPeriod} options={PERIODS.map(([value, label]) => ({ value, label }))} />
        </div>
      </div>

      {!data.collected && <div className="cn-card border-l-4 p-4 text-sm" style={{ borderLeftColor: 'var(--warning)' }}>No billing data has been collected for this selection yet. Figures show “—” until the billing collection succeeds (see System health).</div>}

      <div className="cn-card grid grid-cols-2 gap-5 p-5 lg:grid-cols-4">
        <Metric label="Actual" value={usd(s.actual_usd)} note={s.variance_pct === null ? 'no previous period to compare' : <span style={{ color: tone(s.variance_pct) }}>{s.variance_pct > 0 ? '+' : ''}{s.variance_pct.toFixed(1)}% vs previous period</span>} />
        <Metric label="Previous period" value={usd(s.previous_period_usd)} note="same length, immediately before" />
        <Metric label="Forecast (this month)" value={usd(s.forecast_month_usd)} note={s.forecast_method ? `forecast · ${s.forecast_method}` : 'forecast not available'} />
        <Metric label="Budget" value={usd(s.approved_budget_usd)} note={s.approved_budget_usd === null ? 'no approved budget' : `${usd(s.remaining_budget_usd) ?? '—'} remaining${s.budget_utilisation_pct !== null ? ` · ${s.budget_utilisation_pct.toFixed(0)}% used` : ''}`}
          tone={s.budget_utilisation_pct !== null && s.budget_utilisation_pct > 100 ? 'var(--critical)' : undefined} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)]">
        <SectionCard title="Daily cost" subtitle="Actual cost per day, stacked by cloud">
          <ComparisonChart data={data.daily} x="date" series={series} stacked fmt={fmtUsdShort} xFmt={(v) => String(v).slice(5)} height={260} empty="No daily billing collected for this period." />
        </SectionCard>
        <SectionCard title="By cloud">
          <ArcDonut fmt={fmtUsdShort} centre={usd(s.actual_usd) ?? '—'} centreNote="total" emptyText="No billing collected."
            items={data.groups.map((g) => ({ key: g.key, label: PROVIDER_LABEL[g.key] ?? g.label, value: g.cost_usd, color: PROVIDER_COLOR[g.key] ?? '#8a94a6' }))} />
        </SectionCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <SectionCard title="Top accounts, subscriptions and projects" to="/accounts" toLabel="Cloud accounts">
          <Bars empty="No account-level cost collected." rows={data.by_scope.slice(0, 8).map((x) => ({ label: x.name || x.scope, sub: PROVIDER_LABEL[x.provider], value: x.cost_usd }))} />
        </SectionCard>
        <SectionCard title="Top services">
          <Bars empty="No service cost collected." rows={data.by_service.slice(0, 8).map((x) => ({ label: x.service, value: x.cost_usd }))} />
        </SectionCard>
        <SectionCard title={rgOrRegion ? 'Top resource groups' : 'Top regions'} subtitle="From the detailed cost collection">
          {rgOrRegion ? <Bars empty="Resource-group cost not collected yet." rows={data.by_resource_group.slice(0, 8).map((x) => ({ label: x.resource_group, sub: x.scope, value: x.cost_usd }))} />
            : <Bars empty="Region cost not collected yet." rows={data.by_region.slice(0, 8).map((x) => ({ label: x.region, value: x.cost_usd }))} />}
        </SectionCard>
      </div>

      <SectionCard title="Most expensive resources" subtitle="Where the provider reports cost per resource (Azure always; AWS when resource-level data is enabled; GCP detailed export)"
        to="/cost/analysis" toLabel="Advanced analysis">
        {data.top_resources.length === 0 ? <p className="py-6 text-center text-sm text-ink-3">Resource-level cost not collected for this selection.</p> : <>
          <div className="mb-2 flex justify-end"><ExportButton name="Top resources by cost" head={['Cloud', 'Scope', 'Resource', 'Cost (USD)']}
            rows={data.top_resources.map((r) => [r.provider, r.scope, r.name ?? r.resource_id, r.cost_usd])} /></div>
          <div className="overflow-auto rounded-xl border border-line"><table className="cn-table w-full text-sm"><thead><tr className="border-b border-line text-left text-[11px] uppercase tracking-wide text-ink-3">
            <th className="px-3 py-2">Resource</th><th className="px-3 py-2">Cloud</th><th className="px-3 py-2">Account / subscription / project</th><th className="px-3 py-2 text-right">Cost</th></tr></thead>
            <tbody>{data.top_resources.slice(0, 15).map((r) => <tr key={r.resource_id} className="border-b border-line last:border-0">
              <td className="max-w-[360px] truncate px-3 py-2 font-medium" title={r.resource_id}>{r.name ?? r.resource_id.split('/').pop()}</td><td className="px-3 py-2">{PROVIDER_LABEL[r.provider]}</td>
              <td className="px-3 py-2 text-ink-2">{r.scope}</td><td className="tabular px-3 py-2 text-right">{fmtUsd(r.cost_usd)}</td></tr>)}</tbody></table></div></>}
      </SectionCard>

      <ul className="space-y-0.5 text-[11.5px] text-ink-3">{[...fresh, ...data.notes].map((t) => <li key={t}>{t}</li>)}{' '}
        <li><Link className="text-accent hover:underline" to="/cost/analysis">Open advanced analysis</Link> for billing periods, invoices, financial year, amortised cost and tag grouping.</li></ul>
    </div>
  )
}
