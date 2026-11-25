import { BarChart3, Layers, TrendingUp } from 'lucide-react'
import { useState } from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ArcDonut, ComparisonChart, Panel, Segmented, SubTabs, type HeroSeries } from '../../components/hero'
import { ErrorNote, ExportButton, PageHeader, PageSkeleton, PROVIDER_COLOR, PROVIDER_LABEL, fmtAgo, fmtUsd, fmtUsdShort } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { COST_TABS } from './Cost'

interface Analysis {
  period: { key: string; start: string; end: string; label: string; includes_today: boolean }; collected: boolean; cost_type: string
  summary: { actual_usd: number | null; previous_period_usd: number | null; variance_usd: number | null; variance_pct: number | null; month_to_date_usd: number | null
    forecast_month_usd: number | null; forecast_method: string | null; approved_budget_usd: number | null; remaining_budget_usd: number | null; budget_utilisation_pct: number | null
    daily_average_usd: number | null }
  group_by: string; groups: { key: string; label: string; cost_usd: number; providers?: string[] }[]; group_coverage: Record<string, string>
  daily: Record<string, string | number>[]; actual_vs_forecast: { date: string; actual: number | null; forecast: number | null }[]
  by_service: { service: string; cost_usd: number }[]; by_region: { region: string; cost_usd: number }[]; by_scope: { provider: string; scope: string; name: string; cost_usd: number }[]
  by_resource_group: { resource_group: string; scope: string; cost_usd: number }[]; top_resources: { resource_id: string; name: string | null; provider: string; scope: string; cost_usd: number }[]
  top_increasing_services: { service: string; current: number; previous: number; increase: number }[]; month_over_month: Record<string, string | number>[]
  provider_budgets: { provider: string; scope: string; name: string; amount: number; currency: string; current_spend: number | null; forecast_spend: number | null; time_grain: string | null }[]
  freshness: Record<string, { last_usage_date?: string; last_collected_at?: string; detail_refreshed_at?: string }>; notes: string[]
}
const PERIODS = [['this_month', 'This month'], ['current_billing_period', 'Current billing period'], ['last_7_days', 'Last 7 days'], ['last_30_days', 'Last 30 days'],
  ['previous_month', 'Previous month'], ['last_invoice', 'Last invoice'], ['last_3_invoices', 'Last 3 invoices'], ['last_12_invoices', 'Last 12 invoices'],
  ['year_to_date', 'Year to date'], ['financial_year', 'Financial year'], ['custom_financial_period', 'Custom financial year'], ['custom', 'Custom range']]
const GROUPS = [['service', 'Service'], ['provider', 'Cloud'], ['scope', 'Account / subscription / project'], ['resource_group', 'Resource group'], ['resource', 'Resource'],
  ['resource_type', 'Resource type'], ['region', 'Region'], ['sku', 'SKU'], ['usage_type', 'Usage type'], ['environment', 'Environment tag'], ['cost_center', 'Cost centre tag'], ['business_entity', 'Business entity tag']]
const PALETTE = ['#2a6fdb', '#0aa38c', '#e0a100', '#7a5af5', '#d9534f', '#3aa0d8', '#8a94a6', '#c2185b', '#5b8c00', '#ff7a45']
const usd = (v: number | null | undefined) => (v === null || v === undefined ? '—' : fmtUsd(v))

export default function CostAnalysis() {
  const [period, setPeriod] = useState('this_month')
  const [range, setRange] = useState({ start: '', end: '', fy: String(new Date().getMonth() >= 3 ? new Date().getFullYear() : new Date().getFullYear() - 1) })
  const [filters, setFilters] = useState<{ provider?: string; scope?: string; service?: string; region?: string; resource_group?: string }>({})
  const [groupBy, setGroupBy] = useState('service')
  const [costType, setCostType] = useState('actual')
  const needs = period === 'custom' && (!range.start || !range.end)
  const { data, error, reload } = useApi<Analysis>(needs ? null : '/cost/analysis', { period, group_by: groupBy, cost_type: costType, ...filters,
    start: period === 'custom' ? range.start : undefined, end: period === 'custom' ? range.end : undefined, fy: period.includes('financial') ? range.fy : undefined })
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  const series: HeroSeries[] = ['aws', 'azure', 'gcp'].map((p) => ({ key: p, label: PROVIDER_LABEL[p], color: PROVIDER_COLOR[p] }))
  const drill = (k: string) => {
    const map: Record<string, string> = { service: 'service', provider: 'provider', scope: 'scope', region: 'region', resource_group: 'resource_group' }
    if (map[groupBy]) setFilters({ ...filters, [map[groupBy]]: k })
    if (groupBy === 'provider') setGroupBy('scope')
    else if (groupBy === 'scope') setGroupBy('service')
    else if (groupBy === 'service' || groupBy === 'region') setGroupBy('resource_group')
    else if (groupBy === 'resource_group') setGroupBy('resource')
  }
  const s = data?.summary
  const tiles: [string, string, string][] = s ? [
    ['Actual cost', usd(s.actual_usd), data!.period.includes_today ? 'includes today (partial)' : `${data!.period.start} to ${data!.period.end}`],
    ['Previous period', usd(s.previous_period_usd), s.variance_pct === null ? 'same length, before the selection' : `${s.variance_pct > 0 ? '+' : ''}${s.variance_pct}% (${usd(s.variance_usd)})`],
    ['Month to date', usd(s.month_to_date_usd), 'actual, incl. provisional'],
    ['Forecast (month end)', usd(s.forecast_month_usd), s.forecast_method ? `estimate: ${s.forecast_method}` : 'no forecast collected'],
    ['Approved budget (month)', usd(s.approved_budget_usd), s.approved_budget_usd === null ? 'no active budget for this selection' : 'LV NEXUS budget register'],
    ['Remaining budget', usd(s.remaining_budget_usd), s.budget_utilisation_pct === null ? '—' : `${s.budget_utilisation_pct}% used`],
    ['Daily average', usd(s.daily_average_usd), 'over the selected days'],
  ] : []
  const filterChips = Object.entries(filters).filter(([, v]) => v)
  return (
    <>
      <PageHeader eyebrow="FinOps" title="Cost analysis" description="Actual and amortized cost by billing period with grouping and drill-down to resources. Forecasts are estimates shown beside actual cost, never added to it. Every figure states its source and freshness." />
      <SubTabs items={COST_TABS} />
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-ink-3">Billing period<select className="cn-input mt-1 block" value={period} onChange={(e) => setPeriod(e.target.value)}>{PERIODS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        {period === 'custom' && <><label className="text-xs text-ink-3">From<input type="date" className="cn-input mt-1 block" value={range.start} onChange={(e) => setRange({ ...range, start: e.target.value })} /></label>
          <label className="text-xs text-ink-3">To<input type="date" className="cn-input mt-1 block" value={range.end} onChange={(e) => setRange({ ...range, end: e.target.value })} /></label></>}
        {period.includes('financial') && <label className="text-xs text-ink-3">Financial year starting<input type="number" min={2015} max={2100} className="cn-input mt-1 block w-28" value={range.fy} onChange={(e) => setRange({ ...range, fy: e.target.value })} /></label>}
        <label className="text-xs text-ink-3">Group by<select className="cn-input mt-1 block" value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>{GROUPS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        <label className="text-xs text-ink-3">Cloud<select className="cn-input mt-1 block" value={filters.provider ?? ''} onChange={(e) => setFilters({ ...filters, provider: e.target.value || undefined })}><option value="">All clouds</option>{['aws', 'azure', 'gcp'].map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p]}</option>)}</select></label>
        <Segmented label="Cost type" value={costType} onChange={setCostType} options={[{ value: 'actual', label: 'Actual' }, { value: 'amortized', label: 'Amortized' }]} />
        <div className="ml-auto flex flex-wrap gap-1">{filterChips.map(([k, v]) => <button key={k} className="cn-btn cn-btn-ghost h-7 text-xs" onClick={() => setFilters({ ...filters, [k]: undefined })}>{k.replace('_', ' ')}: {v} ✕</button>)}</div>
      </div>
      {needs ? <p className="text-sm text-ink-3">Choose a start and end date.</p> : !data ? <PageSkeleton tiles={7} /> : <>
        <p className="text-xs text-ink-3">{data.period.label}: {data.period.start} to {data.period.end}{costType === 'amortized' ? ' · amortized cost comes from the detailed collection (Azure AmortizedCost, AWS AmortizedCost); totals stay actual' : ''}</p>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">{tiles.map(([l, v, n]) => <div key={l} className="cn-card px-4 py-3"><div className="text-[11.5px] text-ink-3">{l}</div><div className="tabular mt-1 text-[19px] font-semibold">{v}</div><div className="text-[11px] text-ink-3">{n}</div></div>)}</div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          <Panel icon={<TrendingUp size={15} />} title="Accumulated cost: actual vs forecast (this month)" subtitle="Solid = actual to date · shaded = forecast to month end (estimate)">
            {data.actual_vs_forecast.length === 0 ? <p className="py-10 text-center text-sm text-ink-3">No forecast or month-to-date data yet.</p> :
              <div className="h-[260px]"><ResponsiveContainer><AreaChart data={data.actual_vs_forecast}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" /><XAxis dataKey="date" tickFormatter={(v: string) => v.slice(8)} fontSize={11} /><YAxis tickFormatter={fmtUsdShort} fontSize={11} width={60} />
                <Tooltip formatter={(v) => fmtUsd(Number(v))} />
                <Area type="monotone" dataKey="actual" name="Actual" stroke="var(--series-azure)" fill="var(--series-azure)" fillOpacity={0.35} connectNulls={false} />
                <Area type="monotone" dataKey="forecast" name="Forecast (estimate)" stroke="var(--ink-3)" strokeDasharray="5 4" fill="var(--ink-3)" fillOpacity={0.12} connectNulls={false} />
              </AreaChart></ResponsiveContainer></div>}
          </Panel>
          <Panel title="Budget utilisation" subtitle="Approved budgets (register) and provider budget alerts are separate">
            {s?.approved_budget_usd ? <div><div className="h-3 rounded-full bg-surface-2"><div className="h-3 rounded-full" style={{ width: `${Math.min(100, s.budget_utilisation_pct ?? 0)}%`, background: (s.budget_utilisation_pct ?? 0) >= 100 ? 'var(--critical)' : (s.budget_utilisation_pct ?? 0) >= 80 ? 'var(--high,#e0a100)' : 'var(--series-gcp)' }} /></div>
              <p className="mt-1 text-xs text-ink-3">{s.budget_utilisation_pct}% of {usd(s.approved_budget_usd)} used (month to date)</p></div> : <p className="text-sm text-ink-3">No approved budget matches this selection.</p>}
            <ul className="mt-3 space-y-1 text-xs">{data.provider_budgets.map((b) => <li key={`${b.provider}${b.scope}${b.name}`}><b>{PROVIDER_LABEL[b.provider]}</b> {b.name}: {b.amount.toLocaleString()} {b.currency} / {b.time_grain ?? 'period'} · spend {b.current_spend ?? '—'} · forecast {b.forecast_spend ?? '—'} <span className="text-ink-3">(provider alert)</span></li>)}</ul>
          </Panel>
        </div>
        <Panel icon={<BarChart3 size={15} />} title="Daily cost" subtitle="By cloud">
          <ComparisonChart data={data.daily} x="date" series={series} stacked fmt={fmtUsdShort} xFmt={(v) => v.slice(5)} empty="No billing data in this period. Spend is unknown, not zero." />
        </Panel>
        <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
          <Panel title="By service"><ArcDonut fmt={fmtUsdShort} centre={usd(data.summary.actual_usd)} items={data.by_service.slice(0, 8).map((x, i) => ({ key: x.service, label: x.service, value: x.cost_usd, color: PALETTE[i % PALETTE.length] }))} /></Panel>
          <Panel title="By region" subtitle="From the detailed collection"><ArcDonut fmt={fmtUsdShort} centre="Regions" emptyText="Region cost not collected yet (cost_detail_refresh)." items={data.by_region.slice(0, 8).map((x, i) => ({ key: x.region, label: x.region, value: x.cost_usd, color: PALETTE[i % PALETTE.length] }))} /></Panel>
          <Panel title="Accounts / subscriptions / projects"><ul className="space-y-1 text-sm">{data.by_scope.slice(0, 12).map((x) => <li key={x.scope}><button className="flex w-full justify-between hover:underline" onClick={() => { setFilters({ ...filters, provider: x.provider, scope: x.scope }); setGroupBy('service') }}><span className="truncate">{PROVIDER_LABEL[x.provider]} · {x.name}</span><span className="tabular">{fmtUsd(x.cost_usd)}</span></button></li>)}
            {data.by_scope.length === 0 && <li className="text-ink-3">No billing data.</li>}</ul></Panel>
        </div>
        <Panel icon={<Layers size={15} />} title={`Grouped by ${GROUPS.find((g) => g[0] === groupBy)?.[1].toLowerCase()} (${data.groups.length})`}
          subtitle={Object.entries(data.group_coverage).map(([p, v]) => `${PROVIDER_LABEL[p]}: ${v}`).join(' · ')}
          action={<ExportButton name={`Cost by ${groupBy}`} head={['Group', 'Label', 'Cost (USD)', 'Clouds']} rows={data.groups.map((g) => [g.key, g.label, g.cost_usd, (g.providers ?? []).join(' ')])} />}>
          <table className="w-full text-left text-sm"><thead><tr className="border-b border-line text-xs text-ink-3"><th className="py-1">Group</th><th>Cost (USD)</th><th className="w-1/3">Share</th></tr></thead>
            <tbody>{data.groups.slice(0, 100).map((g) => { const total = data.groups.reduce((a, b) => a + b.cost_usd, 0) || 1; return (
              <tr key={g.key} className="border-b border-line/60"><td className="max-w-[460px] truncate py-1"><button className="text-left hover:underline" title={g.key} onClick={() => drill(g.key)}>{g.label}</button></td>
                <td className="tabular">{fmtUsd(g.cost_usd)}</td><td><div className="h-1.5 rounded-full bg-surface-2"><div className="h-1.5 rounded-full" style={{ width: `${(100 * g.cost_usd) / total}%`, background: 'var(--compare-current)' }} /></div></td></tr>) })}</tbody></table>
          {data.groups.length === 0 && <p className="py-4 text-sm text-ink-3">Nothing collected for this grouping in the selected period.</p>}
        </Panel>
        <div className="grid gap-4 lg:grid-cols-3">
          <Panel title="Top 10 expensive resources">{data.top_resources.length ? <ul className="space-y-1 text-sm">{data.top_resources.map((r) => <li key={r.resource_id} className="flex justify-between gap-2"><span className="truncate" title={r.resource_id}>{PROVIDER_LABEL[r.provider]} · {r.name ?? r.resource_id}</span><span className="tabular">{fmtUsd(r.cost_usd)}</span></li>)}</ul>
            : <p className="text-sm text-ink-3">Resource-level cost not collected (Azure by default; AWS needs Cost Explorer resource-level data; GCP needs the detailed export).</p>}</Panel>
          <Panel title="Resource groups">{data.by_resource_group.length ? <ul className="space-y-1 text-sm">{data.by_resource_group.slice(0, 10).map((r) => <li key={`${r.scope}${r.resource_group}`} className="flex justify-between"><button className="truncate hover:underline" onClick={() => { setFilters({ ...filters, resource_group: r.resource_group }); setGroupBy('resource') }}>{r.resource_group}</button><span className="tabular">{fmtUsd(r.cost_usd)}</span></li>)}</ul> : <p className="text-sm text-ink-3">Not collected yet.</p>}</Panel>
          <Panel title="Top cost-increasing services" subtitle="Month to date vs same days last month">{data.top_increasing_services.length ? <ul className="space-y-1 text-sm">{data.top_increasing_services.map((x) => <li key={x.service} className="flex justify-between gap-2"><span className="truncate">{x.service}</span><span className="tabular" style={{ color: 'var(--critical)' }}>+{fmtUsd(x.increase)}</span></li>)}</ul> : <p className="text-sm text-ink-3">No increases.</p>}</Panel>
        </div>
        <Panel title="Month over month" subtitle="Actual cost per calendar month by cloud">
          <ComparisonChart data={data.month_over_month} x="month" series={series} stacked fmt={fmtUsdShort} empty="No history yet." />
        </Panel>
        <Panel title="Data freshness and definitions">
          <ul className="text-xs text-ink-2">{Object.entries(data.freshness).map(([p, f]) => <li key={p}><b>{PROVIDER_LABEL[p]}</b>: last usage day {f.last_usage_date ?? '—'} · collected {fmtAgo(f.last_collected_at ?? null)} · detail refreshed {fmtAgo(f.detail_refreshed_at ?? null)}</li>)}
            {data.notes.map((n) => <li key={n}>{n}</li>)}</ul>
        </Panel>
      </>}
    </>
  )
}
