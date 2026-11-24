import { Lightbulb, ReceiptText, Sigma } from 'lucide-react'
import { useState } from 'react'
import { ComparisonChart, Panel, Segmented, SubTabs, type HeroSeries } from '../../components/hero'
import { DataGrid, Drawer, FilterPanel, Pager, Pill, Select, type Col } from '../../components/secops'
import { ErrorNote, ExportButton, PageHeader, PageSkeleton, PROVIDER_COLOR, PROVIDER_LABEL, fmtUsd, fmtUsdShort } from '../../components/ui'
import { useApi } from '../../hooks/useApi'

export const COST_TABS = [{ to: '/cost/overview', label: 'Cost overview' }, { to: '/cost/analysis', label: 'Cost analysis' }, { to: '/cost/billing-periods', label: 'Billing periods' }, { to: '/cost/optimization', label: 'Optimisation' }, { to: '/budgets', label: 'Budgets' }]
interface Explorer {
  period: string; start: string; end: string; collected: boolean; total_usd: number | null; complete_days_usd: number | null; includes_today_partial: boolean
  provisional_records: number; records: number; month_to_date_usd: number | null; previous_month_usd: number | null; year_to_date_usd: number | null
  forecast_month_usd: number | null; forecast_note: string; by_provider: { provider: string; cost_usd: number }[]
  by_scope: { provider: string; scope: string; name: string; environment: string; cost_usd: number }[]; by_service: { service: string; cost_usd: number }[]
  by_environment: { environment: string; cost_usd: number }[]; daily: Record<string, string | number>[]; not_available: Record<string, string>
  definitions: Record<string, string>; calculation: string
}
const usd = (v: number | null | undefined) => (v === null || v === undefined ? 'not collected' : fmtUsd(v))

function Breakdown({ title, rows, onPick }: { title: string; rows: { label: string; value: number; key: string }[]; onPick?: (k: string) => void }) {
  const max = Math.max(1, ...rows.map((r) => r.value))
  return (
    <Panel title={title}>
      <ul className="space-y-1.5 text-xs">{rows.slice(0, 12).map((r) => (
        <li key={r.key}><button className="grid w-full grid-cols-[minmax(0,1fr)_90px] items-center gap-2 text-left hover:opacity-80 disabled:cursor-default" disabled={!onPick} onClick={() => onPick?.(r.key)}>
          <span><span className="block truncate">{r.label}</span><span className="mt-0.5 block h-1.5 rounded-full bg-surface-2"><span className="block h-1.5 rounded-full" style={{ width: `${(100 * r.value) / max}%`, background: 'var(--compare-current)' }} /></span></span>
          <span className="tabular text-right font-semibold">{fmtUsd(r.value)}</span></button></li>))}
        {rows.length === 0 && <li className="text-ink-3">No billing data in this period.</li>}</ul>
    </Panel>
  )
}

/** Unified cost explorer: period selection, drilldown provider → account → service, and the records behind each figure. */
export function CostExplorer() {
  const [period, setPeriod] = useState('monthly')
  const [range, setRange] = useState({ start: '', end: '' })
  const [drill, setDrill] = useState<{ provider?: string; scope?: string; service?: string }>({})
  const [records, setRecords] = useState(false)
  const [page, setPage] = useState(1)
  const q = { period, start: period === 'custom' ? range.start : undefined, end: period === 'custom' ? range.end : undefined, ...drill }
  const { data, error, reload } = useApi<Explorer>(period === 'custom' && (!range.start || !range.end) ? null : '/cost/explorer', q)
  const recs = useApi<{ total: number; items: Record<string, unknown>[] }>(records ? '/cost/records' : null, { ...q, page, size: 100 })
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  const series: HeroSeries[] = ['aws', 'azure', 'gcp'].map((p) => ({ key: p, label: PROVIDER_LABEL[p], color: PROVIDER_COLOR[p] }))
  const crumbs = [['All clouds', {}], drill.provider && [PROVIDER_LABEL[drill.provider], { provider: drill.provider }],
    drill.scope && [data?.by_scope.find((s) => s.scope === drill.scope)?.name ?? drill.scope, { provider: drill.provider, scope: drill.scope }],
    drill.service && [drill.service, drill]].filter(Boolean) as [string, typeof drill][]
  return (
    <>
      <PageHeader eyebrow="FinOps" title="Cost explorer" description="One view of AWS, Azure and Google Cloud spend. Each figure can be traced to the billing records behind it; cost definitions are shown below." />
      <SubTabs items={COST_TABS} />
      <div className="flex flex-wrap items-center gap-2">
        <Segmented label="Period" value={period} onChange={(v) => { setPeriod(v); setPage(1) }} options={[{ value: 'daily', label: 'Last 30 days' }, { value: 'weekly', label: '12 weeks' }, { value: 'monthly', label: 'This month' }, { value: 'quarterly', label: 'Quarter' }, { value: 'yearly', label: 'Year' }, { value: 'custom', label: 'Custom' }]} />
        {period === 'custom' && <><input type="date" className="cn-input" aria-label="Start" value={range.start} onChange={(e) => setRange({ ...range, start: e.target.value })} /><input type="date" className="cn-input" aria-label="End" value={range.end} onChange={(e) => setRange({ ...range, end: e.target.value })} /></>}
        <nav aria-label="Drilldown" className="ml-auto flex flex-wrap items-center gap-1 text-sm">{crumbs.map(([l, d], i) => <span key={i} className="flex items-center gap-1">{i > 0 && <span className="text-ink-3">/</span>}<button className="text-accent hover:underline" onClick={() => setDrill(d)}>{l}</button></span>)}</nav>
      </div>
      {!data ? <PageSkeleton tiles={6} /> : <>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          {[['Selected period', usd(data.total_usd), data.includes_today_partial ? 'includes today (partial)' : `${data.start} to ${data.end}`], ['Complete days only', usd(data.complete_days_usd), 'excludes today'],
            ['Month to date', usd(data.month_to_date_usd), 'actual, incl. provisional'], ['Previous month', usd(data.previous_month_usd), 'actual'], ['Year to date', usd(data.year_to_date_usd), 'actual'],
            ['Forecast this month', usd(data.forecast_month_usd), 'estimate']].map(([l, v, n]) => <div key={l} className="cn-card px-4 py-3"><div className="text-[11.5px] text-ink-3">{l}</div><div className="tabular mt-1 text-[20px] font-semibold">{v}</div><div className="text-[11px] text-ink-3">{n}</div></div>)}
        </div>
        <Panel icon={<Sigma size={15} />} title="Daily expenditure by cloud" subtitle={`${data.records} billing records · ${data.provisional_records} provisional`}
          action={<button className="cn-btn cn-btn-ghost h-8 text-xs" onClick={() => setRecords(true)}><ReceiptText size={13} aria-hidden />Show underlying records</button>}>
          <ComparisonChart data={data.daily} x="date" series={series} stacked fmt={fmtUsdShort} xFmt={(v) => v.slice(5)} empty="No billing data in this period. Spend is unknown, not zero." />
        </Panel>
        <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
          <Breakdown title="By cloud" rows={data.by_provider.map((r) => ({ key: r.provider, label: PROVIDER_LABEL[r.provider], value: r.cost_usd }))} onPick={!drill.provider ? (k) => setDrill({ provider: k }) : undefined} />
          <Breakdown title="By account / subscription / project" rows={data.by_scope.map((r) => ({ key: `${r.provider}|${r.scope}`, label: `${PROVIDER_LABEL[r.provider]} · ${r.name}`, value: r.cost_usd }))} onPick={!drill.scope ? (k) => { const [p, s] = k.split('|'); setDrill({ provider: p, scope: s }) } : undefined} />
          <Breakdown title="By service" rows={data.by_service.map((r) => ({ key: r.service, label: r.service, value: r.cost_usd }))} onPick={!drill.service ? (k) => setDrill({ ...drill, service: k }) : undefined} />
          <Breakdown title="By environment" rows={data.by_environment.map((r) => ({ key: r.environment, label: r.environment, value: r.cost_usd }))} />
        </div>
        <Panel title="How these figures are calculated">
          <p className="text-sm text-ink-2">{data.calculation}</p>
          <ul className="mt-2 space-y-1 text-xs text-ink-2">{Object.entries(data.definitions).map(([k, v]) => <li key={k}><b>{k === 'usd' ? 'Currency' : k === 'not_available' ? 'Not included' : PROVIDER_LABEL[k]}:</b> {v}</li>)}
            {Object.values(data.not_available).map((v) => <li key={v}>{v}</li>)}<li>{data.forecast_note}</li></ul>
        </Panel>
      </>}
      {records && (
        <Drawer title="Billing records" subtitle="The records summed for the current selection" onClose={() => setRecords(false)} width={980}>
          {recs.data ? <>
            <ExportButton name="Billing records" head={['Usage date', 'Cloud', 'Scope', 'Service', 'Cost (original)', 'Currency', 'Cost (USD)', 'Rate', 'Final', 'Collected']} rows={recs.data.items.map((r) => [r.usage_date, r.provider, r.scope, r.service, r.cost_original, r.currency_original, r.cost_usd, r.conversion_rate, r.is_final ? 'yes' : 'no', r.collected_at] as (string | number | null)[])} />
            <table className="mt-2 w-full text-left text-xs"><thead><tr className="border-b border-line text-ink-3">{['Date', 'Cloud', 'Scope', 'Service', 'Original', 'USD', 'Status'].map((h) => <th key={h} className="px-1 py-1">{h}</th>)}</tr></thead>
              <tbody>{recs.data.items.map((r, i) => <tr key={i} className="border-b border-line/60"><td className="px-1 py-1">{String(r.usage_date)}</td><td className="px-1">{String(r.provider)}</td><td className="px-1">{String(r.scope)}</td><td className="px-1">{String(r.service)}</td>
                <td className="tabular px-1">{Number(r.cost_original).toFixed(2)} {String(r.currency_original)}</td><td className="tabular px-1">{r.cost_usd === null ? '—' : Number(r.cost_usd).toFixed(2)}</td><td className="px-1">{r.is_final ? 'final' : 'provisional'}</td></tr>)}</tbody></table>
            <Pager page={page} pageSize={100} total={recs.data.total} onPage={setPage} /></> : <div className="text-sm text-ink-3">Loading…</div>}
        </Drawer>
      )}
    </>
  )
}

interface Opp { type: string; title: string; provider: string | null; scope: string | null; resource: string | null; evidence: string; confidence: string; estimated_savings_usd: number | null; savings_note: string; recommended_action: string }

export function CostOptimization() {
  const [type, setType] = useState('')
  const { data, error, reload } = useApi<{ items: Opp[]; not_detected: string[]; note: string }>('/cost/optimization')
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton tiles={0} />
  const rows = data.items.filter((i) => !type || i.type === type).map((i, n) => ({ ...i, id: n }))
  const cols: Col<Opp & { id: number }>[] = [
    { key: 't', label: 'Opportunity', render: (o) => <div className="max-w-sm"><div className="font-medium">{o.title}</div><div className="text-[11px] text-ink-3">{o.type.replace(/_/g, ' ')}</div></div> },
    { key: 's', label: 'Cloud / scope', render: (o) => (o.provider ? `${PROVIDER_LABEL[o.provider]} · ${o.scope}` : '—') },
    { key: 'e', label: 'Evidence', render: (o) => <span className="text-xs">{o.evidence}</span> },
    { key: 'c', label: 'Confidence', render: (o) => <Pill value={o.confidence === 'High' ? 'APPROVED' : 'PENDING'} text={o.confidence} /> },
    { key: 'v', label: 'Estimated saving', render: (o) => (o.estimated_savings_usd === null ? <span className="text-xs text-ink-3">{o.savings_note}</span> : fmtUsd(o.estimated_savings_usd)) },
    { key: 'a', label: 'Recommended action', render: (o) => <span className="text-xs">{o.recommended_action}</span> },
  ]
  return (
    <>
      <PageHeader eyebrow="FinOps" title="Optimisation opportunities" description={data.note} />
      <SubTabs items={COST_TABS} />
      <Panel icon={<Lightbulb size={15} />} title={`Opportunities (${rows.length})`}
        action={<ExportButton name="Cost optimization" head={['Type', 'Title', 'Cloud', 'Scope', 'Resource', 'Evidence', 'Confidence', 'Saving', 'Action']} rows={rows.map((o) => [o.type, o.title, o.provider, o.scope, o.resource, o.evidence, o.confidence, o.estimated_savings_usd ?? o.savings_note, o.recommended_action])} />}>
        <FilterPanel><Select label="Type" value={type} onChange={setType} options={[...new Set(data.items.map((i) => i.type))].map((t) => ({ value: t, label: t.replace(/_/g, ' ') }))} /></FilterPanel>
        <DataGrid label="Optimisation opportunities" cols={cols} rows={rows} empty="No opportunities detected in the collected data." />
        <ul className="mt-3 list-disc pl-5 text-xs text-ink-3">{data.not_detected.map((x) => <li key={x}>{x}</li>)}</ul>
      </Panel>
    </>
  )
}
