import { Activity, CalendarDays, CircleDollarSign, Gauge, Info, Layers, Lightbulb, PieChart as PieIcon, TrendingUp, Wallet } from 'lucide-react'
import { useState } from 'react'
import { useCan } from '../auth/AuthContext'
import { DataTableToggle, StackedBars } from '../components/charts'
import { ArcDonut, CARD_ORDER, ComparisonChart, HeroLayout, KpiCard, Panel, ProviderCard, TrendArea } from '../components/hero'
import { monthLabel } from '../lib/cost'
import { LOW_CPU_PERCENT, vmByProvider } from './Dashboard'
import { useToast } from '../components/Toast'
import {
  Card, CollectionNotice, EmptyState, ErrorNote, ExportButton, Freshness, Meter, PageHeader, PageSkeleton, PROVIDER_COLOR, PROVIDER_LABEL, PROVIDER_NAME, PROVIDERS,
  ProviderTag, StatusBadge, Table, fmtInt, fmtPct, fmtTime, fmtUsd, fmtUsdShort,
} from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useFilters } from '../hooks/useFilters'
import { api, type FinOps, type Infra } from '../services/api'

const money = (n: number | null, cur: string) => (n === null ? '—' : cur === 'USD' ? fmtUsd(n) : `₹${n.toLocaleString('en-IN', { maximumFractionDigits: 0 })}`)

function BudgetForm({ onSaved }: { onSaved: () => void }) {
  const today = new Date()
  const first = new Date(Date.UTC(today.getFullYear(), today.getMonth(), 1)).toISOString().slice(0, 10)
  const last = new Date(Date.UTC(today.getFullYear(), today.getMonth() + 1, 0)).toISOString().slice(0, 10)
  const [b, setB] = useState({ provider: 'azure', scope_external_id: '', amount: '', currency: 'USD', period_start: first, period_end: last })
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const save = async () => {
    setBusy(true)
    try {
      await api.post('/finops/budgets', { ...b, scope_external_id: b.scope_external_id || '*', amount: Number(b.amount) })
      toast({ kind: 'success', title: 'Budget saved', text: `${PROVIDER_LABEL[b.provider]} ${b.scope_external_id || 'all scopes'}: ${b.currency} ${Number(b.amount).toLocaleString()}` })
      setB({ ...b, amount: '' }); onSaved()
    } catch (e) { toast({ kind: 'error', title: 'Budget not saved', text: e instanceof Error ? e.message : 'Unknown error' }) } finally { setBusy(false) }
  }
  return (
    <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-line pt-3 text-xs text-ink-2">
      <span className="font-semibold text-ink">Approved budget</span>
      <select className="cn-input" value={b.provider} onChange={(e) => setB({ ...b, provider: e.target.value })} aria-label="Cloud">{PROVIDERS.map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p]}</option>)}</select>
      <input className="cn-input w-48" placeholder="Scope ID (blank = whole cloud)" value={b.scope_external_id} onChange={(e) => setB({ ...b, scope_external_id: e.target.value })} aria-label="Account, project or subscription ID" />
      <input className="cn-input w-28" type="number" min="0" placeholder="Amount" value={b.amount} onChange={(e) => setB({ ...b, amount: e.target.value })} aria-label="Amount" />
      <select className="cn-input" value={b.currency} onChange={(e) => setB({ ...b, currency: e.target.value })} aria-label="Currency"><option>USD</option><option>INR</option></select>
      <input className="cn-input" type="date" value={b.period_start} onChange={(e) => setB({ ...b, period_start: e.target.value })} aria-label="Period start" />
      <input className="cn-input" type="date" value={b.period_end} onChange={(e) => setB({ ...b, period_end: e.target.value })} aria-label="Period end" />
      <button onClick={save} disabled={!b.amount || busy} className="cn-btn cn-btn-primary">{busy && <span className="cn-spinner" aria-hidden />}Save budget</button>
    </div>
  )
}

export default function FinOpsPage() {
  const { filters: f, refreshKey, refresh } = useFilters()
  const [bump, setBump] = useState(0)
  const { data, error, loading, reload } = useApi<FinOps>('/dashboard/finops', { provider: f.provider, scope: f.scope, date_from: f.dateFrom, date_to: f.dateTo }, refreshKey + bump)
  const canManage = useCan('finops:manage')
  const canInfra = useCan('infra:read')
  const infra = useApi<Infra>(canInfra ? '/dashboard/infrastructure' : null, { provider: f.provider, scope: f.scope }, refreshKey)
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return loading ? <PageSkeleton tiles={6} /> : null
  const mtd = data.month_to_date, md = data.metadata, pm = data.previous_month, w = data.weekly
  const days = [...new Set(data.daily.map((d) => d.date))]
  const present = PROVIDERS.filter((p) => data.daily.some((d) => d.provider === p))
  const series = days.map((date) => {
    const row: Record<string, string | number> = { date }
    for (const d of data.daily.filter((x) => x.date === date)) row[d.provider] = d.cost_usd
    return row
  })
  const monthly: Record<string, string | number>[] = data.monthly.map((m) => ({ ...m, month: String(m.month).slice(2) }))
  const monthlyProviders = PROVIDERS.filter((p) => data.monthly.some((m) => m[p] !== undefined))
  const rangeTotal = Object.values(data.by_provider_range).reduce((a, b) => a + b, 0)
  const atRisk = data.budget_status.filter((b) => b.level && b.level !== 'info').length
  const today = new Date().toISOString().slice(0, 10)
  const monthTotals = data.monthly.map((m) => ({ x: String(m.month), y: Math.round(PROVIDERS.reduce((a2, p) => a2 + Number(m[p] ?? 0), 0) * 100) / 100 }))
  const curMonth = today.slice(0, 7)
  const complete = data.monthly.filter((m) => String(m.month) < curMonth)
  const monthlyDelta = (p: string) => {
    const [prev, last] = complete.slice(-2)
    if (!prev || !last || !Number(prev[p])) return null
    return { month: String(last.month), prev: String(prev.month), pct: (100 * (Number(last[p] ?? 0) - Number(prev[p]))) / Number(prev[p]) }
  }
  const vm = vmByProvider(infra.data)
  const lowVms = (infra.data?.vms ?? []).filter((x) => x.power_state === 'running' && x.cpu_percent !== null && x.cpu_percent < LOW_CPU_PERCENT)
  return (
    <>
      <PageHeader eyebrow="Cloud cost intelligence" title="FinOps"
        description="Cost by cloud, account, subscription and service from provider billing data. Figures stay labelled provisional until the provider finalises the month; nothing here is an invoice."
        action={<Freshness at={md.last_collected_at} label="Billing collected" state={data.collection.last_status} onRefresh={refresh} />} />
      <CollectionNotice collection={data.collection} what="billing data" />

      <HeroLayout
        kpis={<>
          <KpiCard icon={<Wallet size={15} />} label="Spend in range" num={data.daily.length ? rangeTotal : null} fmt={fmtUsd} note={`${data.range.from} to ${data.range.to}`} />
          <KpiCard icon={<CircleDollarSign size={15} />} label="Period to date" num={mtd.total} fmt={fmtUsd} note={mtd.total === null ? 'Not collected' : mtd.is_final ? 'Final' : 'Provisional'} />
          <KpiCard icon={<TrendingUp size={15} />} label="Forecast, month" num={data.forecast_total} fmt={fmtUsd} note={data.forecast_total === null ? 'Needs one complete day' : 'Run-rate estimate'} />
          <KpiCard icon={<CalendarDays size={15} />} label={`Last month (${pm.month})`} num={pm.total_actual || null} fmt={fmtUsd} delta={pm.mom_variation_percent} deltaLabel="vs month before"
            note="No earlier month to compare" />
          <KpiCard icon={<Activity size={15} />} label="Week on week" num={w.variation_percent} fmt={(n) => `${n > 0 ? '+' : ''}${n.toFixed(1)}%`} note={`${fmtUsd(w.current_week)} vs ${fmtUsd(w.previous_week)}`} />
          <KpiCard icon={<Gauge size={15} />} label="Budgets at risk" num={data.budgets ? atRisk : null} note={data.budgets ? `of ${fmtInt(data.budgets)} budget(s), at warning or above` : 'No approved budgets yet'} />
        </>}
        main={
          <Panel icon={<CircleDollarSign size={15} />} title="Daily expenditure, $" subtitle={`By cloud, ${data.range.from} to ${data.range.to}`} bodyClass="px-5 pb-4 pt-3 xl:pr-16">
            <ComparisonChart stacked data={series} x="date" fmt={fmtUsdShort} xFmt={(d) => d.slice(5)}
              series={(present.length ? present : [...PROVIDERS]).map((p) => ({ key: p, label: PROVIDER_NAME[p], color: PROVIDER_COLOR[p] }))}
              empty={<EmptyState title="No billing records in this range" />} />
          </Panel>
        }
        trend={
          <Panel float icon={<TrendingUp size={15} />} title="Monthly cost trend" subtitle="All clouds; change vs previous month (current month partial)">
            <TrendArea points={monthTotals} fmt={fmtUsdShort} xFmt={(x) => monthLabel(x)} compare={(i) => (i > 0 ? monthTotals[i - 1].y : null)} />
          </Panel>
        }
        donut={
          <Panel float icon={<PieIcon size={15} />} title="Cost distribution" subtitle="Share of spend in the selected range">
            <ArcDonut fmt={fmtUsd} centre={data.daily.length ? fmtUsd(rangeTotal) : '—'} centreNote="in range" emptyText="No billing records in this range."
              items={(['azure', 'aws', 'gcp'] as const).map((p) => ({ key: p, label: `${PROVIDER_LABEL[p]} cost`, value: data.by_provider_range[p] ?? 0, color: PROVIDER_COLOR[p] }))} />
          </Panel>
        }
        bottom={CARD_ORDER.filter((p) => !f.provider || p === f.provider).map((p) => {
          const v = data.by_provider_range[p]
          const bud = data.budget_status.filter((x) => x.provider === p && x.currency === 'USD' && x.period_start <= today && x.period_end >= today)
          const approved = bud.reduce((a2, x) => a2 + x.approved, 0), actual = bud.reduce((a2, x) => a2 + x.actual, 0)
          const mm = monthlyDelta(p)
          const c = vm[p]
          return (
            <ProviderCard key={p} provider={p} to="/dashboard" action="Open cost dashboard"
              value={v === undefined ? '—' : fmtUsd(v)} valueLabel="Spend in range"
              side={{ value: approved ? fmtPct((100 * actual) / approved, 0) : '—', label: approved ? 'Budget used' : 'No USD budget' }}
              split={approved ? { left: { label: 'Actual', value: fmtUsd(actual) }, right: { label: 'Approved budget', value: fmtUsd(approved) }, ratio: actual / approved } : null}
              delta={mm?.pct} deltaLabel={mm ? `${monthLabel(mm.month)} vs ${monthLabel(mm.prev)}` : undefined} note={md.periods[p] ?? 'No billing records'}
              extra={canInfra ? <div className="flex justify-between gap-2"><span className="text-ink-3">Optimisation candidates</span><span>{c.withCpu ? `${c.lowCpu} low-CPU VM${c.lowCpu === 1 ? '' : 's'} (<${LOW_CPU_PERCENT}%)` : 'no CPU samples'}</span></div> : undefined} />
          )
        })}
      />

      <div className="grid gap-4 xl:grid-cols-3">
      <Card icon={<CalendarDays size={15} />} className="xl:col-span-2" title="Monthly expenditure by cloud" subtitle="Last 12 months, USD. The current month is partial.">
        {monthly.length === 0 ? <EmptyState title="No monthly data" /> : (
          <><StackedBars data={monthly} category="month" stacked={false} valueFormat={fmtUsdShort} height={260} series={monthlyProviders.map((p) => ({ key: p, label: PROVIDER_LABEL[p], color: PROVIDER_COLOR[p] }))} />
            <DataTableToggle columns={['Month', ...monthlyProviders.map((p) => PROVIDER_LABEL[p])]} rows={data.monthly.map((m) => [m.month, ...monthlyProviders.map((p) => fmtUsd(Number(m[p] ?? 0)))])} /></>
        )}
        </Card>

        <Card icon={<Info size={15} />} title="Currency and reporting periods">
          <dl className="space-y-2.5 text-sm">
            <div><dt className="text-xs text-ink-3">Reporting currency</dt><dd>{md.reporting_currency}; original amounts kept per record ({Object.entries(md.original_currencies).map(([c, n]) => `${c}: ${fmtInt(n)}`).join(', ') || 'none yet'})</dd></div>
            <div><dt className="text-xs text-ink-3">USD/INR rate</dt><dd>{md.fx_usd_inr_rate ? `${md.fx_usd_inr_rate}, stored with each record and its conversion time` : 'Not configured: INR amounts are left empty, not guessed'}</dd></div>
            <div><dt className="text-xs text-ink-3">Billing periods</dt><dd>AWS and GCP: calendar month. Azure: each subscription's own billing period{md.azure_period_starts.length ? ` (${md.azure_period_starts.length} with a reported start date)` : ''}.</dd></div>
            <div><dt className="text-xs text-ink-3">Data status</dt><dd>{fmtInt(md.provisional_records)} of {fmtInt(md.total_records)} records provisional</dd></div>
            <div><dt className="text-xs text-ink-3">Last collected</dt><dd>{fmtTime(md.last_collected_at)}</dd></div>
          </dl>
        </Card>
      </div>

      <Card icon={<CircleDollarSign size={15} />} title="Budget versus actual" subtitle="Levels: 70% information, 80% warning, 90% high warning, 100% exceeded (configurable per budget)"
        action={<ExportButton name="Budget versus actual" head={['Cloud', 'Scope', 'Service', 'Currency', 'Period start', 'Period end', 'Approved', 'Actual', 'Utilisation %', 'Remaining', 'Forecast USD', 'Level']}
          rows={data.budget_status.map((b) => [b.provider, b.scope, b.service, b.currency, b.period_start, b.period_end, b.approved, b.actual, b.utilisation_percent, b.remaining, b.forecast, b.level_label])} />}>
        <Table empty="No approved budgets recorded for the current period" head={['Cloud', 'Scope', 'Approved', 'Actual', 'Utilisation', 'Remaining', 'Forecast', 'Level']} rows={data.budget_status.map((b) => [
          <ProviderTag provider={b.provider} />, <div className="text-xs"><code className="break-all">{b.scope === '*' ? 'All' : b.scope}</code>{b.service !== '*' && <div className="text-ink-3">{b.service}</div>}</div>,
          <span className="tabular">{money(b.approved, b.currency)}</span>, <span className="tabular">{money(b.actual, b.currency)}</span>,
          <Meter value={b.utilisation_percent} label="Budget utilisation" />, <span className="tabular">{money(b.remaining, b.currency)}</span>,
          <span className="tabular">{b.forecast === null ? '—' : fmtUsd(b.forecast)}</span>, <StatusBadge status={b.level ?? 'within'} label={b.level_label} />,
        ])} />
        {canManage && <BudgetForm onSaved={() => setBump((x) => x + 1)} />}
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card icon={<CircleDollarSign size={15} />} title="Cost anomalies" subtitle="Latest complete day well above the scope's own 14-day pattern (3 standard deviations and at least $10)">
          <Table empty="No abnormal cost increases detected" head={['Cloud', 'Scope', 'Date', 'Cost', 'Usual', 'Increase']} rows={data.anomalies.map((a) => [
            <ProviderTag provider={a.provider} />, <code className="text-xs">{a.scope}</code>, a.date, <span className="tabular font-semibold">{fmtUsd(a.cost_usd)}</span>,
            <span className="tabular">{fmtUsd(a.baseline_mean_usd)}</span>, <span className="tabular inline-flex items-center gap-1 font-semibold"><span className="h-2 w-2 rounded-sm bg-critical" aria-hidden />{a.increase_percent === null ? '—' : `+${a.increase_percent}%`}</span>])} />
        </Card>
        <Card icon={<CircleDollarSign size={15} />} title="Top cost-increasing services" subtitle="This week compared with last week">
          <Table empty="No service increased this week" head={['Service', 'Increase', '']} rows={w.top_increasing_services.map((r) => [r.service, <span className="tabular">+{fmtUsd(r.increase_usd)}</span>, r.new ? <span className="cn-chip">New this week</span> : null])} />
        </Card>
        <Card icon={<CircleDollarSign size={15} />} title="Service-level expenditure" subtitle="Top 10 in range"
          action={<ExportButton name="Cost by service" head={['Service', 'Cost USD']} rows={data.by_service.map((r) => [r.name, r.cost_usd])} />}>
          <Table empty="No billing records" head={['Service', 'Cost']} rows={data.by_service.map((r) => [r.name, <span className="tabular">{fmtUsd(r.cost_usd)}</span>])} />
        </Card>
        <Card icon={<CircleDollarSign size={15} />} title="Account, project and subscription expenditure" subtitle="Top 10 in range"
          action={<ExportButton name="Cost by scope" head={['Scope', 'Cost USD']} rows={data.by_scope.map((r) => [r.name, r.cost_usd])} />}>
          <Table empty="No billing records" head={['Scope', 'Cost']} rows={data.by_scope.map((r) => [<code className="text-xs">{r.name}</code>, <span className="tabular">{fmtUsd(r.cost_usd)}</span>])} />
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card icon={<Layers size={15} />} title="Resource-group expenditure" subtitle="Azure resource groups, AWS cost-allocation tags, GCP labels">
          <EmptyState title="Not collected">Billing is collected at service and account / subscription level. Resource-group cost needs an extra grouping in each billing query and a database change, which have not been approved, so no figures are shown.</EmptyState>
        </Card>
        <Card icon={<Lightbulb size={15} />} title="Cost optimisation recommendations" subtitle={`Running VMs below ${LOW_CPU_PERCENT}% CPU at the last collected sample. Review over a longer period before resizing; savings are not estimated.`}>
          {!canInfra ? <EmptyState title="Requires infrastructure access" /> : lowVms.length === 0
            ? <EmptyState title={infra.data ? 'No low-utilisation VMs at the last sample' : 'Loading…'}>{infra.data && 'Provider rightsizing advice (Azure Advisor, AWS Compute Optimizer, GCP Recommender) is not collected yet.'}</EmptyState>
            : <Table label="Optimisation candidates" maxHeight={320} empty="None" head={['Cloud', 'VM', 'Size', 'Region', 'CPU']}
                rows={lowVms.map((x) => [<ProviderTag provider={x.provider} />, <span className="font-medium">{x.name ?? '—'}</span>, <span className="text-xs">{x.instance_type ?? '—'}</span>, <span className="text-xs">{x.region ?? '—'}</span>, <Meter value={x.cpu_percent} label="CPU" />])} />}
        </Card>
      </div>
      <p className="text-center text-[11px] text-ink-3">Generated {fmtTime(data.generated_at)}.</p>
    </>
  )
}
