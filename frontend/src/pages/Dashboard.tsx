import { CircleDollarSign, Gauge, PieChart as PieIcon, TrendingUp, Wallet } from 'lucide-react'
import { useState } from 'react'
import { ArcDonut, CARD_ORDER, ComparisonChart, Delta, HeroLayout, KpiCard, Panel, ProviderBadge, ProviderCard, Segmented, TrendArea } from '../components/hero'
import { CollectionNotice, ErrorNote, Freshness, PageHeader, PageSkeleton, PROVIDER_COLOR, PROVIDER_LABEL, PROVIDER_NAME, fmtPct, fmtUsd, fmtUsdShort } from '../components/ui'
import { useCan } from '../auth/AuthContext'
import { useApi } from '../hooks/useApi'
import { useFilters } from '../hooks/useFilters'
import { cumulative, dayOfMonthSeries, monthCompare, monthLabel, monthWindow, pivotByProvider, type DailyRow } from '../lib/cost'
import type { FinOps, Infra, Overview } from '../services/api'

type View = 'compare' | 'cloud' | 'monthly'
export const LOW_CPU_PERCENT = 10

/** Per-provider VM figures from the latest collected samples (no estimates). */
export function vmByProvider(infra: Infra | null) {
  const out: Record<string, { running: number; withCpu: number; avgCpu: number | null; lowCpu: number }> = {}
  for (const p of ['aws', 'azure', 'gcp']) {
    const vms = (infra?.vms ?? []).filter((v) => v.provider === p && v.power_state === 'running')
    const cpu = vms.map((v) => v.cpu_percent).filter((c): c is number => c !== null && c !== undefined)
    out[p] = { running: vms.length, withCpu: cpu.length, avgCpu: cpu.length ? cpu.reduce((a, b) => a + b, 0) / cpu.length : null, lowCpu: cpu.filter((c) => c < LOW_CPU_PERCENT).length }
  }
  return out
}

export default function Dashboard() {
  const { filters: f, refreshKey, refresh } = useFilters()
  const canInfra = useCan('infra:read')
  const w = monthWindow()
  const fin = useApi<FinOps>('/dashboard/finops', { provider: f.provider, scope: f.scope, date_from: w.prevStart, date_to: w.today }, refreshKey)
  const ov = useApi<Overview>('/dashboard/overview', { provider: f.provider, scope: f.scope }, refreshKey)
  const infra = useApi<Infra>(canInfra ? '/dashboard/infrastructure' : null, { provider: f.provider, scope: f.scope }, refreshKey)
  const [view, setView] = useState<View>('compare')

  if (fin.error) return <ErrorNote message={fin.error.message} onRetry={fin.reload} />
  if (!fin.data) return <PageSkeleton tiles={6} />
  const d = fin.data
  const rows = d.daily as DailyRow[]
  const mc = monthCompare(rows)
  const mtd = d.month_to_date
  const providers = (f.provider ? [f.provider] : ['azure', 'aws', 'gcp'])
  const curRows = rows.filter((r) => r.date.startsWith(w.curMonth))
  const spark = (p?: string) => dayOfMonthSeries(rows, p).map((x) => x.current).filter((x): x is number => x !== null)
  const budgetFor = (p: string) => {
    const b = d.budget_status.filter((x) => x.provider === p && x.period_start <= w.today && x.period_end >= w.today)
    const approved = b.reduce((a, x) => a + x.approved, 0), actual = b.reduce((a, x) => a + x.actual, 0)
    return approved > 0 ? { pct: (100 * actual) / approved, approved, actual } : null
  }
  const vm = vmByProvider(infra.data)
  const cum = cumulative(rows)
  const sameDays = mc.lastDay ? `vs days 1–${mc.lastDay} of ${monthLabel(w.prevMonth)}` : 'vs last month'

  const chart = (() => {
    if (view === 'compare') {
      return <ComparisonChart key="c" data={dayOfMonthSeries(rows)} x="day" fmt={fmtUsdShort} xFmt={(v) => `Day ${Number(v)}`}
        series={[{ key: 'current', label: `Current month (${monthLabel(w.curMonth)})`, color: 'var(--compare-current)' }, { key: 'previous', label: `Previous month (${monthLabel(w.prevMonth)})`, color: 'var(--compare-previous)' }]} />
    }
    if (view === 'cloud') {
      return <ComparisonChart key="p" stacked data={pivotByProvider(curRows)} x="date" fmt={fmtUsdShort} xFmt={(v) => v.slice(8)}
        series={providers.map((p) => ({ key: p, label: PROVIDER_NAME[p], color: PROVIDER_COLOR[p] }))} />
    }
    return <ComparisonChart key="m" stacked data={d.monthly} x="month" fmt={fmtUsdShort} xFmt={(v) => monthLabel(v)}
      series={providers.map((p) => ({ key: p, label: PROVIDER_NAME[p], color: PROVIDER_COLOR[p] }))} />
  })()

  return (
    <>
      <PageHeader eyebrow="Cloud cost dashboard" title="Total cloud cost"
        description="Month to date across Microsoft Azure, AWS and Google Cloud, compared with the same days of last month. USD, from collected billing data."
        action={<Freshness at={d.metadata.last_collected_at} label="Billing collected" onRefresh={refresh} />} />
      <CollectionNotice collection={d.collection} what="billing data" />
      <HeroLayout
        kpis={<>
          <KpiCard icon={<Wallet size={15} />} label="Total cost" num={mtd.total} fmt={fmtUsd} delta={mc.total.pct} deltaLabel="vs last month" spark={spark()}
            note={mtd.total === null ? 'No billing data' : undefined} />
          {(['aws', 'azure', 'gcp'] as const).map((p) => (
            <KpiCard key={p} icon={<ProviderBadge provider={p} size={20} />} label={`${PROVIDER_LABEL[p]} cost`} num={f.provider && f.provider !== p ? null : mtd.by_provider[p] ?? null} fmt={fmtUsd}
              delta={mc.by[p]?.pct} deltaLabel="vs last month" note={f.provider && f.provider !== p ? 'Filtered out' : 'Not collected'} spark={spark(p)} to="/finops" />
          ))}
          <KpiCard icon={<TrendingUp size={15} />} label="Month over month" num={mc.total.pct} fmt={(n) => `${n > 0 ? '+' : ''}${n.toFixed(1)}%`}
            note={mc.hasPrevious ? 'Same days compared' : 'No previous month data'} />
          <KpiCard icon={<Gauge size={15} />} label="Budget utilisation" num={ov.data?.budget.utilisation_percent ?? null} fmt={(n) => fmtPct(n)}
            note={ov.data?.budget.approved ? `of ${fmtUsd(ov.data.budget.approved)} approved` : 'No approved budget'} to="/finops" />
        </>}
        main={
          <Panel icon={<CircleDollarSign size={15} />} title="Total cost, $" subtitle={view === 'compare' ? 'Daily cost: current month against previous month' : view === 'cloud' ? `Daily cost by cloud, ${monthLabel(w.curMonth)}` : 'Monthly cost by cloud, last 12 months'}
            action={<Segmented label="View" value={view} onChange={setView} options={[{ value: 'compare', label: 'Daily' }, { value: 'cloud', label: 'By cloud' }, { value: 'monthly', label: 'Monthly' }]} />}
            bodyClass="px-5 pb-4 pt-3 xl:pr-16">{chart}</Panel>
        }
        trend={
          <Panel float icon={<TrendingUp size={15} />} title="Month-to-date cost" subtitle={`Cumulative, ${monthLabel(w.curMonth)}; change vs same day last month`}>
            <TrendArea points={cum.map(({ x, y }) => ({ x, y }))} fmt={fmtUsdShort} xFmt={(x) => `${Number(x)} ${monthLabel(w.curMonth)}`}
              compare={(i) => cum[i]?.prev ?? null} />
          </Panel>
        }
        donut={
          <Panel float icon={<PieIcon size={15} />} title="Hybrid cost comparison" subtitle="Share of month-to-date cost">
            <ArcDonut fmt={fmtUsd} centre={fmtUsd(mtd.total)} centreNote={<Delta pct={mc.total.pct} suffix="vs last month" />}
              items={(['azure', 'aws', 'gcp'] as const).map((p) => ({ key: p, label: `${PROVIDER_LABEL[p]} cost`, value: mtd.by_provider[p] ?? 0, color: PROVIDER_COLOR[p] }))}
              emptyText="No month-to-date billing collected yet." />
          </Panel>
        }
        bottom={CARD_ORDER.filter((p) => !f.provider || p === f.provider).map((p) => {
          const b = budgetFor(p), m = mc.by[p], v = vm[p]
          return (
            <ProviderCard key={p} provider={p} to="/finops"
              value={mtd.by_provider[p] === undefined ? '—' : fmtUsd(mtd.by_provider[p])} valueLabel="Month-to-date cost"
              side={{ value: b ? fmtPct(b.pct, 0) : '—', label: b ? 'Budget used' : 'No budget set' }}
              split={m ? { left: { label: 'This month', value: fmtUsd(m.current) }, right: { label: 'Same days last month', value: fmtUsd(m.previousSame) }, ratio: m.current + m.previousSame ? m.current / (m.current + m.previousSame) : null } : null}
              delta={m?.pct} deltaLabel={sameDays} note={m ? 'No previous-month data to compare' : 'No billing collected for this cloud'}
              extra={canInfra ? <>
                <div className="flex justify-between gap-2"><span className="text-ink-3">Resource utilisation</span><span>{v.avgCpu === null ? 'no CPU samples' : `avg CPU ${v.avgCpu.toFixed(0)}% · ${v.withCpu} VM${v.withCpu === 1 ? '' : 's'}`}</span></div>
                <div className="flex justify-between gap-2" title={`Running VMs under ${LOW_CPU_PERCENT}% CPU at the last sample. Review before acting; savings are not estimated.`}>
                  <span className="text-ink-3">Optimisation candidates</span><span>{v.withCpu ? `${v.lowCpu} low-CPU VM${v.lowCpu === 1 ? '' : 's'}` : 'not available'}</span></div>
              </> : undefined} />
          )
        })}
      />
    </>
  )
}
