import { CalendarRange } from 'lucide-react'
import { useState } from 'react'
import { Panel, SubTabs } from '../../components/hero'
import { ErrorNote, ExportButton, PageHeader, PageSkeleton, fmtUsd } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { COST_TABS } from './Cost'

interface Period {
  name: string; start: string; end: string; status: 'current' | 'closed'; days_elapsed: number; days_total: number
  cost_original: number | null; currency: string | null; cost_usd: number | null; cost_inr: number | null
  total_source: 'provider_query' | 'daily_records' | null; is_final: boolean; invoice_ids: string[]; collected_at: string | null
}
interface Sub { scope: string; name: string; onboarding_status: string; source: string | null; note: string | null; periods: Period[]; gap: string | null }
interface Resp { as_of: string; today: string; subscriptions: Sub[]; definitions: Record<string, string> }

const fmtDate = (d: string) => new Date(`${d}T00:00:00`).toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' })
const money = (p: Period) => {
  if (p.cost_usd !== null) return fmtUsd(p.cost_usd)
  if (p.cost_original !== null && p.currency) return `${p.cost_original.toLocaleString(undefined, { maximumFractionDigits: 2 })} ${p.currency}`
  return null
}

function PeriodRow({ p }: { p: Period }) {
  const value = money(p)
  const pct = Math.min(100, Math.round((100 * p.days_elapsed) / p.days_total))
  return (
    <tr className="border-t border-line">
      <td className="px-3 py-2 text-sm">
        <div className="font-medium">{fmtDate(p.start)} – {fmtDate(p.end)}</div>
        <div className="text-[11px] text-ink-3">{p.name}{p.invoice_ids.length ? ` · invoice ${p.invoice_ids.join(', ')}` : ''}</div>
      </td>
      <td className="px-3 py-2 text-xs">
        {p.status === 'current'
          ? <><span className="rounded-full bg-accent/10 px-2 py-0.5 font-medium text-accent">Current</span><div className="mt-1 h-1.5 w-28 rounded-full bg-surface-2"><div className="h-1.5 rounded-full bg-accent" style={{ width: `${pct}%` }} /></div><div className="mt-0.5 text-ink-3">day {p.days_elapsed} of {p.days_total}</div></>
          : <span className={`rounded-full px-2 py-0.5 font-medium ${p.is_final ? 'bg-surface-2 text-ink-2' : 'bg-warning/10 text-warning'}`}>{p.is_final ? 'Closed · final' : 'Closed · provisional'}</span>}
      </td>
      <td className="tabular px-3 py-2 text-right text-sm font-semibold">{value ?? <span className="font-normal text-ink-3">not collected</span>}
        {p.cost_usd !== null && p.currency && p.currency !== 'USD' && p.cost_original !== null && <div className="text-[11px] font-normal text-ink-3">{p.cost_original.toLocaleString(undefined, { maximumFractionDigits: 2 })} {p.currency}</div>}
      </td>
      <td className="px-3 py-2 text-[11px] text-ink-3">{p.total_source === 'provider_query' ? 'Azure Cost Management total' : p.total_source === 'daily_records' ? 'Sum of daily records (to date)' : '—'}</td>
    </tr>
  )
}

/** Each Azure subscription's own billing cycle (e.g. 5th to 4th) with the cost of the current and recent periods. */
export default function BillingPeriods() {
  const [q, setQ] = useState('')
  const { data, error, reload } = useApi<Resp>('/cost/billing-periods')
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  const subs = (data?.subscriptions ?? []).filter((s) => !q || s.name.toLowerCase().includes(q.toLowerCase()))
  const withData = subs.filter((s) => s.periods.length)
  const without = subs.filter((s) => !s.periods.length)
  const currentTotal = withData.reduce((t, s) => t + (s.periods.find((p) => p.status === 'current')?.cost_usd ?? 0), 0)
  return (
    <>
      <PageHeader eyebrow="FinOps" title="Billing periods" description="Cost per Azure subscription for its own billing cycle, as Azure bills it. Pay-As-You-Go subscriptions do not bill by calendar month." />
      <SubTabs items={COST_TABS} />
      {!data ? <PageSkeleton tiles={3} /> : <>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {[['Subscriptions with billing periods', `${withData.length} of ${subs.length}`, 'collected from Azure'], ['Current periods, to date', fmtUsd(currentTotal), 'sum of subscriptions with data (provisional)'],
            ['Not collected', String(without.length), without.length ? 'reason shown below' : 'all subscriptions covered']].map(([l, v, n]) =>
            <div key={l} className="cn-card px-4 py-3"><div className="text-[11.5px] text-ink-3">{l}</div><div className="tabular mt-1 text-[20px] font-semibold">{v}</div><div className="text-[11px] text-ink-3">{n}</div></div>)}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input className="cn-input w-72" placeholder="Filter subscriptions by name" aria-label="Filter subscriptions" value={q} onChange={(e) => setQ(e.target.value)} />
          <span className="ml-auto" />
          <ExportButton name="billing-periods" head={['Subscription', 'Subscription ID', 'Period', 'Start', 'End', 'Status', 'Final', 'Cost USD', 'Cost (billing currency)', 'Currency', 'Source']}
            rows={withData.flatMap((s) => s.periods.map((p) => [s.name, s.scope, p.name, p.start, p.end, p.status, p.is_final ? 'yes' : 'no', p.cost_usd, p.cost_original, p.currency, p.total_source]))} />
        </div>
        {withData.map((s) => (
          <Panel key={s.scope} icon={<CalendarRange size={15} />} title={s.name} subtitle={`${s.scope}${s.source === 'calendar_month' ? ' · calendar months' : ' · billing cycle from Azure'}`}>
            {s.note && <p className="mb-2 text-xs text-ink-3">{s.note}</p>}
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead><tr className="text-[11px] uppercase tracking-wide text-ink-3"><th className="px-3 py-1.5">Billing period</th><th className="px-3 py-1.5">Status</th><th className="px-3 py-1.5 text-right">Cost</th><th className="px-3 py-1.5">Source</th></tr></thead>
                <tbody>{s.periods.map((p) => <PeriodRow key={p.name} p={p} />)}</tbody>
              </table>
            </div>
          </Panel>
        ))}
        {without.length > 0 && (
          <Panel title={`Subscriptions without billing periods (${without.length})`} subtitle="Shown so nothing is silently missing; cost is unknown, not zero">
            <ul className="space-y-1.5 text-sm">{without.map((s) => <li key={s.scope}><b>{s.name}</b> <span className="text-[11px] text-ink-3">{s.scope}</span><div className="text-xs text-ink-2">{s.gap}</div></li>)}</ul>
          </Panel>
        )}
        <Panel title="How these figures are calculated">
          <ul className="space-y-1 text-xs text-ink-2">{Object.values(data.definitions).map((v) => <li key={v}>{v}</li>)}</ul>
        </Panel>
      </>}
    </>
  )
}
