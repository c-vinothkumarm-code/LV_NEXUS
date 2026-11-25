import { AlertOctagon, CircleDollarSign, Gavel, KeyRound, Landmark, ShieldAlert, Wallet } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ComparisonChart, Panel, Segmented, type HeroSeries } from '../../components/hero'
import { Pill } from '../../components/secops'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_COLOR, PROVIDER_LABEL, fmtTime, fmtUsd, fmtUsdShort } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { useFilters } from '../../hooks/useFilters'
import ExecutiveOperations from './Operations'
import { ExecutiveBrief } from '../../components/brief'

interface Kpi { key: string; label: string; value: number | null; link: string; note: string | null; format: 'int' | 'usd' | 'pct'; reason: string | null }
interface Risk { title: string; provider: string | null; scope: string | null; scope_name: string | null; environment: string | null; business_impact: string; severity: string
  affected_resources: number | null; owner: string; status: string; target_date: string | null; recommended_action: string; pending_decision: string | null; link: string }
interface Decision { type: string; title: string; owner: string; next_step: string; since: string | null; link: string }
interface Summary {
  kpis: Kpi[]; risks: Record<string, Risk[]>; risk_counts: Record<string, number>; decisions: Decision[]; decision_count: number; generated_at: string
  spend: null | { daily_by_provider: Record<string, string | number>[]; daily_by_account: Record<string, string | number>[]; accounts: string[]
    monthly: Record<string, string | number>[]; year_to_date_usd: number | null; top_accounts: { provider: string; name: string; cost_usd: number }[]; top_services: { service: string; cost_usd: number }[] }
}
const GROUPS: [string, string, typeof ShieldAlert][] = [['critical', 'Immediate critical risks', AlertOctagon], ['high', 'High-priority risks', ShieldAlert],
  ['financial', 'Financial risks', Wallet], ['access', 'Access governance risks', KeyRound], ['compliance', 'Compliance risks', Landmark]]
const KPI_GROUPS: [string, string[]][] = [
  ['Footprint', ['providers', 'aws_accounts', 'azure_subscriptions', 'gcp_projects', 'resources', 'vms']],
  ['Cost and budget', ['mtd_spend', 'monthly_spend', 'forecast', 'approved_budgets', 'budget_utilisation', 'over_budget', 'pending_budget_approvals']],
  ['Security', ['critical', 'high', 'medium', 'open_findings', 'overdue']],
  ['Access', ['identities_with_access', 'privileged_access', 'access_gaps', 'unapproved_access', 'expired_access', 'pending_access']],
]
const ACCOUNT_COLORS = ['var(--compare-current)', '#0f97a8', '#8a63d8', '#d99100', '#d03b3b']
const day = (v: string | null) => (v ? fmtTime(v).split(',')[0] : '—')

function KpiTile({ k }: { k: Kpi }) {
  const v = k.value === null ? '—' : k.format === 'usd' ? fmtUsd(k.value) : k.format === 'pct' ? `${k.value.toFixed(1)}%` : k.value.toLocaleString('en-IN')
  return (
    <Link to={k.link} className="cn-card cn-card-link block px-4 py-3" aria-label={`${k.label}: ${v}. Open details`}>
      <div className="text-[11.5px] text-ink-3">{k.label}</div>
      <div className="tabular mt-1 text-[20px] font-semibold leading-tight">{v}</div>
      <div className="mt-0.5 truncate text-[11px] text-ink-3" title={k.reason ?? k.note ?? ''}>{k.value === null ? k.reason : k.note}</div>
    </Link>
  )
}

/** Executive Command Center: KPIs, risk and decision centre, expenditure overview and decision tracker. */
export default function CommandCenter() {
  const { refreshKey } = useFilters()
  const { data, error, reload } = useApi<Summary>('/executive/summary', undefined, refreshKey)
  const [group, setGroup] = useState('critical')
  const [spendView, setSpendView] = useState<'provider' | 'account' | 'monthly'>('provider')
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton tiles={8} />
  const risks = data.risks[group] ?? []
  const s = data.spend
  const providerSeries: HeroSeries[] = ['aws', 'azure', 'gcp'].map((p) => ({ key: p, label: PROVIDER_LABEL[p], color: PROVIDER_COLOR[p] }))
  const accountSeries: HeroSeries[] = (s?.accounts ?? []).map((a, i) => ({ key: a, label: a, color: ACCOUNT_COLORS[i % ACCOUNT_COLORS.length] }))
  return (
    <>
      <PageHeader eyebrow="Executive Overview" title="Cloud risk, cost and decisions at a glance"
        description="Every figure links to its source records. Values that are not collected, or not visible to your role, are shown as — with the reason, never as zero."
        action={<span className="text-xs text-ink-3">Generated {fmtTime(data.generated_at)}</span>} />
      <ExecutiveBrief />
      <div className="grid gap-4 xl:grid-cols-2">{KPI_GROUPS.map(([title, keys]) => {
        const items = data.kpis.filter((k) => keys.includes(k.key))
        return items.length ? (
          <section key={title} aria-label={title}>
            <h2 className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-ink-3">{title}</h2>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">{items.map((k) => <KpiTile key={k.key} k={k} />)}</div>
          </section>) : null
      })}</div>

      <Panel icon={<ShieldAlert size={15} />} title="Executive risk and decision center" subtitle="Highest-priority items from findings, budgets, access and controls"
        action={<Segmented label="Risk group" value={group} onChange={setGroup} options={GROUPS.map(([k, l]) => ({ value: k, label: `${l.split(' ')[0]} ${data.risk_counts[k] ?? 0}` }))} />}>
        {risks.length === 0 ? <div className="py-4 text-sm text-ink-3">No {GROUPS.find((g) => g[0] === group)?.[1].toLowerCase()} in the collected data.</div> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1100px] text-left text-[12.5px]">
              <thead><tr className="border-b border-line text-[11px] uppercase tracking-wide text-ink-3">
                {['Severity', 'Risk', 'Cloud / scope', 'Environment', 'Business impact', 'Affected', 'Owner', 'Status', 'Target', 'Recommended action', 'Pending decision'].map((h) => <th key={h} className="px-2 py-2 font-semibold">{h}</th>)}
              </tr></thead>
              <tbody>{risks.map((r, i) => (
                <tr key={i} className="border-b border-line/60 align-top">
                  <td className="px-2 py-2"><Pill value={r.severity} /></td>
                  <td className="max-w-xs px-2 py-2"><Link to={r.link} className="font-medium text-ink hover:underline">{r.title}</Link></td>
                  <td className="px-2 py-2">{r.provider ? `${PROVIDER_LABEL[r.provider]} · ${r.scope_name}` : '—'}</td>
                  <td className="px-2 py-2">{r.environment ?? '—'}</td>
                  <td className="max-w-xs px-2 py-2 text-ink-2">{r.business_impact}</td>
                  <td className="px-2 py-2 tabular">{r.affected_resources ?? '—'}</td>
                  <td className="px-2 py-2">{r.owner === 'Unassigned' ? <b style={{ color: 'var(--critical)' }}>Unassigned</b> : r.owner}</td>
                  <td className="px-2 py-2">{r.status}</td><td className="whitespace-nowrap px-2 py-2">{day(r.target_date)}</td>
                  <td className="max-w-xs px-2 py-2 text-ink-2">{r.recommended_action}</td><td className="px-2 py-2">{r.pending_decision ?? '—'}</td>
                </tr>))}</tbody>
            </table>
          </div>
        )}
      </Panel>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel icon={<CircleDollarSign size={15} />} title="Cloud expenditure" subtitle={s ? `Year to date ${s.year_to_date_usd === null ? 'not collected' : fmtUsd(s.year_to_date_usd)} · today is partial` : 'Requires the FinOps read permission'}
          action={s ? <Segmented label="Spend view" value={spendView} onChange={setSpendView} options={[{ value: 'provider', label: 'Daily by cloud' }, { value: 'account', label: 'Daily by account' }, { value: 'monthly', label: 'Monthly' }]} /> : undefined}>
          {s ? <ComparisonChart key={spendView} data={spendView === 'provider' ? s.daily_by_provider : spendView === 'account' ? s.daily_by_account : s.monthly}
            x={spendView === 'monthly' ? 'month' : 'date'} series={spendView === 'account' ? accountSeries : providerSeries} stacked fmt={fmtUsdShort}
            xFmt={(v) => (spendView === 'monthly' ? v : v.slice(5))} empty="No billing data collected yet. Spend is unknown, not zero." />
            : <div className="py-6 text-sm text-ink-3">Not available for your role.</div>}
        </Panel>
        <Panel title="Top cost drivers this month">
          {s ? <>
            <div className="text-[11px] uppercase tracking-wide text-ink-3">Accounts</div>
            <ul className="mb-3 mt-1 space-y-1 text-xs">{s.top_accounts.map((a) => <li key={a.name} className="flex justify-between gap-2"><span className="truncate">{PROVIDER_LABEL[a.provider]} · {a.name}</span><span className="tabular font-semibold">{fmtUsd(a.cost_usd)}</span></li>)}
              {!s.top_accounts.length && <li className="text-ink-3">No billing data this month.</li>}</ul>
            <div className="text-[11px] uppercase tracking-wide text-ink-3">Services</div>
            <ul className="mt-1 space-y-1 text-xs">{s.top_services.map((a) => <li key={a.service} className="flex justify-between gap-2"><span className="truncate">{a.service}</span><span className="tabular font-semibold">{fmtUsd(a.cost_usd)}</span></li>)}</ul>
          </> : <div className="text-sm text-ink-3">Not available for your role.</div>}
        </Panel>
      </div>

      <Panel icon={<Gavel size={15} />} title={`Executive decision tracker (${data.decision_count})`} subtitle="Approvals and decisions waiting, with who acts next">
        {data.decisions.length === 0 ? <div className="py-3 text-sm text-ink-3">Nothing is waiting for a decision.</div> : (
          <ul className="divide-y divide-line">{data.decisions.map((d, i) => (
            <li key={i} className="grid gap-1 py-2 text-sm md:grid-cols-[170px_1fr_220px_260px_90px]">
              <span className="text-xs font-semibold text-ink-2">{d.type}</span><Link to={d.link} className="truncate hover:underline">{d.title}</Link>
              <span className="text-xs text-ink-3">{d.owner}</span><span className="text-xs">{d.next_step}</span><span className="text-xs text-ink-3">{day(d.since)}</span>
            </li>))}</ul>
        )}
      </Panel>
      <ExecutiveOperations />
    </>
  )
}
