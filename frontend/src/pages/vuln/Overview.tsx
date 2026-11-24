import { AlertTriangle, CheckCircle2, Clock, Eye, FileWarning, Gauge, PieChart as PieIcon, RotateCcw, ShieldAlert, ShieldCheck, TrendingUp } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { ArcDonut, CARD_ORDER, ComparisonChart, HeroLayout, KpiCard, Panel, ProviderCard, SubTabs, TrendArea } from '../../components/hero'
import { ErrorNote, Freshness, PageHeader, PageSkeleton, PROVIDER_LABEL, fmtInt } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { useFilters } from '../../hooks/useFilters'
import { VULN_TABS } from './tabs'

/* eslint-disable @typescript-eslint/no-explicit-any */
const SEV = { Critical: 'var(--critical)', High: 'var(--serious)', Medium: 'var(--warning)', Low: 'var(--compare-current)' } as const

export default function VulnOverview() {
  const { refreshKey, refresh } = useFilters()
  const ov = useApi<any>('/security/overview', undefined, refreshKey)
  const sync = useApi<any>('/sync/status', undefined, refreshKey)
  const nav = useNavigate()
  if (ov.error) return <ErrorNote message={ov.error.message} onRetry={ov.reload} />
  if (!ov.data) return <PageSkeleton tiles={8} />
  const d = ov.data, k = d.kpis, a = d.audit
  const go = (q: string) => () => nav(`/vulnerabilities/findings?${q}`)
  const trend = (d.trend as any[]).map((t) => ({ x: t.date, y: t.open_total }))
  const integ = Object.fromEntries((sync.data?.integrations ?? []).map((i: any) => [i.provider, i]))
  return (
    <>
      <PageHeader eyebrow="Security Center" title="Enterprise Multi-Cloud Vulnerability & Security Posture Management"
        description="Findings from AWS Security Hub, Azure Advisor (security recommendations) and Google Security Command Center, synchronized daily at 02:00 UTC. Every figure is counted from the synchronized database."
        action={<Freshness at={sync.data?.last_successful_run?.finished_at} label="Last successful sync" onRefresh={refresh} />} />
      <SubTabs items={VULN_TABS} />
      <HeroLayout
        kpis={<>
          <KpiCard icon={<ShieldAlert size={15} />} label="Total findings" num={k.total} note={`${fmtInt(k.active_natively)} active at the provider`} to="/vulnerabilities/findings" />
          <KpiCard icon={<AlertTriangle size={15} />} label="Critical" num={k.critical} note={`High ${fmtInt(k.high)}`} to="/vulnerabilities/findings?severity=Critical&status=OPEN,UNDER_REVIEW,REOPENED,EXCEPTION" />
          <KpiCard icon={<Eye size={15} />} label="Open" num={k.open} note={`Under review ${fmtInt(k.under_review)}`} to="/vulnerabilities/findings?status=OPEN" />
          <KpiCard icon={<Clock size={15} />} label="Overdue" num={k.overdue} note="past remediation SLA" to="/vulnerabilities/findings?overdue=true" />
          <KpiCard icon={<FileWarning size={15} />} label="Active exceptions" num={k.exceptions} note="risk accepted, not removed" to="/vulnerabilities/exceptions" />
          <KpiCard icon={<CheckCircle2 size={15} />} label="Resolved" num={k.resolved} note={`Reopened ${fmtInt(k.reopened)}`} to="/vulnerabilities/findings?status=RESOLVED" />
          {a && <>
            <KpiCard icon={<ShieldCheck size={15} />} label="Audit events" num={a.total_events} note={`${fmtInt(a.authorized)} authorized · ${fmtInt(a.normal)} normal`} to="/audit" />
            <KpiCard icon={<RotateCcw size={15} />} label="Under investigation" num={a.under_investigation} note={`${fmtInt(a.suspicious + a.violations)} suspicious / violations · ${fmtInt(a.closed)} closed`} to="/audit/queue" />
          </>}
        </>}
        main={
          <Panel icon={<ShieldAlert size={15} />} title="Findings by cloud" subtitle="Open, under review, reopened and excepted findings by severity" bodyClass="px-5 pb-4 pt-3 xl:pr-16">
            <ComparisonChart stacked x="cloud" data={['aws', 'azure', 'gcp'].map((p) => ({ cloud: PROVIDER_LABEL[p], ...(d.by_provider[p] ?? {}) }))}
              series={(['Critical', 'High', 'Medium', 'Low'] as const).map((s) => ({ key: s, label: s, color: SEV[s] }))}
              empty={<div className="grid h-[300px] place-items-center text-center text-sm text-ink-3">No findings synchronized yet.<br />Connect a cloud and run the security sync under Integrations.</div>} />
          </Panel>
        }
        trend={
          <Panel float icon={<TrendingUp size={15} />} title="Posture over time" subtitle="Unresolved findings at the end of each day (30 days)">
            <TrendArea points={trend} xFmt={(x) => x} compare={(i) => (i >= 7 ? trend[i - 7].y || null : null)} />
          </Panel>
        }
        donut={
          <Panel float icon={<PieIcon size={15} />} title="Severity distribution" subtitle="Unresolved findings">
            <ArcDonut centre={fmtInt(k.critical + k.high + k.medium + k.low)} centreNote="unresolved" items={(['Critical', 'High', 'Medium', 'Low'] as const).map((s) => ({ key: s, label: s, value: k[s.toLowerCase()], color: SEV[s] }))} />
          </Panel>
        }
        bottom={CARD_ORDER.map((p) => {
          const c = d.by_provider[p] ?? {}
          const total = Object.values(c).reduce((x: number, y: any) => x + Number(y), 0) as number
          const i = integ[p]
          return (
            <ProviderCard key={p} provider={p} to={`/vulnerabilities/${p}`} action="View findings" value={fmtInt(total)} valueLabel="Unresolved findings"
              side={{ value: fmtInt((c.Critical ?? 0) + (c.High ?? 0)), label: 'Critical + high' }}
              note={i ? `Integration: ${String(i.health).replace(/_/g, ' ').toLowerCase()}${i.last_success_at ? ` · synced ${new Date(i.last_success_at).toLocaleDateString('en-IN')}` : ''}` : 'Integration status unavailable'} />
          )
        })}
      />
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel icon={<ShieldAlert size={15} />} title="By account / subscription / project">
          <ul className="space-y-1.5 text-sm">{(d.by_scope as [string, number][]).slice(0, 12).map(([s, n]) => (
            <li key={s}><button className="flex w-full justify-between hover:text-accent" onClick={go(`scope=${encodeURIComponent(s.split(':').slice(1).join(':'))}`)}><span className="truncate">{s}</span><b className="tabular">{n}</b></button></li>))}
            {!d.by_scope.length && <li className="text-xs text-ink-3">No findings.</li>}</ul>
        </Panel>
        <Panel icon={<ShieldAlert size={15} />} title="By region / location">
          <ul className="space-y-1.5 text-sm">{(d.by_region as [string, number][]).slice(0, 12).map(([s, n]) => (
            <li key={s}><button className="flex w-full justify-between hover:text-accent" onClick={go(`region=${encodeURIComponent(s)}`)}><span>{s}</span><b className="tabular">{n}</b></button></li>))}
            {!d.by_region.length && <li className="text-xs text-ink-3">No findings.</li>}</ul>
        </Panel>
        <Panel icon={<Gauge size={15} />} title="Remediation SLA performance" subtitle="Resolved within SLA vs missed; open on track vs overdue">
          <ArcDonut centre={fmtInt(Object.values(d.sla).reduce((x: number, y: any) => x + Number(y), 0) as number)} centreNote="with an SLA"
            items={[{ key: 'met', label: 'Resolved in SLA', value: d.sla.met ?? 0, color: 'var(--good)' }, { key: 'missed', label: 'Resolved late', value: d.sla.missed ?? 0, color: 'var(--serious)' },
              { key: 'on_track', label: 'Open, on track', value: d.sla.on_track ?? 0, color: 'var(--compare-current)' }, { key: 'overdue', label: 'Overdue', value: d.sla.overdue ?? 0, color: 'var(--critical)' }]} />
        </Panel>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel icon={<TrendingUp size={15} />} title="Detected vs resolved" subtitle="Per day, last 30 days">
          <ComparisonChart data={d.trend} x="date" xFmt={(v) => v.slice(5)} defaultMode="line"
            series={[{ key: 'detected', label: 'Detected', color: 'var(--critical)' }, { key: 'resolved', label: 'Resolved', color: 'var(--good)' }]} />
        </Panel>
        <Panel icon={<PieIcon size={15} />} title="Finding categories" subtitle={d.non_security_recommendations ? `${fmtInt(d.non_security_recommendations)} non-security Azure Advisor recommendations are kept separately and not counted` : 'Unresolved findings'}>
          <ul className="space-y-1.5 text-sm">{(d.by_category as [string, number][]).map(([c, n]) => (
            <li key={c}><button className="flex w-full justify-between hover:text-accent" onClick={go(`category=${encodeURIComponent(c)}`)}><span className="truncate">{c}</span><b className="tabular">{n}</b></button></li>))}
            {!d.by_category.length && <li className="text-xs text-ink-3">No findings.</li>}</ul>
        </Panel>
      </div>
    </>
  )
}
