import { AlertTriangle, ArrowRight, Bell, Boxes, CheckCircle2, CircleDollarSign, Clock, Gauge, HeartPulse, OctagonAlert, Server, ShieldAlert, TrendingUp, Wallet, Zap } from 'lucide-react'
import { Link } from 'react-router-dom'
import { StackedBars } from '../components/charts'
import { ArcDonut, CARD_ORDER, ComparisonChart, Delta, HeroLayout, KpiCard, Panel, ProviderCard, TrendArea } from '../components/hero'
import {
  Card, CollectionNotice, EmptyState, ErrorNote, Freshness, Meter, PageHeader, PageSkeleton, PROVIDER_COLOR, PROVIDER_LABEL, PROVIDER_NAME, PROVIDERS,
  ProviderTag, SCOPE_NOUN, StatusBadge, fmtAgo, fmtInt, fmtPct, fmtTime, fmtUsd, fmtUsdShort,
} from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useFilters } from '../hooks/useFilters'
import type { Overview as OverviewData, ProviderHealth } from '../services/api'

const HEALTH_LABEL: Record<ProviderHealth['state'], string> = { healthy: 'Healthy', degraded: 'Degraded', failing: 'Failing', pending: 'Awaiting discovery', not_connected: 'Not connected' }
const JOB_LABEL: Record<string, string> = { account_discovery: 'Account discovery', security_events: 'Security events', billing_refresh: 'Billing', vm_metrics: 'VM metrics' }
const ALERT_ICON: Record<string, React.ReactNode> = {
  critical: <OctagonAlert size={15} className="text-critical" aria-hidden />, serious: <AlertTriangle size={15} className="text-serious" aria-hidden />,
  warning: <AlertTriangle size={15} className="text-warning" aria-hidden />,
}
const SEV_COLOR: Record<string, string> = { Critical: 'var(--critical)', High: 'var(--serious)', Medium: 'var(--warning)', Low: 'var(--compare-previous)' }
const AREA_LINK: Record<string, string> = { soc: '/soc', finops: '/finops', infrastructure: '/monitoring', automation: '/automation' }

export default function Overview() {
  const { filters: f, refreshKey, refresh } = useFilters()
  const { data, error, loading, reload } = useApi<OverviewData>('/dashboard/overview', { provider: f.provider, scope: f.scope, date_from: f.dateFrom, date_to: f.dateTo }, refreshKey)
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return loading ? <PageSkeleton tiles={6} /> : null
  const c = data.collection
  const has = (k: keyof typeof c) => c[k].state === 'collected'
  const totalScopes = PROVIDERS.reduce((n, p) => n + data.scopes[p].total, 0)
  const sev = data.findings_open_by_severity
  const rate = data.automation.success_rate_percent
  const providersWithCost = PROVIDERS.filter((p) => data.cost_daily.some((d) => d[p] !== undefined))
  const monthly: Record<string, string | number>[] = data.cost_monthly.map((m) => ({ ...m, month: String(m.month).slice(2) }))
  const u = data.vm_utilisation
  const dailyTotal = data.cost_daily.map((r) => ({ x: String(r.date), y: Math.round(PROVIDERS.reduce((a, p) => a + Number(r[p] ?? 0), 0) * 100) / 100 }))
  const openTotal = (['Critical', 'High', 'Medium', 'Low'] as const).reduce((a, k) => a + (sev[k] ?? 0), 0)
  const lastSync = Object.values(data.freshness).map((x) => x.last_success_at).filter(Boolean).sort().pop() ?? null

  return (
    <>
      <PageHeader eyebrow="Executive Command Center" title="Multi-cloud command center"
        description="Live position across AWS, Microsoft Azure and Google Cloud. Every figure is read from collected cloud data; nothing is estimated."
        action={<Freshness at={lastSync} label="Last successful sync" onRefresh={refresh} />} />
      {!has('inventory') && <CollectionNotice collection={c.inventory} what="cloud inventory" />}

      <HeroLayout
        kpis={<>
          <KpiCard icon={<Boxes size={15} />} label="Cloud scopes" num={has('inventory') ? totalScopes : null} to="/inventory"
            note={PROVIDERS.map((p) => `${PROVIDER_LABEL[p]} ${data.scopes[p].total}`).join(' · ')} />
          <KpiCard icon={<Server size={15} />} label="Cloud resources" num={data.total_resources || null} to="/monitoring" note={data.total_resources ? `${fmtInt(data.vms.total)} VMs included` : 'Inventory not collected'} />
          <KpiCard icon={<ShieldAlert size={15} />} label="Critical findings" num={has('soc') ? sev.Critical : null} to="/soc"
            note={has('soc') ? `High ${fmtInt(sev.High)} · Medium ${fmtInt(sev.Medium)}` : 'Audit logs not collected'} />
          <KpiCard icon={<Wallet size={15} />} label="Spend to date" num={data.cost.total} fmt={fmtUsd} to="/dashboard"
            note={data.cost.total === null ? 'Billing not collected' : data.cost.is_final ? 'Final figures' : 'Provisional, not an invoice'} />
          <KpiCard icon={<Gauge size={15} />} label="Budget used" num={data.budget.utilisation_percent} fmt={(n) => fmtPct(n)} to="/finops"
            note={data.budget.approved === null ? 'No approved budget' : `of ${fmtUsd(data.budget.approved)}`} />
          <KpiCard icon={<HeartPulse size={15} />} label="Healthy VMs" num={has('infrastructure') ? data.vms.healthy : null} to="/monitoring"
            note={has('infrastructure') ? `${fmtInt(data.vms.unhealthy)} unhealthy · ${fmtInt(data.vms.unknown)} no metrics` : 'VM monitoring not collected'} />
        </>}
        main={
          <Panel icon={<CircleDollarSign size={15} />} title="Daily cloud spend, $" subtitle={`By cloud, ${data.filters.from} to ${data.filters.to}`} bodyClass="px-5 pb-4 pt-3 xl:pr-16"
            action={<Link to="/dashboard" className="text-xs font-medium text-accent hover:underline">Cost dashboard</Link>}>
            <ComparisonChart stacked data={data.cost_daily} x="date" fmt={fmtUsdShort} xFmt={(d) => d.slice(5)}
              series={(providersWithCost.length ? providersWithCost : [...PROVIDERS]).map((p) => ({ key: p, label: PROVIDER_NAME[p], color: PROVIDER_COLOR[p] }))}
              empty={<EmptyState title="No billing records in this range" />} />
          </Panel>
        }
        trend={
          <Panel float icon={<TrendingUp size={15} />} title="Daily total spend" subtitle="Hover a day; change vs 7 days earlier">
            <TrendArea points={dailyTotal} fmt={fmtUsdShort} xFmt={(x) => x} compare={(i) => (i >= 7 ? dailyTotal[i - 7].y : null)} />
          </Panel>
        }
        donut={
          <Panel float icon={<ShieldAlert size={15} />} title="Open findings" subtitle="By severity, awaiting or under review">
            <ArcDonut centre={has('soc') ? fmtInt(openTotal) : '—'} centreNote="open findings" emptyText={has('soc') ? 'No open findings.' : 'Audit logs not collected yet.'}
              items={(['Critical', 'High', 'Medium', 'Low'] as const).map((k) => ({ key: k, label: k, value: sev[k] ?? 0, color: SEV_COLOR[k] }))} />
          </Panel>
        }
        bottom={CARD_ORDER.map((p) => {
          const h = data.provider_health[p]
          return (
            <ProviderCard key={p} provider={p} to="/inventory" value={h.enabled ? fmtInt(h.scopes_active) : '—'} valueLabel={`active ${SCOPE_NOUN[p]}`}
              side={{ value: HEALTH_LABEL[h.state], label: 'Service health' }}
              split={h.enabled && h.scopes_active ? { left: { label: 'Fully onboarded', value: fmtInt(h.fully_onboarded) }, right: { label: 'Access failed', value: fmtInt(h.access_failed) }, ratio: h.fully_onboarded / h.scopes_active } : null}
              note={!h.enabled ? 'Connect on Cloud Inventory' : h.failure_count ? `${h.failure_count} problem(s) in the latest runs: ${h.failures[0]?.reason ?? ''}`
                : h.last_connection_test ? `Connection ${h.last_connection_test.ok ? 'verified' : 'test failed'} ${fmtAgo(h.last_connection_test.at)}` : 'Connection never tested'} />
          )
        })}
      />

      <div className="grid gap-4 xl:grid-cols-3">
        <Card icon={<Bell size={15} />} title="Alerts and notifications" subtitle="Derived from current state; resolves itself when the condition clears" className="xl:col-span-1"
          >
          {data.alerts.length === 0 ? <EmptyState title="No active alerts" icon={<CheckCircle2 size={18} className="text-good" />}>Nothing currently needs attention.</EmptyState> : (
            <ul className="space-y-1.5">
              {data.alerts.map((a, i) => (
                <li key={i}><Link to={AREA_LINK[a.area] ?? '/'} className="flex items-start gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-surface-2">{ALERT_ICON[a.level] ?? ALERT_ICON.warning}<span className="flex-1">{a.text}</span><ArrowRight size={13} className="mt-1 text-ink-3" aria-hidden /></Link></li>
              ))}
            </ul>
          )}
        </Card>
        <Card icon={<ShieldAlert size={15} />} title="Latest cloud activity" subtitle="Most recent audit events across all connected clouds" className="xl:col-span-2"
          action={<Link to="/soc" className="text-xs font-medium text-accent hover:underline">Open SOC</Link>}>
          {data.recent_events.length === 0 ? <EmptyState title="No audit events collected yet" /> : (
            <ul className="divide-y divide-line/70">
              {data.recent_events.map((e) => (
                <li key={e.id} className="flex flex-wrap items-center gap-x-3 gap-y-0.5 py-2 text-sm">
                  <span className="w-16"><ProviderTag provider={e.provider} /></span>
                  <span className="min-w-0 flex-1 truncate font-medium" title={e.event_name}>{e.event_name}</span>
                  <span className="max-w-[16rem] truncate text-xs text-ink-2" title={e.principal ?? ''}>{e.principal ?? 'unknown principal'}</span>
                  {e.flagged ? <StatusBadge status={e.severity ?? 'Low'} /> : <span className="text-xs text-ink-3">no rule matched</span>}
                  <span className="w-24 text-right text-xs text-ink-3">{fmtAgo(e.time)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card icon={<Server size={15} />} title="VM utilisation" subtitle={`Latest sample from ${fmtInt(u.running_with_samples)} running VM(s). "no data" means the metric is not collected, not zero.`}>
          <div className="space-y-3 text-sm">
            {(['cpu', 'memory', 'disk'] as const).map((k) => (
              <div key={k}>
                <div className="mb-1 flex justify-between text-xs"><span className="font-medium capitalize text-ink-2">{k === 'cpu' ? 'CPU' : k} (average)</span>
                  <span className="text-ink-3">{u[k].reporting} reporting{u[k].missing ? `, ${u[k].missing} without data` : ''}{u[k].max !== null ? ` · peak ${u[k].max}%` : ''}</span></div>
                <Meter value={u[k].average} label={`${k} average`} />
              </div>
            ))}
          </div>
        </Card>
        <Card icon={<Zap size={15} />} title="Background jobs" subtitle={data.scheduler.state === 'active' ? `Scheduler active · last start ${fmtAgo(data.scheduler.last_scheduled_run_at)}` : data.scheduler.state === 'stale' ? 'Scheduler has stopped starting jobs' : 'Scheduler has not run yet'}
          action={<StatusBadge status={data.scheduler.state} label={data.scheduler.state === 'never_run' ? 'Not running' : data.scheduler.state === 'active' ? 'Running' : 'Stale'} />}>
          <ul className="space-y-2 text-sm">
            {Object.entries(data.freshness).map(([job, fr]) => {
              const next = data.jobs.find((j) => j.name === job)?.next_run_at
              return (
                <li key={job} className="flex items-center justify-between gap-2">
                  <div><div className="font-medium">{JOB_LABEL[job] ?? job}</div>
                    <div className="text-xs text-ink-3"><Clock size={11} className="mr-1 inline" aria-hidden />Last success {fmtAgo(fr.last_success_at)}{next ? ` · next ${fmtTime(next).replace(' IST', '')}` : ''}</div></div>
                  {fr.last_status ? <StatusBadge status={fr.last_status} /> : <StatusBadge status="unknown" label="Never run" />}
                </li>
              )
            })}
          </ul>
          <Link to="/automation" className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline">
            <Zap size={12} aria-hidden />{rate === null ? 'No completed runs in 7 days' : `${rate}% of runs fully successful in 7 days`}
          </Link>
        </Card>
        <Card title="Spend trend" subtitle="Last 7 days and the last six months" icon={<TrendingUp size={15} />}>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-2xl bg-surface-2 p-3"><div className="text-xs text-ink-3">Last 7 days</div><div className="tabular text-lg font-semibold">{fmtUsd(data.cost_weekly.current_week)}</div></div>
            <div className="rounded-2xl bg-surface-2 p-3"><div className="text-xs text-ink-3">vs previous 7 days</div><div className="mt-1"><Delta pct={data.cost_weekly.variation_percent} /> {data.cost_weekly.variation_percent === null && <span className="text-sm">—</span>}</div></div>
          </div>
          {monthly.length === 0 ? <div className="mt-3"><EmptyState title="No monthly data" /></div> : (
            <div className="mt-3"><StackedBars data={monthly} category="month" stacked={false} valueFormat={fmtUsdShort} height={170}
              series={PROVIDERS.filter((p) => monthly.some((m) => m[p] !== undefined)).map((p) => ({ key: p, label: PROVIDER_LABEL[p], color: PROVIDER_COLOR[p] }))} /></div>
          )}
        </Card>
      </div>
      <p className="text-center text-[11px] text-ink-3">Generated {fmtTime(data.generated_at)} from the CloudNexus database. Collection runs on schedule without a browser session.</p>
    </>
  )
}
