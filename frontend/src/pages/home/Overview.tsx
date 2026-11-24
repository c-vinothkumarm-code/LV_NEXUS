import { ArrowUpRight, Boxes, CircleDollarSign, KeyRound, Radar, ShieldAlert } from 'lucide-react'
import { Link } from 'react-router-dom'
import { ComparisonChart, ProviderBadge, type HeroSeries } from '../../components/hero'
import { Pill } from '../../components/secops'
import { Metric, SectionCard, type Freshness } from '../../components/shell'
import { ErrorNote, PageSkeleton, PROVIDER_COLOR, PROVIDER_LABEL, PROVIDER_NAME, fmtAgo, fmtInt, fmtUsd, fmtUsdShort } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { MetricCard, type MetricsResponse } from '../../components/metrics'
import { ScopeName } from '../../hooks/useScopeNames'

interface CloudStats { scopes: number; healthy_scopes: number; resources: number; vms: number; vms_running: number; cost_mtd: number | null
  critical: number; high: number; events_24h: number; flagged_24h: number; privileged: number }
interface Home {
  generated_at: string; clouds: Record<'aws' | 'azure' | 'gcp', CloudStats>
  accounts: Freshness & { total_scopes: number; resources: number; vms: number }
  cost: Freshness & { month_to_date: number | null; last_month: number | null; forecast_month: number | null; trend: Record<string, string | number>[] }
  security: Freshness & { by_severity: Record<string, number>; top: { id: number; title: string; severity: string; provider: string; scope: string; resource: string | null }[] }
  audit: Freshness & { events_24h: number; flagged_24h: number; recent_flagged: { id: number; time: string; provider: string; operation: string; actor: string | null; classification: string; severity: string | null }[] }
  access: Freshness & { identities_with_access: number; privileged_assignments: number }
  health: { jobs: Record<string, { status: string; at: string | null }>; success: number; total: number }
}
const SCOPE_NOUN = { aws: 'accounts', azure: 'subscriptions', gcp: 'projects' } as const
const SEV = ['Critical', 'High', 'Medium', 'Low']
const SEV_COLOR: Record<string, string> = { Critical: 'var(--critical)', High: 'var(--serious)', Medium: 'var(--warning)', Low: 'var(--low)' }

function CloudCard({ p, c }: { p: 'aws' | 'azure' | 'gcp'; c: CloudStats }) {
  const connected = c.scopes > 0
  return (
    <Link to={`/accounts?provider=${p}`} className="cn-card cn-lift group block p-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5"><ProviderBadge provider={p} size={34} /><div><div className="text-sm font-semibold">{PROVIDER_NAME[p]}</div>
          <div className="text-[11.5px] text-ink-3">{connected ? `${c.healthy_scopes} of ${c.scopes} ${SCOPE_NOUN[p]} fully onboarded` : 'Not connected'}</div></div></div>
        <ArrowUpRight size={16} className="text-ink-3 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" aria-hidden />
      </div>
      {connected ? (
        <dl className="mt-4 grid grid-cols-3 gap-3 text-sm">
          <div><dt className="text-[11px] text-ink-3">Resources</dt><dd className="tabular font-semibold">{fmtInt(c.resources + c.vms)}</dd></div>
          <div><dt className="text-[11px] text-ink-3">Cost this month</dt><dd className="tabular font-semibold">{c.cost_mtd === null ? '—' : fmtUsdShort(c.cost_mtd)}</dd></div>
          <div><dt className="text-[11px] text-ink-3">Critical / high</dt><dd className="tabular font-semibold" style={{ color: c.critical ? 'var(--critical)' : undefined }}>{c.critical} / {c.high}</dd></div>
          <div><dt className="text-[11px] text-ink-3">VMs running</dt><dd className="tabular font-semibold">{c.vms_running} / {c.vms}</dd></div>
          <div><dt className="text-[11px] text-ink-3">Activity 24 h</dt><dd className="tabular font-semibold">{fmtInt(c.events_24h)}{c.flagged_24h ? <span className="ml-1 text-xs" style={{ color: 'var(--critical)' }}>{c.flagged_24h} flagged</span> : null}</dd></div>
          <div><dt className="text-[11px] text-ink-3">Privileged roles</dt><dd className="tabular font-semibold">{fmtInt(c.privileged)}</dd></div>
        </dl>
      ) : <p className="mt-4 text-sm text-ink-3">Connect this cloud under Integrations → Onboard a cloud to start collecting.</p>}
    </Link>
  )
}

/** Executive metrics: connectivity, security, infrastructure, FinOps, governance and activity, each card with its definition,
 *  source, calculation, timestamp, scope and availability (from /home/metrics, filtered by role on the server). */
function ExecutiveMetrics() {
  const { data, error, reload } = useApi<MetricsResponse>('/home/metrics')
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton tiles={6} />
  return (
    <div className="space-y-5" aria-label="Executive metrics">
      {data.sections.map((sec) => {
        const items = data.metrics.filter((m) => m.section === sec.key)
        if (!items.length) return null
        return (
          <section key={sec.key} aria-labelledby={`sec-${sec.key}`}>
            <div className="mb-2 flex items-baseline justify-between gap-3">
              <h2 id={`sec-${sec.key}`} className="cn-h-section">{sec.label}</h2>
              <Link to={sec.link} className="text-xs font-medium text-accent hover:underline">Open {sec.label.toLowerCase()} →</Link>
            </div>
            <div className="cn-stagger grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-6">{items.map((m) => <MetricCard key={m.key} m={m} />)}</div>
          </section>
        )
      })}
      <p className="text-[11.5px] text-ink-3">Select ⓘ on any figure for its definition, source, calculation and timestamp. "—" means the data has not been collected: it is never shown as zero.</p>
    </div>
  )
}

/** Executive overview: three clouds, cost, security, live activity and access, each with its own "last updated". */
export default function Overview() {
  const { data, error, reload } = useApi<Home>('/home')
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton tiles={6} />
  const series: HeroSeries[] = (['aws', 'azure', 'gcp'] as const).map((p) => ({ key: p, label: PROVIDER_LABEL[p], color: PROVIDER_COLOR[p] }))
  const sev = data.security.by_severity
  const sevTotal = SEV.reduce((a, k) => a + (sev[k] ?? 0), 0)
  const delta = data.cost.month_to_date !== null && data.cost.forecast_month !== null && data.cost.last_month
    ? ((data.cost.forecast_month - data.cost.last_month) / data.cost.last_month) * 100 : null
  const failing = Object.entries(data.health.jobs).filter(([, j]) => j.status === 'failed')
  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><p className="text-[11px] font-semibold uppercase tracking-[.14em] text-accent">Executive Overview</p>
          <h1 className="cn-h-page mt-1">Executive overview</h1>
          <p className="mt-1 text-sm text-ink-3">AWS, Azure and Google Cloud in one view. Every figure comes from the providers' APIs; each section shows when it was last updated.</p></div>
        <Link to="/system-health" className="cn-card flex items-center gap-2 px-3 py-2 text-xs hover:bg-surface-2">
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: failing.length ? 'var(--critical)' : data.health.success === data.health.total ? 'var(--good)' : 'var(--warning)' }} aria-hidden />
          <span><b>{data.health.success}/{data.health.total}</b> collections healthy{failing.length ? ` · ${failing.length} failing` : ''}</span>
        </Link>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">{(['azure', 'aws', 'gcp'] as const).map((p) => <CloudCard key={p} p={p} c={data.clouds[p]} />)}</div>

      <ExecutiveMetrics />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <SectionCard title="Cost" to="/cost/overview" fresh={data.cost}><div className="flex items-start gap-3"><CircleDollarSign size={20} className="mt-1 text-accent" aria-hidden />
          <Metric label="This month" value={data.cost.month_to_date === null ? null : fmtUsd(data.cost.month_to_date)}
            note={data.cost.forecast_month !== null ? `Forecast ${fmtUsd(data.cost.forecast_month)}${delta !== null ? ` (${delta > 0 ? '+' : ''}${delta.toFixed(0)}% vs last month)` : ''}` : `Last month ${data.cost.last_month === null ? '—' : fmtUsd(data.cost.last_month)}`} /></div></SectionCard>
        <SectionCard title="Vulnerabilities" to="/vulnerabilities" fresh={data.security}><div className="flex items-start gap-3"><ShieldAlert size={20} className="mt-1" style={{ color: 'var(--critical)' }} aria-hidden />
          <Metric label="Open critical / high" value={`${sev.Critical ?? 0} / ${sev.High ?? 0}`} note={`${fmtInt(sevTotal)} open findings in total`} tone={(sev.Critical ?? 0) ? 'var(--critical)' : undefined} /></div></SectionCard>
        <SectionCard title="Live audit" to="/activity" fresh={data.audit}><div className="flex items-start gap-3"><Radar size={20} className="mt-1 text-accent" aria-hidden />
          <Metric label="Events, last 24 h" value={fmtInt(data.audit.events_24h)} note={data.audit.flagged_24h ? `${data.audit.flagged_24h} flagged as unusual` : 'Nothing unusual flagged'} /></div></SectionCard>
        <SectionCard title="Access" to="/access" fresh={data.access}><div className="flex items-start gap-3"><KeyRound size={20} className="mt-1 text-accent" aria-hidden />
          <Metric label="Identities with access" value={fmtInt(data.access.identities_with_access)} note={`${fmtInt(data.access.privileged_assignments)} privileged role assignments`} /></div></SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <SectionCard title="Daily cost, last 30 days" subtitle="Actual cost by cloud (USD). Today is partial; provider billing lags by up to a day." to="/cost/overview" fresh={data.cost}>
          <ComparisonChart data={data.cost.trend} x="date" series={series} stacked fmt={fmtUsdShort} xFmt={(v) => v.slice(5)} height={250} empty="No billing data collected yet." />
        </SectionCard>
        <SectionCard title="Vulnerabilities by severity" to="/vulnerabilities" fresh={data.security}>
          {sevTotal === 0 ? <p className="py-8 text-center text-sm text-ink-3">No open findings in the collected data.</p> : <>
            <div className="flex h-3 overflow-hidden rounded-full bg-surface-2">{SEV.map((k) => <div key={k} style={{ width: `${((sev[k] ?? 0) / sevTotal) * 100}%`, background: SEV_COLOR[k] }} title={`${k}: ${sev[k] ?? 0}`} />)}</div>
            <div className="mt-2 flex flex-wrap gap-3 text-xs">{SEV.map((k) => <span key={k} className="flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[k] }} />{k} <b className="tabular">{sev[k] ?? 0}</b></span>)}</div>
            <ul className="mt-4 divide-y divide-line">{data.security.top.map((f) => <li key={f.id} className="flex items-start gap-2 py-2 text-sm">
              <Pill value={f.severity} /><span className="min-w-0"><span className="block truncate">{f.title}</span><span className="block truncate text-[11px] text-ink-3">{PROVIDER_LABEL[f.provider]} · {f.resource ?? <ScopeName provider={f.provider} id={f.scope} />}</span></span></li>)}</ul>
          </>}
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <SectionCard title="Unusual activity" subtitle="Latest events flagged by the detection rules" to="/activity" toLabel="Open live feed" fresh={data.audit}>
          {data.audit.recent_flagged.length === 0 ? <p className="py-6 text-center text-sm text-ink-3">No unusual activity detected in the collected logs.</p> :
            <ul className="divide-y divide-line">{data.audit.recent_flagged.map((e) => <li key={e.id} className="grid grid-cols-[110px_60px_minmax(0,1fr)_minmax(0,220px)] items-center gap-2 py-2 text-sm">
              <span className="text-xs text-ink-3">{fmtAgo(e.time)}</span><span className="text-xs font-semibold">{PROVIDER_LABEL[e.provider]}</span>
              <span className="truncate font-medium">{e.operation}</span><span className="truncate text-xs text-ink-3">{e.actor ?? '—'}</span></li>)}</ul>}
        </SectionCard>
        <SectionCard title="Inventory" to="/accounts" fresh={data.accounts}>
          <div className="flex items-start gap-3"><Boxes size={20} className="mt-1 text-accent" aria-hidden /><div className="grid flex-1 grid-cols-3 gap-3">
            <Metric label="Scopes" value={fmtInt(data.accounts.total_scopes)} note="accounts / subs / projects" />
            <Metric label="Resources" value={fmtInt(data.accounts.resources)} /><Metric label="VMs" value={fmtInt(data.accounts.vms)} /></div></div>
        </SectionCard>
      </div>
    </>
  )
}
