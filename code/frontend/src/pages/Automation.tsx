import { AlertTriangle, CalendarClock, CheckCircle2, Gauge, Play, Send, Workflow, XCircle } from 'lucide-react'
import { useState } from 'react'
import { useCan } from '../auth/AuthContext'
import { ComparisonChart, HeroLayout, KpiCard, MONITORING_TABS, Panel, SubTabs } from '../components/hero'
import { useToast } from '../components/Toast'
import { Card, EmptyState, ErrorNote, ExportButton, PageHeader, PageSkeleton, StatusBadge, Table, fmtAgo, fmtInt, fmtTime } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useFilters } from '../hooks/useFilters'
import { api, type Automation as AutomationData } from '../services/api'
import { ScopeName } from '../hooks/useScopeNames'

export default function Automation() {
  const { filters, refreshKey } = useFilters()
  const [bump, setBump] = useState(0)
  const [starting, setStarting] = useState<string | null>(null)
  const { data, error, loading, reload } = useApi<AutomationData>('/dashboard/automation', { date_from: filters.dateFrom, date_to: filters.dateTo }, refreshKey + bump)
  const canRun = useCan('automation:run')
  const toast = useToast()

  const run = async (job: string) => {
    setStarting(job)
    try {
      await api.post(`/jobs/${job}/run`)
      toast({ kind: 'info', title: `${job} started`, text: 'The result appears in the execution history when it finishes.' })
      for (const d of [2500, 8000, 20000]) setTimeout(() => setBump((b) => b + 1), d)
    } catch (e) { toast({ kind: 'error', title: `Could not start ${job}`, text: e instanceof Error ? e.message : 'Unknown error' }) } finally { setStarting(null) }
  }

  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return loading ? <PageSkeleton tiles={5} /> : null
  const c = data.stats.counts
  const s = data.scheduler
  const perDayMap = new Map<string, Record<string, string | number>>()
  for (const e of data.executions) {
    const d = e.started_at.slice(0, 10), r = perDayMap.get(d) ?? { date: d, success: 0, partial: 0, failed: 0 }
    if (e.status in r && e.status !== 'date') r[e.status] = Number(r[e.status]) + 1
    perDayMap.set(d, r)
  }
  const perDay = [...perDayMap.values()].sort((x, y) => String(x.date).localeCompare(String(y.date)))
  return (
    <>
      <PageHeader eyebrow="Infrastructure Health" title="Automation jobs"
        description="Schedules, execution history and failures. A run that could not reach a scope is reported as partial or failed, with the scope and reason, never as success." />
      <SubTabs items={MONITORING_TABS} />
      <HeroLayout
        kpis={<>
          <KpiCard icon={<CheckCircle2 size={15} />} label="Successful runs" num={c.success ?? 0} note="last 7 days" />
          <KpiCard icon={<AlertTriangle size={15} />} label="Partial runs" num={c.partial ?? 0} note="some scopes had a problem" />
          <KpiCard icon={<XCircle size={15} />} label="Failed runs" num={c.failed ?? 0} note="see history below" />
          <KpiCard icon={<Gauge size={15} />} label="Success rate" num={data.stats.success_rate_percent} fmt={(v) => `${v.toFixed(0)}%`} note="partial counts as not successful" />
          <KpiCard icon={<Send size={15} />} label="Notifications sent" num={data.notifications.sent ?? 0} note={`${fmtInt(data.notifications.queued ?? 0)} queued · ${fmtInt(data.notifications.failed ?? 0)} failed`} />
          <KpiCard icon={<Workflow size={15} />} label="Jobs enabled" num={data.jobs.filter((j) => j.enabled && j.implemented).length} note={`of ${data.jobs.length} in the catalogue`} />
        </>}
        main={
          <Panel icon={<Workflow size={15} />} title="Job runs per day" subtitle="All jobs in the selected dates, by outcome" bodyClass="px-5 pb-4 pt-3 xl:pr-16">
            <ComparisonChart stacked data={perDay} x="date" xFmt={(d) => d.slice(5)}
              series={[{ key: 'success', label: 'Success', color: 'var(--compare-current)' }, { key: 'partial', label: 'Partial', color: 'var(--compare-previous)' }, { key: 'failed', label: 'Failed', color: 'var(--critical)' }]}
              empty={<EmptyState title="No runs in the selected dates" />} />
          </Panel>
        }
        trend={
          <Panel float icon={<CalendarClock size={15} />} title="Scheduler" subtitle="Unattended background execution (Asia/Kolkata)"
            action={<StatusBadge status={s.state} label={s.state === 'active' ? 'Running' : s.state === 'stale' ? 'Stale' : 'Not running'} />}>
            <p className="text-sm">
              <span className="font-semibold">{s.state === 'active' ? 'Running unattended.' : s.state === 'stale' ? 'Has stopped starting jobs.' : 'Has not started any job yet.'}</span>{' '}
              <span className="text-ink-2">{s.last_scheduled_run_at ? `Last scheduled start ${fmtAgo(s.last_scheduled_run_at)}.` : 'Start it as a background task (see the deployment guide).'}</span>
            </p>
            <ul className="mt-3 space-y-1.5 text-xs">
              {Object.entries(data.next_runs).filter(([, t]) => t).sort((x, y) => String(x[1]).localeCompare(String(y[1]))).slice(0, 5).map(([j, t]) => (
                <li key={j} className="flex justify-between gap-2"><span className="truncate font-medium">{j}</span><span className="tabular whitespace-nowrap text-ink-3">{fmtTime(t)}</span></li>
              ))}
            </ul>
          </Panel>
        }
      />

      <Card icon={<Workflow size={15} />} title="Job schedule" subtitle="Optional integrations (Sheets, AI, notifications) stay idle until configured">
        <Table empty="No jobs registered" head={['Job', 'Schedule', 'State', 'Last run', 'Last result', 'Next run', '']} rows={data.jobs.map((j) => [
          <div><div className="font-medium">{j.name}</div><div className="text-xs text-ink-3">{j.description}</div></div>,
          <code className="text-xs">{j.schedule}</code>,
          j.implemented ? <StatusBadge status={j.running ? 'running' : j.enabled ? 'pass' : 'muted'} label={j.running ? 'Running' : j.enabled ? 'Active' : 'Disabled'} /> : <StatusBadge status="unknown" label="Not built" />,
          <span className="whitespace-nowrap text-xs">{fmtTime(j.last_started_at)}</span>,
          j.last_status ? <StatusBadge status={j.last_status} /> : <span className="text-xs text-ink-3">Never run</span>,
          <span className="whitespace-nowrap text-xs text-ink-2">{fmtTime(data.next_runs[j.name])}</span>,
          j.implemented && canRun ? <button onClick={() => run(j.name)} disabled={starting === j.name} className="cn-btn cn-btn-ghost h-7 px-2.5 text-xs">{starting === j.name ? <span className="cn-spinner" aria-hidden /> : <Play size={12} aria-hidden />}Run now</button> : null,
        ])} />
      </Card>

      <Card icon={<Workflow size={15} />} title="Execution history" subtitle="Most recent 100 runs for the selected dates"
        action={<ExportButton name="Job executions" head={['ID', 'Job', 'Trigger', 'Triggered by', 'Status', 'Started (UTC)', 'Finished (UTC)', 'Scopes', 'Failed', 'Failures', 'Error']}
          rows={data.executions.map((e) => [e.id, e.job_name, e.trigger, e.triggered_by, e.status, e.started_at, e.finished_at, e.scopes_total, e.scopes_failed, e.failures.map((x) => `${x.provider}/${x.scope}: ${x.reason}`).join(' | '), e.error])} />}>
        <Table empty="No executions recorded" head={['Started', 'Job', 'Trigger', 'Result', 'Scopes', 'Problems reported']} rows={data.executions.map((e) => [
          <span className="whitespace-nowrap text-xs">{fmtTime(e.started_at)}</span>, <span className="font-medium">{e.job_name}</span>,
          <span className="text-xs">{e.trigger}{e.triggered_by ? ` · ${e.triggered_by}` : ''}</span>, <StatusBadge status={e.status} />,
          <span className="tabular text-xs">{fmtInt(e.scopes_total)} checked · {fmtInt(e.scopes_failed)} failed</span>,
          e.failures.length || e.error ? (
            <ul className="space-y-0.5 text-xs text-ink-2">
              {e.error && <li>{e.error}</li>}
              {e.failures.slice(0, 4).map((f, i) => <li key={i}>{f.provider !== '*' && <span className="font-medium uppercase">{f.provider} </span>}{f.scope !== '*' ? <>{f.name ?? <ScopeName provider={f.provider} id={f.scope} />}: </> : ''}{f.reason}</li>)}
              {e.failures.length > 4 && <li>and {e.failures.length - 4} more</li>}
            </ul>
          ) : <span className="text-xs text-ink-3">None</span>,
        ])} />
      </Card>
    </>
  )
}
