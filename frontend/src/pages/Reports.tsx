import { CalendarClock, CheckCircle2, FileBarChart2, Mail, PieChart as PieIcon, Play, Send, XCircle } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useCan } from '../auth/AuthContext'
import { ArcDonut, ComparisonChart, HeroLayout, IconBadge, KpiCard, Panel } from '../components/hero'
import { useToast } from '../components/Toast'
import { ErrorNote, ExportButton, PageHeader, PageSkeleton, StatusBadge, Table, fmtAgo, fmtInt, fmtTime } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useFilters } from '../hooks/useFilters'
import { api, type Automation, type Execution, type Finding, type FinOps, type Soc } from '../services/api'

/** Report jobs in the catalogue (backend/app/database/seed.py). */
export const REPORT_JOBS: { name: string; label: string; cadence: string }[] = [
  { name: 'consolidated_daily_report', label: 'Consolidated daily report', cadence: 'Daily' },
  { name: 'soc_daily_review', label: 'SOC daily review', cadence: 'Daily' },
  { name: 'vm_daily_review', label: 'VM health daily review', cadence: 'Daily' },
  { name: 'billing_daily_review', label: 'Billing daily review', cadence: 'Daily' },
  { name: 'weekly_reports', label: 'Weekly security and FinOps summary', cadence: 'Weekly (Monday)' },
  { name: 'monthly_reports', label: 'Monthly expenditure and infrastructure report', cadence: 'Monthly (1st)' },
]
const NOTIFY_COLOR: Record<string, string> = { sent: 'var(--compare-current)', queued: 'var(--compare-previous)', failed: 'var(--critical)', skipped: 'var(--neutral-mark)' }

function perDay(execs: Execution[]) {
  const m = new Map<string, Record<string, number | string>>()
  for (const e of execs) {
    const d = e.started_at.slice(0, 10)
    const r = m.get(d) ?? { date: d, success: 0, partial: 0, failed: 0 }
    const k = e.status === 'success' ? 'success' : e.status === 'partial' ? 'partial' : e.status === 'failed' ? 'failed' : null
    if (k) r[k] = Number(r[k]) + 1
    m.set(d, r)
  }
  return [...m.values()].sort((a, b) => String(a.date).localeCompare(String(b.date)))
}

export default function Reports() {
  const { filters: f, refreshKey } = useFilters()
  const [bump, setBump] = useState(0)
  const canRun = useCan('automation:run'), canSoc = useCan('soc:read'), canFin = useCan('finops:read')
  const toast = useToast()
  const auto = useApi<Automation>('/dashboard/automation', { date_from: f.dateFrom, date_to: f.dateTo }, refreshKey + bump)
  const soc = useApi<Soc>(canSoc ? '/dashboard/soc' : null, undefined, refreshKey)
  const fin = useApi<FinOps>(canFin ? '/dashboard/finops' : null, undefined, refreshKey)
  const [busy, setBusy] = useState<string | null>(null)

  if (auto.error) return <ErrorNote message={auto.error.message} onRetry={auto.reload} />
  if (!auto.data) return <PageSkeleton tiles={6} />
  const a = auto.data
  const names = new Set(REPORT_JOBS.map((r) => r.name))
  const execs = a.executions.filter((e) => names.has(e.job_name))
  const jobs = Object.fromEntries(a.jobs.map((j) => [j.name, j]))
  const ok = execs.filter((e) => e.status === 'success').length, failed = execs.filter((e) => e.status === 'failed').length
  const n = a.notifications
  const upcoming = REPORT_JOBS.map((r) => ({ ...r, next: a.next_runs[r.name] ?? null })).filter((r) => r.next).sort((x, y) => String(x.next).localeCompare(String(y.next)))

  const run = async (job: string) => {
    setBusy(job)
    try { await api.post(`/jobs/${job}/run`); toast({ kind: 'info', title: 'Report run started', text: 'Its result appears below when it finishes.' }); setBump((b) => b + 1) }
    catch (e) { toast({ kind: 'error', title: 'Could not start the report', text: e instanceof Error ? e.message : 'Unknown error' }) }
    finally { setBusy(null) }
  }

  return (
    <>
      <PageHeader eyebrow="Reports & Alerts" title="Reports and exports"
        description="Scheduled email and Google Chat reports with their delivery history, plus CSV exports of current data. A report is marked delivered only when the channel accepted it." />
      <HeroLayout
        kpis={<>
          <KpiCard icon={<FileBarChart2 size={15} />} label="Report schedules" num={REPORT_JOBS.filter((r) => jobs[r.name]?.enabled).length} note={`of ${REPORT_JOBS.length} enabled`} />
          <KpiCard icon={<CheckCircle2 size={15} />} label="Successful runs" num={ok} note="in the selected dates" />
          <KpiCard icon={<XCircle size={15} />} label="Failed runs" num={failed} note={failed ? 'see run history below' : 'none'} />
          <KpiCard icon={<Send size={15} />} label="Messages sent" num={n.sent ?? 0} note={`${fmtInt(n.queued ?? 0)} queued`} />
          <KpiCard icon={<Mail size={15} />} label="Delivery failures" num={n.failed ?? 0} note="retried by notification dispatch" />
          <KpiCard icon={<CalendarClock size={15} />} label="Next report" num={null} note={upcoming[0] ? `${upcoming[0].label}, ${fmtTime(upcoming[0].next)}` : 'Scheduler has not planned one'} />
        </>}
        main={
          <Panel icon={<FileBarChart2 size={15} />} title="Report runs per day" subtitle="Most recent runs of the six report jobs, by outcome" bodyClass="px-5 pb-4 pt-3 xl:pr-16">
            <ComparisonChart stacked data={perDay(execs)} x="date" xFmt={(d) => d.slice(5)}
              series={[{ key: 'success', label: 'Success', color: 'var(--compare-current)' }, { key: 'partial', label: 'Partial', color: 'var(--compare-previous)' }, { key: 'failed', label: 'Failed', color: 'var(--critical)' }]}
              empty={<div className="grid h-[300px] place-items-center text-xs text-ink-3">No report runs in the selected dates.</div>} />
          </Panel>
        }
        trend={
          <Panel float icon={<CalendarClock size={15} />} title="Upcoming reports" subtitle="Next planned run (IST)">
            {upcoming.length === 0 ? <div className="py-6 text-center text-xs text-ink-3">No upcoming runs planned.</div> : (
              <ul className="space-y-2.5">
                {upcoming.map((r) => (
                  <li key={r.name} className="flex items-start justify-between gap-2 text-xs">
                    <div><div className="font-semibold text-ink">{r.label}</div><div className="text-ink-3">{r.cadence}</div></div>
                    <span className="tabular whitespace-nowrap text-ink-2">{fmtTime(r.next)}</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        }
        donut={
          <Panel float icon={<PieIcon size={15} />} title="Notification delivery" subtitle="All channels, by status">
            <ArcDonut centre={fmtInt(Object.values(n).reduce((x, y) => x + y, 0))} centreNote="messages"
              items={Object.entries(n).map(([k, v]) => ({ key: k, label: k[0].toUpperCase() + k.slice(1), value: v, color: NOTIFY_COLOR[k] ?? 'var(--neutral-mark)' }))}
              emptyText="No notifications recorded yet. Email and Chat stay idle until configured." />
          </Panel>
        }
        bottom={REPORT_JOBS.filter((r) => r.cadence !== 'Daily' || r.name === 'consolidated_daily_report').map((r) => {
          const j = jobs[r.name]
          const last = execs.find((e) => e.job_name === r.name)
          return (
            <section key={r.name} className="cn-card cn-lift flex flex-col p-5" aria-label={r.label}>
              <header className="flex items-center gap-2.5"><IconBadge><FileBarChart2 size={15} /></IconBadge><h3 className="text-[14px] font-semibold">{r.label}</h3></header>
              <div className="mt-4 flex items-end justify-between">
                <div><div className="text-[22px] font-semibold leading-none">{r.cadence}</div><div className="mt-1.5 text-[11.5px] text-ink-3">{j?.enabled ? 'Enabled' : 'Disabled'}</div></div>
                <div className="text-right">{last ? <StatusBadge status={last.status} /> : <span className="text-xs text-ink-3">no runs</span>}<div className="mt-1 text-[11.5px] text-ink-3">last run</div></div>
              </div>
              <div className="mt-4 flex-1 space-y-1 rounded-2xl bg-surface-2 p-3.5 text-xs">
                <div className="flex justify-between"><span className="text-ink-3">Last finished</span><span>{j?.last_finished_at ? fmtAgo(j.last_finished_at) : '—'}</span></div>
                <div className="flex justify-between"><span className="text-ink-3">Next run</span><span>{fmtTime(a.next_runs[r.name])}</span></div>
              </div>
              {canRun
                ? <button className="cn-btn cn-btn-dark mt-4 h-10 w-full justify-center" disabled={busy === r.name || j?.running} onClick={() => void run(r.name)}>
                    {busy === r.name || j?.running ? <span className="cn-spinner" aria-hidden /> : <Play size={13} aria-hidden />}Run report now</button>
                : <Link to="/automation" className="cn-btn cn-btn-dark mt-4 h-10 w-full justify-center">View in Automation</Link>}
            </section>
          )
        })}
      />

      <Panel icon={<FileBarChart2 size={15} />} title="Report schedule and history" subtitle="All six report jobs; times in IST">
        <Table label="Report jobs" empty="No report jobs"
          head={['Report', 'Cadence', 'Enabled', 'Last status', 'Last finished', 'Next run', '']}
          rows={REPORT_JOBS.map((r) => {
            const j = jobs[r.name]
            return [<span className="font-medium">{r.label}</span>, r.cadence, j?.enabled ? 'Yes' : 'No', j?.last_status ? <StatusBadge status={j.last_status} /> : <span className="text-xs text-ink-3">never run</span>,
              <span className="text-xs">{fmtTime(j?.last_finished_at)}</span>, <span className="text-xs">{fmtTime(a.next_runs[r.name])}</span>,
              canRun ? <button className="cn-btn cn-btn-ghost h-7 text-xs" disabled={busy === r.name || j?.running} onClick={() => void run(r.name)}>Run now</button> : null]
          })} />
      </Panel>

      <Panel icon={<Send size={15} />} title="Data exports" subtitle="CSV of the data on screen, stamped with the product name and export time">
        <div className="flex flex-wrap gap-3">
          {canSoc && <ExportCard title="Security findings" detail="Most recent findings with severity and review status"
            button={<ExportButton name="Security findings" head={['ID', 'Cloud', 'Scope', 'Title', 'Severity', 'Review status', 'Resource', 'First seen', 'Last seen']}
              rows={(soc.data?.recent_findings ?? []).map((x: Finding) => [x.id, x.provider, x.scope, x.title, x.severity, x.review_status, x.resource_id, x.first_seen_at, x.last_seen_at])} />} />}
          {canFin && <ExportCard title="Daily cost by cloud" detail="Last 30 days, USD"
            button={<ExportButton name="Daily cost" head={['Date', 'Cloud', 'Cost (USD)']} rows={(fin.data?.daily ?? []).map((x) => [x.date, x.provider, x.cost_usd])} />} />}
          {canFin && <ExportCard title="Budget versus actual" detail="Every approved budget"
            button={<ExportButton name="Budgets" head={['Cloud', 'Scope', 'Service', 'Period start', 'Period end', 'Approved', 'Actual', 'Utilisation %']}
              rows={(fin.data?.budget_status ?? []).map((b) => [b.provider, b.scope, b.service, b.period_start, b.period_end, b.approved, b.actual, b.utilisation_percent])} />} />}
          <ExportCard title="Report run history" detail="Runs listed above"
            button={<ExportButton name="Report runs" head={['Job', 'Trigger', 'Status', 'Started', 'Finished', 'Error']} rows={execs.map((e) => [e.job_name, e.trigger, e.status, e.started_at, e.finished_at, e.error])} />} />
        </div>
        <p className="mt-3 text-xs text-ink-3">The full audit evidence pack is built with <code>python -m app.validation evidence</code> on the server.</p>
      </Panel>
    </>
  )
}

function ExportCard({ title, detail, button }: { title: string; detail: string; button: React.ReactNode }) {
  return (
    <div className="flex min-w-[240px] flex-1 items-center justify-between gap-3 rounded-2xl border border-line bg-surface-2 px-4 py-3">
      <div><div className="text-sm font-semibold">{title}</div><div className="text-xs text-ink-3">{detail}</div></div>{button}
    </div>
  )
}
