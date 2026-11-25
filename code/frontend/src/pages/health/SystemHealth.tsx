import { CheckCircle2, CircleAlert, CircleDashed, PlayCircle, TriangleAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useCan } from '../../auth/AuthContext'
import { Segmented } from '../../components/hero'
import { post, useAction } from '../../components/secops'
import { ErrorNote, PageSkeleton, PROVIDER_LABEL, fmtAgo, fmtTime } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { ScopeName } from '../../hooks/useScopeNames'

/** Is every workflow working, and if not, exactly what to fix. Pre-flight is read-only. */
interface Check { area: string; cloud: string | null; scope: string | null; check: string; status: 'PASS' | 'WARN' | 'FAIL'; message: string; fix: string | null }
interface Preflight { verdict: string; counts: Record<string, number>; checks: Check[]; generated_at: string | null }
interface Job { name: string; description: string | null; enabled: boolean; last_status: string; last_run_at: string | null; last_success_at: string | null
  problem_streak: number; scopes_total: number; scopes_failed: number; next_run_at: string | null; problems: { scope: string; reason: string | null; fix: string }[] }
interface Health { verdict: string; jobs: Job[]; jobs_failing: number; jobs_active: number; clouds: Record<string, Record<string, number>>; preflight: Preflight | null }

const TONE: Record<string, [string, typeof CheckCircle2]> = {
  PASS: ['var(--good)', CheckCircle2], WARN: ['var(--warning)', TriangleAlert], FAIL: ['var(--critical)', CircleAlert],
  success: ['var(--good)', CheckCircle2], partial: ['var(--warning)', TriangleAlert], failed: ['var(--critical)', CircleAlert],
  running: ['var(--accent)', CircleDashed], never: ['var(--ink-3)', CircleDashed],
}
function Status({ s, label }: { s: string; label?: string }) {
  const [c, Icon] = TONE[s] ?? TONE.never
  return <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-semibold" style={{ color: c }}><Icon size={14} aria-hidden />{label ?? s}</span>
}

export default function SystemHealth() {
  const [bump, setBump] = useState(0), [show, setShow] = useState<'problems' | 'all'>('problems')
  const canRun = useCan('automation:run')
  const { data, error, reload } = useApi<Health>('/system/health', undefined, bump)
  const { run, busy } = useAction(() => setBump((b) => b + 1))
  const checks = useMemo(() => (data?.preflight?.checks ?? []).filter((c) => show === 'all' || c.status !== 'PASS'), [data, show])
  if (error && !data) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton />
  const pre = data.preflight
  const verdictText = data.verdict === 'PASS' ? 'All workflows healthy' : data.verdict === 'WARN' ? 'Working, with warnings' : 'Action needed'
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><p className="text-[11px] font-semibold uppercase tracking-[.14em] text-accent">Integrations</p>
          <h1 className="mt-1 flex items-center gap-3 text-[28px] font-semibold tracking-tight"><Status s={data.verdict} label="" />{verdictText}</h1>
          <p className="mt-1 text-sm text-ink-3">{data.jobs_active - data.jobs_failing} of {data.jobs_active} scheduled workflows healthy on their latest run. Pre-flight {pre?.generated_at ? `ran ${fmtAgo(pre.generated_at)}` : 'has not run yet'}.</p></div>
        <div className="flex flex-wrap gap-2">
          <a className="cn-btn cn-btn-ghost h-9" href="/api/v1/reports/governance/preview" target="_blank" rel="noopener noreferrer"
            title="Today's Daily Governance Dashboard exactly as it is e-mailed. Nothing is sent.">Preview daily governance e-mail</a>
          {canRun && <button type="button" className="cn-btn cn-btn-primary h-9" disabled={busy} onClick={() => run(() => post('/system/preflight'), 'Pre-flight finished')}>
            <PlayCircle size={15} aria-hidden />{busy ? 'Running pre-flight…' : 'Run pre-flight now'}</button>}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">{(['azure', 'aws', 'gcp'] as const).map((p) => { const t = data.clouds[p] ?? {}; return (
        <Link key={p} to="/connections" className="cn-card cn-lift p-4">
          <div className="text-sm font-semibold">{PROVIDER_LABEL[p]}</div>
          {t.scopes ? <div className="mt-1 text-xs text-ink-3"><b className="text-ink">{t.Healthy ?? 0}</b> healthy · <b className="text-ink">{t.Degraded ?? 0}</b> degraded · <b className="text-ink">{t['Not connected'] ?? 0}</b> not connected <span className="text-ink-3">of {t.scopes}</span></div>
            : <div className="mt-1 text-xs text-ink-3">No scopes connected</div>}
        </Link>) })}</div>

      <section className="cn-card p-5" aria-label="Pre-flight">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-[15px] font-semibold">Pre-flight {pre && <span className="ml-2 align-middle"><Status s={pre.verdict} /></span>}</h2>
          <div className="flex items-center gap-3 text-xs text-ink-3">{pre && <span>{pre.counts.PASS ?? 0} pass · {pre.counts.WARN ?? 0} warn · {pre.counts.FAIL ?? 0} fail · {fmtTime(pre.generated_at)}</span>}
            <Segmented label="Show" value={show} onChange={setShow} options={[{ value: 'problems', label: 'Problems' }, { value: 'all', label: 'All checks' }]} /></div>
        </div>
        {!pre ? <p className="py-6 text-center text-sm text-ink-3">Pre-flight has not run yet. It runs daily at 06:40 IST, or now with the button above.</p>
          : checks.length === 0 ? <p className="py-6 text-center text-sm text-ink-3">No problems. Every check passed.</p> :
            <div className="mt-3 overflow-auto rounded-xl border border-line"><table className="cn-table w-full text-sm"><thead><tr className="border-b border-line text-left text-[11px] uppercase tracking-wide text-ink-3">
              <th className="px-3 py-2">Result</th><th className="px-3 py-2">Where</th><th className="px-3 py-2">Check</th><th className="px-3 py-2">What we found</th><th className="px-3 py-2">How to fix</th></tr></thead>
              <tbody>{checks.map((c, i) => <tr key={i} className="border-b border-line align-top last:border-0">
                <td className="px-3 py-2"><Status s={c.status} /></td>
                <td className="px-3 py-2 text-xs">{c.cloud ? <b>{PROVIDER_LABEL[c.cloud]}</b> : <span className="capitalize">{c.area}</span>}{c.scope && <div className="text-ink-3"><ScopeName provider={c.cloud} id={c.scope} /></div>}</td>
                <td className="px-3 py-2 font-medium">{c.check}</td><td className="max-w-[28rem] px-3 py-2 text-[12.5px] text-ink-2">{c.message}</td>
                <td className="max-w-[24rem] px-3 py-2 text-[12.5px]">{c.fix ?? '—'}</td></tr>)}</tbody></table></div>}
      </section>

      <section className="cn-card p-5" aria-label="Workflows">
        <h2 className="text-[15px] font-semibold">Scheduled workflows</h2>
        <p className="text-xs text-ink-3">A failed or partial run raises one alert per workflow per day (rule “job_run_problem”). The last good data is always kept.</p>
        <div className="mt-3 overflow-auto rounded-xl border border-line"><table className="cn-table w-full text-sm"><thead><tr className="border-b border-line text-left text-[11px] uppercase tracking-wide text-ink-3">
          <th className="px-3 py-2">Workflow</th><th className="px-3 py-2">Latest run</th><th className="px-3 py-2">Last success</th><th className="px-3 py-2">Next run</th><th className="px-3 py-2">Problem and fix</th></tr></thead>
          <tbody>{data.jobs.filter((j) => j.enabled).map((j) => <tr key={j.name} className="border-b border-line align-top last:border-0">
            <td className="px-3 py-2"><div className="font-medium">{j.name}</div><div className="max-w-[22rem] truncate text-[11.5px] text-ink-3" title={j.description ?? ''}>{j.description}</div></td>
            <td className="px-3 py-2"><Status s={j.last_status} /><div className="text-[11.5px] text-ink-3">{j.last_run_at ? fmtAgo(j.last_run_at) : '—'}{j.scopes_failed ? ` · ${j.scopes_failed}/${j.scopes_total} scopes failed` : ''}</div>
              {j.problem_streak > 1 && <div className="text-[11px]" style={{ color: 'var(--critical)' }}>{j.problem_streak} runs in a row</div>}</td>
            <td className="px-3 py-2 text-xs text-ink-2">{j.last_success_at ? fmtAgo(j.last_success_at) : 'never'}</td>
            <td className="px-3 py-2 text-xs text-ink-2">{j.next_run_at ? fmtTime(j.next_run_at) : '—'}</td>
            <td className="max-w-[30rem] px-3 py-2 text-[12px]">{j.problems.length === 0 ? <span className="text-ink-3">—</span> : j.problems.map((p, i) => <div key={i} className="mb-1">
              <span className="text-ink-2">{p.scope !== '*' && <b><ScopeName id={p.scope} />: </b>}{(p.reason ?? '').slice(0, 200)}</span><div className="text-ink-3">Fix: {p.fix}</div></div>)}</td>
          </tr>)}</tbody></table></div>
      </section>
    </div>
  )
}
