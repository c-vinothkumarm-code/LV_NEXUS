import { CalendarClock, CloudCog, PlayCircle, RotateCcw } from 'lucide-react'
import { useState } from 'react'
import { useCan } from '../../auth/AuthContext'
import { KpiCard, Panel, ProviderBadge, SubTabs } from '../../components/hero'
import { Confirm, DataGrid, DownloadButton, KV, Pill, Select, fmtDT, post, put, useAction } from '../../components/secops'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_LABEL, PROVIDER_NAME, fmtInt } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { useFilters } from '../../hooks/useFilters'
import { INTEG_TABS } from '../vuln/tabs'
import { ScopeName } from '../../hooks/useScopeNames'

/* eslint-disable @typescript-eslint/no-explicit-any */
const dur = (s: number | null) => (s === null || s === undefined ? '—' : s < 90 ? `${Math.round(s)} s` : `${(s / 60).toFixed(1)} min`)

function useSync() {
  const { refreshKey } = useFilters()
  const [bump, setBump] = useState(0)
  const st = useApi<any>('/sync/status', undefined, refreshKey + bump)
  return { st, reload: () => setBump((b) => b + 1) }
}

function RunButtons({ onDone }: { onDone: () => void }) {
  const canRun = useCan('sync:run')
  const { run, busy } = useAction(onDone)
  const [confirm, setConfirm] = useState<'run' | 'full' | 'retry' | null>(null)
  if (!canRun) return null
  return (
    <div className="flex flex-wrap gap-2">
      <button className="cn-btn cn-btn-primary" disabled={busy} onClick={() => setConfirm('run')}><PlayCircle size={14} />Sync now</button>
      <button className="cn-btn cn-btn-ghost" disabled={busy} onClick={() => setConfirm('full')}>Full reconciliation</button>
      <button className="cn-btn cn-btn-ghost" disabled={busy} onClick={() => setConfirm('retry')}><RotateCcw size={13} />Retry failed</button>
      {confirm && <Confirm title={confirm === 'retry' ? 'Retry failed scopes and regions?' : confirm === 'full' ? 'Start a full reconciliation?' : 'Start a synchronization now?'}
        body="Runs in the background with the same lock as the scheduled run, so it cannot overlap or create duplicates. Results appear in Sync history." confirm="Start"
        onCancel={() => setConfirm(null)} onConfirm={() => { const c = confirm; setConfirm(null); void run(() => c === 'retry' ? post('/sync/retry') : post('/sync/run', { full: c === 'full' }), 'Synchronization started') }} />}
    </div>
  )
}

export function IntegrationsHome() {
  const { st, reload } = useSync()
  if (st.error) return <ErrorNote message={st.error.message} onRetry={st.reload} />
  if (!st.data) return <PageSkeleton tiles={4} />
  const d = st.data
  return (
    <>
      <PageHeader eyebrow="Integrations" title="Cloud integrations" description="Native security sources and their health. ACCESS DENIED and PARTIALLY CONFIGURED come from real API responses; they are never shown as zero findings." action={<RunButtons onDone={reload} />} />
      <SubTabs items={INTEG_TABS} />
      <div className="grid gap-4 md:grid-cols-3">{d.integrations.map((i: any) => (
        <section key={i.provider} className="cn-card cn-lift p-5" aria-label={i.label}>
          <header className="flex items-center gap-2.5"><ProviderBadge provider={i.provider} /><div><h3 className="text-sm font-semibold">{i.label}</h3><div className="text-[11px] text-ink-3">{PROVIDER_NAME[i.provider]}</div></div></header>
          <div className="mt-4"><Pill value={i.health} /></div>
          <KV items={[['Enabled', i.enabled ? 'Yes' : 'No (set in Cloud connections)'], ['Scopes in inventory', fmtInt(i.scopes_in_inventory)], ['Last success', fmtDT(i.last_success_at)],
            ['Checkpoint states', Object.entries(i.checkpoint_states).map(([k, v]) => `${k.replace(/_/g, ' ').toLowerCase()} ${v}`).join(', ') || 'none yet']]} />
        </section>))}</div>
      <Panel icon={<CalendarClock size={15} />} title="Schedule">
        <KV items={[['Daily schedule', `${d.schedule.cron} (${d.schedule.timezone})${d.schedule.enabled ? '' : ' — disabled'}`], ['Next run', fmtDT(d.next_run_at)], ['Running now', d.running ? 'Yes' : 'No'],
          ['Last run', d.last_run ? `${d.last_run.status} · ${fmtDT(d.last_run.started_at)}` : 'Never'], ['Last successful run', d.last_successful_run ? fmtDT(d.last_successful_run.finished_at) : 'Never']]} />
      </Panel>
    </>
  )
}

export function SyncDashboard() {
  const { st, reload } = useSync()
  if (st.error) return <ErrorNote message={st.error.message} onRetry={st.reload} />
  if (!st.data) return <PageSkeleton tiles={8} />
  const r = st.data.last_run, c = r?.counts ?? {}, p = c.providers ?? {}
  const pv = (k: string, f: string) => (p[k] ? p[k][f] : null)
  return (
    <>
      <PageHeader eyebrow="Integrations" title="Synchronization dashboard" description="The latest run of the daily native findings synchronization (AWS Security Hub, Azure Advisor, Google SCC), every 24 hours at 02:00 UTC."
        action={<div className="flex flex-wrap gap-2"><RunButtons onDone={reload} /><DownloadButton url="/api/v1/security/reports/sync?format=xlsx">Sync report</DownloadButton></div>} />
      <SubTabs items={INTEG_TABS} />
      {!r ? <div className="cn-card p-8 text-center text-sm text-ink-3">No synchronization has run yet. Next scheduled run: {fmtDT(st.data.next_run_at)}.</div> : (
        <>
          <div className="cn-card flex flex-wrap items-center gap-4 px-5 py-4"><Pill value={st.data.running ? 'RUNNING' : r.status} />
            <span className="text-sm">Started {fmtDT(r.started_at)} · finished {fmtDT(r.finished_at)} · duration {dur(r.duration_seconds)} · {r.trigger} · {r.mode}</span>
            <span className="ml-auto text-xs text-ink-3">Last successful {fmtDT(st.data.last_successful_run?.finished_at)} · next {fmtDT(st.data.next_run_at)}</span></div>
          <div className="cn-stagger grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
            <KpiCard icon={<CloudCog size={15} />} label="Findings retrieved" num={c.retrieved ?? 0} />
            <KpiCard icon={<CloudCog size={15} />} label="New findings" num={c.new ?? 0} note={`${fmtInt(c.new_critical_high ?? 0)} critical/high`} />
            <KpiCard icon={<CloudCog size={15} />} label="Updated" num={c.updated ?? 0} />
            <KpiCard icon={<CloudCog size={15} />} label="Natively resolved" num={c.resolved ?? 0} />
            <KpiCard icon={<CloudCog size={15} />} label="Reappeared" num={c.reappeared ?? 0} />
            <KpiCard icon={<CloudCog size={15} />} label="Permission errors" num={c.permission_errors ?? 0} note={`${fmtInt(c.throttling_errors ?? 0)} throttling · ${fmtInt(c.not_enabled ?? 0)} not enabled`} />
          </div>
          <Panel title="Coverage in this run">
            <DataGrid label="Coverage per cloud" rows={['aws', 'azure', 'gcp'].map((k, i) => ({ id: i, k }))} cols={[
              { key: 'p', label: 'Cloud', render: (x) => <b>{PROVIDER_LABEL[x.k]}</b> },
              { key: 's', label: 'Accounts / subscriptions / projects processed', render: (x) => pv(x.k, 'scopes_total') === null ? <span className="text-xs text-ink-3">not in this run</span> : `${pv(x.k, 'scopes_processed')} / ${pv(x.k, 'scopes_total')}` },
              { key: 'r', label: 'Regions / locations OK', render: (x) => pv(x.k, 'regions_processed') ?? '—' },
              { key: 'l', label: 'Locations with findings', render: (x) => <span className="text-xs">{(pv(x.k, 'locations_seen') ?? []).join(', ') || '—'}</span> },
              { key: 'f', label: 'Failed regions', render: (x) => <span className="text-xs">{(pv(x.k, 'regions_failed') ?? []).join(', ') || '—'}</span> },
              { key: 'g', label: 'Coverage gaps', render: (x) => <span className="text-xs">{(pv(x.k, 'coverage_gaps') ?? []).join('; ') || '—'}</span> },
            ]} />
          </Panel>
          {r.errors.length > 0 && <Panel title={`Errors (${r.errors.length})`}><ErrorsTable errors={r.errors} /></Panel>}
        </>
      )}
    </>
  )
}

function ErrorsTable({ errors }: { errors: any[] }) {
  return <DataGrid label="Synchronization errors" rows={errors.map((e, i) => ({ ...e, id: i }))} cols={[
    { key: 'p', label: 'Cloud', render: (e) => PROVIDER_LABEL[e.provider] ?? e.provider ?? '—' }, { key: 's', label: 'Scope', render: (e) => <ScopeName className="text-xs" provider={e.provider} id={e.scope} /> },
    { key: 'r', label: 'Region', render: (e) => <span className="text-xs">{e.region ?? '—'}</span> }, { key: 'k', label: 'Kind', render: (e) => <Pill value={e.kind === 'permission' ? 'ACCESS_DENIED' : e.kind === 'not_enabled' ? 'NOT_ENABLED' : 'ERROR'} text={e.kind} /> },
    { key: 'm', label: 'Message', render: (e) => <span className="text-xs">{e.message}</span> }]} />
}

export function SyncHistory() {
  const [status, setStatus] = useState('')
  const h = useApi<{ total: number; items: any[] }>('/sync/history', { status, page_size: 100 })
  const [open, setOpen] = useState<any | null>(null)
  return (
    <>
      <PageHeader eyebrow="Integrations" title="Synchronization history" description="Every scheduled, manual and retry run with its counts and errors." />
      <SubTabs items={INTEG_TABS} />
      <div className="cn-card p-4">
        <div className="mb-3"><Select label="Status" value={status} onChange={setStatus} options={['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'RUNNING', 'RETRYING']} /></div>
        {h.data ? <DataGrid label="Synchronization runs" rows={h.data.items} onOpen={setOpen} cols={[
          { key: 'id', label: 'Run', render: (r) => <b>#{r.id}</b> }, { key: 's', label: 'Status', render: (r) => <Pill value={r.status} /> },
          { key: 't', label: 'Trigger / mode', render: (r) => <span className="text-xs">{r.trigger} · {r.mode}{r.triggered_by ? ` · ${r.triggered_by}` : ''}</span> },
          { key: 'st', label: 'Started', render: (r) => <span className="text-xs">{fmtDT(r.started_at)}</span> }, { key: 'd', label: 'Duration', render: (r) => dur(r.duration_seconds) },
          { key: 'c', label: 'Retrieved / new / updated / resolved / reappeared', render: (r) => <span className="tabular text-xs">{['retrieved', 'new', 'updated', 'resolved', 'reappeared'].map((k) => r.counts[k] ?? 0).join(' / ')}</span> },
          { key: 'e', label: 'Errors', render: (r) => <span className="tabular">{r.errors.length}</span> }]} /> : <PageSkeleton tiles={0} />}
      </div>
      {open && <Confirm title={`Run #${open.id}: ${open.status}`} body={<div className="max-h-[60vh] overflow-auto"><pre className="text-[11px]">{JSON.stringify(open.counts, null, 1)}</pre>{open.errors.length > 0 && <ErrorsTable errors={open.errors} />}</div>}
        onCancel={() => setOpen(null)} onConfirm={() => setOpen(null)} confirm="Close" />}
    </>
  )
}

export function RegionCoverage({ failedOnly = false }: { failedOnly?: boolean }) {
  const [provider, setProvider] = useState('')
  const { reload } = useSync()
  const cov = useApi<any>(failedOnly ? '/sync/failed' : '/sync/coverage', { provider })
  const rows = failedOnly ? cov.data?.failing_partitions : cov.data?.checkpoints
  return (
    <>
      <PageHeader eyebrow="Integrations" title={failedOnly ? 'Failed jobs' : 'Region coverage'} action={failedOnly ? <RunButtons onDone={reload} /> : <DownloadButton url="/api/v1/security/reports/integration-health?format=xlsx">Integration health report</DownloadButton>}
        description={failedOnly ? 'Scopes and regions whose last attempt failed (dead-letter list). Retry runs only these partitions; repeated failures are counted.' : 'Every account / subscription / project and region the synchronization covers, with its checkpoint, last success and last error.'} />
      <SubTabs items={INTEG_TABS} />
      <div className="cn-card p-4">
        {!failedOnly && <div className="mb-3"><Select label="Cloud" value={provider} onChange={setProvider} options={['aws', 'azure', 'gcp'].map((p) => ({ value: p, label: PROVIDER_LABEL[p] }))} /></div>}
        {cov.error ? <ErrorNote message={cov.error.message} /> : !rows ? <PageSkeleton tiles={0} /> : (
          <DataGrid label="Coverage" rows={rows.map((r: any, i: number) => ({ ...r, id: i })) as any[]} empty={failedOnly ? 'No failing scopes or regions.' : 'No synchronization checkpoints yet.'} cols={[
            { key: 'p', label: 'Cloud / source', render: (r) => <span className="text-xs"><b>{PROVIDER_LABEL[r.provider]}</b> · {r.source.replace('_', ' ')}</span> },
            { key: 's', label: 'Scope', render: (r) => <ScopeName className="text-xs" provider={r.provider} id={r.scope} /> }, { key: 'r', label: 'Region', render: (r) => <span className="text-xs">{r.region}</span> },
            { key: 'st', label: 'State', render: (r) => <Pill value={r.state} /> }, { key: 'ls', label: 'Last success', render: (r) => <span className="text-xs">{fmtDT(r.last_success_at)}</span> },
            { key: 'lf', label: 'Last full', render: (r) => <span className="text-xs">{fmtDT(r.last_full_at)}</span> }, { key: 'n', label: 'Findings seen', render: (r) => r.findings_seen },
            { key: 'f', label: 'Failures', render: (r) => r.consecutive_failures }, { key: 'e', label: 'Last error', render: (r) => <span className="block max-w-[24rem] text-xs">{r.last_error ?? ''}</span> }]} />
        )}
        {!failedOnly && cov.data?.scopes_without_checkpoint?.length > 0 && (
          <div className="mt-4"><h3 className="mb-2 text-sm font-semibold">Scopes without a checkpoint ({cov.data.scopes_without_checkpoint.length})</h3>
            <DataGrid label="Scopes without checkpoint" rows={cov.data.scopes_without_checkpoint.map((r: any, i: number) => ({ ...r, id: i })) as any[]} cols={[
              { key: 'p', label: 'Cloud', render: (r) => PROVIDER_LABEL[r.provider] }, { key: 's', label: 'Scope', render: (r) => `${r.name || ''} ${r.scope}` },
              { key: 'o', label: 'Onboarding', render: (r) => r.onboarding_status }, { key: 'r', label: 'Reason', render: (r) => <span className="text-xs">{r.reason}</span> }]} /></div>
        )}
      </div>
    </>
  )
}

export function Permissions() {
  const p = useApi<any>('/sync/permissions')
  return (
    <>
      <PageHeader eyebrow="Integrations" title="Integration permissions" description="Read-only permissions each integration needs, and where the clouds currently deny access. Remediation permissions are never requested or used." />
      <SubTabs items={INTEG_TABS} />
      {p.data ? <div className="grid gap-4 xl:grid-cols-3">{p.data.items.map((i: any) => (
        <Panel key={i.provider} icon={<ProviderBadge provider={i.provider} size={22} />} title={i.label}>
          <ul className="list-disc space-y-1 pl-4 text-sm">{i.required.map((r: string) => <li key={r}>{r}</li>)}</ul>
          <div className="mt-3 text-xs font-semibold uppercase text-ink-3">Access denied ({i.access_denied.length})</div>
          {i.access_denied.length ? <ul className="mt-1 space-y-1 text-xs">{i.access_denied.map((c: any, n: number) => <li key={n}><b><ScopeName provider={c.provider} id={c.scope} /></b> {c.region}: {c.last_error}</li>)}</ul> : <div className="text-xs text-ink-3">None recorded.</div>}
          <div className="mt-3 text-xs font-semibold uppercase text-ink-3">Not enabled / partially configured ({i.not_enabled_or_partial.length})</div>
          {i.not_enabled_or_partial.length ? <ul className="mt-1 space-y-1 text-xs">{i.not_enabled_or_partial.map((c: any, n: number) => <li key={n}><b><ScopeName provider={c.provider} id={c.scope} /></b> {c.region}: {c.last_error}</li>)}</ul> : <div className="text-xs text-ink-3">None recorded.</div>}
        </Panel>))}</div> : <PageSkeleton tiles={0} />}
    </>
  )
}

export function Schedule() {
  const { st, reload } = useSync()
  const canAdmin = useCan('security:admin')
  const [cron, setCron] = useState('')
  const [enabled, setEnabled] = useState(true)
  const { run, busy } = useAction(reload)
  const rules = useApi<{ items: any[] }>('/security/notification-rules')
  const [rb, setRb] = useState(0)
  const ruleAction = useAction(() => setRb(rb + 1))
  return (
    <>
      <PageHeader eyebrow="Integrations" title="Schedule configuration" description="The security sync runs once a day in UTC (default 02:00). Times use cron syntax. Manual runs share the same lock, so they never overlap a scheduled run." />
      <SubTabs items={INTEG_TABS} />
      <Panel icon={<CalendarClock size={15} />} title="Daily security synchronization">
        {st.data && <KV items={[['Current schedule', `${st.data.schedule.cron} UTC`], ['Enabled', st.data.schedule.enabled ? 'Yes' : 'No'], ['Next run', fmtDT(st.data.next_run_at)]]} />}
        {canAdmin ? (
          <div className="mt-4 flex flex-wrap items-end gap-2">
            <label className="text-xs text-ink-3">Cron (UTC)<input className="cn-input mt-1 w-40 font-mono text-ink" placeholder="0 2 * * *" value={cron} onChange={(e) => setCron(e.target.value)} /></label>
            <label className="flex items-center gap-1.5 pb-2 text-sm"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />Enabled</label>
            <button className="cn-btn cn-btn-primary" disabled={busy || !cron} onClick={() => run(() => put('/sync/schedule', { cron, enabled }), 'Schedule saved')}>Save schedule</button>
          </div>) : <p className="mt-3 text-xs text-ink-3">Only a security administrator can change the schedule.</p>}
      </Panel>
      <Panel title="Notification rules" subtitle="Email and Google Chat through the existing integrations. Each alert is sent once (de-duplicated per item and day).">
        {rules.error ? <ErrorNote message={rules.error.message} /> : rules.data ? <DataGrid label="Notification rules" rows={rules.data.items.map((r, i) => ({ ...r, id: i }))} cols={[
          { key: 'e', label: 'Event', render: (r) => <div><b className="text-xs">{r.event_type}</b><div className="text-xs text-ink-3">{r.description}</div></div> },
          { key: 'c', label: 'Channels', render: (r) => <span className="text-xs">{r.channels}</span> }, { key: 's', label: 'State', render: (r) => <Pill value={r.enabled ? 'OK' : 'NOT_CONFIGURED'} text={r.enabled ? 'Enabled' : 'Disabled'} /> },
          { key: 'a', label: '', render: (r) => canAdmin ? <button className="cn-btn cn-btn-ghost h-7 text-xs" onClick={() => ruleAction.run(() => put(`/security/notification-rules/${r.event_type}`, { enabled: !r.enabled, channels: r.channels }), 'Rule updated').then(() => rules.reload())}>{r.enabled ? 'Disable' : 'Enable'}</button> : null }]} /> : <PageSkeleton tiles={0} />}
      </Panel>
    </>
  )
}
