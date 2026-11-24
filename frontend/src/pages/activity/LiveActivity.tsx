import { Activity, Pause, Play, Radio, Sparkles } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useCan } from '../../auth/AuthContext'
import { Panel } from '../../components/hero'
import { DataGrid, DownloadButton, Drawer, FilterPanel, KV, Pager, Pill, Section, Select, TextFilter, useAction, type Col } from '../../components/secops'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_LABEL, fmtAgo, fmtTime } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'
import Anomalies from './Anomalies'
import { ScopeName } from '../../hooks/useScopeNames'

export interface ActivityRow {
  scope_name?: string | null
  id: number; event_id: string; provider: string; scope: string; region: string | null; resource_group: string | null; resource_id: string | null; resource_type: string | null
  operation: string; event_category: string | null; actor: string | null; principal_type: string | null; source_ip: string | null; time: string; ingested_at: string | null
  provider_delay_seconds: number | null; result: string; severity: string | null; risk_score: number | null; classification: string; service: string | null; suspicious: boolean
}
interface Analysis { id: number; summary: string; evidence: string[]; risk: string; business_impact: string | null; confidence: string; recommended_action: string | null
  supporting_event_ids: number[]; affected_resources: string[]; generated_by: string; label: string; created_at: string }
const delay = (s: number | null) => (s === null ? '—' : s < 120 ? `${s}s` : s < 7200 ? `${Math.round(s / 60)}m` : `${Math.round(s / 3600)}h`)
const RESULT_TONE: Record<string, string> = { success: 'APPROVED', failure: 'High', denied: 'Critical' }

function EventDrawer({ row, onClose }: { row: ActivityRow; onClose: () => void }) {
  const canAi = useCan('ai:use')
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const inv = useApi<{ answers: { q: string; a: string; basis: string | null }[]; identity: null | { name: string | null; type: string; lifecycle: string }; related: ActivityRow[] }>(
    `/activity/events/${row.id}/investigation`)
  const { run, busy } = useAction()
  return (
    <Drawer title={row.operation} subtitle={<span className="flex gap-2"><Pill value={RESULT_TONE[row.result]} text={row.result} />{row.severity && <Pill value={row.severity} />}<span className="text-xs text-ink-3">{PROVIDER_LABEL[row.provider]} · {fmtTime(row.time)}</span></span>} onClose={onClose} width={900}>
      <Section title="Investigation">{!inv.data ? <div className="text-sm text-ink-3">Loading…</div> :
        <dl className="grid gap-2 text-sm">{inv.data.answers.map((a) => <div key={a.q} className="grid grid-cols-[230px_1fr] gap-2 border-b border-line/60 pb-1.5"><dt className="text-ink-3">{a.q}</dt>
          <dd><span className="break-words">{a.a}</span>{a.basis && <div className="text-[11px] text-ink-3">{a.basis}</div>}</dd></div>)}</dl>}</Section>
      <Section title="Event"><KV items={[['Event ID', <span className="break-all font-mono text-xs">{row.event_id}</span>], ['Account / subscription / project', row.scope], ['Region', row.region], ['Resource group', row.resource_group],
        ['Resource', <span className="break-all text-xs">{row.resource_id}</span>], ['Category', row.event_category], ['Service', row.service], ['Source IP', row.source_ip],
        ['Event time (provider)', fmtTime(row.time)], ['Ingested by LV NEXUS', fmtTime(row.ingested_at)], ['Provider + polling delay', delay(row.provider_delay_seconds)],
        ['Rule classification', row.classification.replace(/_/g, ' ').toLowerCase()], ['Risk score', row.risk_score]]} />
        <Link className="mt-2 inline-block text-xs text-accent hover:underline" to={`/audit/activities?event=${row.id}`}>Open in the audit investigation workflow</Link></Section>
      {canAi && <Section title="AI assessment" action={<button className="cn-btn cn-btn-ghost h-7 text-xs" disabled={busy} onClick={() => run(async () => { setAnalysis(await api.post<Analysis>('/ai/analyze', { subject_type: 'activity_event', subject_id: String(row.id) })) }, 'Assessment ready')}><Sparkles size={12} aria-hidden />Analyse</button>}>
        {analysis ? <div className="space-y-1 text-sm"><div className="text-[11px] font-semibold uppercase text-ink-3">{analysis.label} · {analysis.generated_by} · confidence {analysis.confidence}</div>
          <p>{analysis.summary}</p><div><Pill value={analysis.risk} /> {analysis.business_impact}</div><ul className="list-disc pl-5 text-xs">{analysis.evidence.map((e) => <li key={e}>{e}</li>)}</ul>
          <p className="text-xs"><b>Recommended (needs human approval):</b> {analysis.recommended_action}</p><p className="text-[11px] text-ink-3">Supporting events: {analysis.supporting_event_ids.join(', ') || '—'}</p></div>
          : <p className="text-xs text-ink-3">The assessment is written only from this event and related events. It is labelled as an assessment and changes nothing.</p>}</Section>}
      {inv.data && inv.data.related.length > 0 && <Section title={`Correlated activity (${inv.data.related.length}, same principal / resource / IP within 24 h)`}>
        <ul className="space-y-1 text-xs">{inv.data.related.map((r) => <li key={r.id}>{fmtTime(r.time)} · <b>{r.operation}</b> · {r.actor ?? '—'} · {r.result}</li>)}</ul></Section>}
    </Drawer>
  )
}

/** Live multi-cloud activity: Server-Sent Events push new events as soon as they are stored; history is searchable. */
export default function LiveActivity() {
  const [sp] = useSearchParams()
  const [f, setF] = useState({ provider: '', scope: '', user: '', resource: '', severity: '', category: '', result: sp.get('result') ?? '', classification: '', q: '', start: '', end: '' })
  const [live, setLive] = useState(true)
  const [page, setPage] = useState(1)
  const [rows, setRows] = useState<ActivityRow[]>([])
  const [fresh, setFresh] = useState<Set<number>>(new Set())
  const [state, setState] = useState<'connecting' | 'live' | 'paused' | 'reconnecting'>('connecting')
  const [open, setOpen] = useState<ActivityRow | null>(null)
  const params = Object.fromEntries(Object.entries(f).filter(([, v]) => v)) as Record<string, string>
  const historyMode = !!(f.start || f.end)
  const hist = useApi<{ total: number; latest_id: number | null; items: ActivityRow[] }>('/activity/events', { ...params, page, page_size: 100 })
  const fr = useApi<{ by_source: { provider: string; category: string | null; events_24h: number; last_event_time: string; last_ingested_at: string }[]
    delay: Record<string, { median_seconds: number | null; sample: number }>; jobs: Record<string, { last_run_at: string | null; last_status: string | null; schedule: string }>; limitations: string[] }>('/activity/freshness')
  const es = useRef<EventSource | null>(null)

  useEffect(() => { if (hist.data) setRows(hist.data.items) }, [hist.data])
  useEffect(() => {
    if (!live || historyMode || page !== 1 || !hist.data) { es.current?.close(); es.current = null; setState(live ? 'connecting' : 'paused'); return }
    const qs = new URLSearchParams({ ...params, after_id: String(hist.data.latest_id ?? 0) })
    const src = new EventSource(`/api/v1/activity/stream?${qs}`, { withCredentials: true })
    es.current = src
    src.onopen = () => setState('live')
    src.onerror = () => setState('reconnecting')
    src.addEventListener('activity', (m) => {
      const row = JSON.parse((m as MessageEvent).data) as ActivityRow
      setRows((r) => [row, ...r.filter((x) => x.id !== row.id)].slice(0, 300))
      setFresh((s) => new Set(s).add(row.id))
      setTimeout(() => setFresh((s) => { const n = new Set(s); n.delete(row.id); return n }), 6000)
    })
    return () => src.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, historyMode, page, hist.data?.latest_id, JSON.stringify(params)])

  if (hist.error) return <ErrorNote message={hist.error.message} onRetry={hist.reload} />
  const set = (k: keyof typeof f) => (v: string) => { setF({ ...f, [k]: v }); setPage(1) }
  const cols: Col<ActivityRow>[] = [
    { key: 't', label: 'Event time', render: (r) => <div className={`text-xs ${fresh.has(r.id) ? 'font-semibold text-accent' : ''}`}>{fresh.has(r.id) && <span className="cn-pop mr-1 rounded-full px-1.5 py-px text-[10px] font-semibold text-white" style={{ background: 'var(--accent-btn)' }}>new</span>}{fmtTime(r.time)}<div className="text-ink-3">delay {delay(r.provider_delay_seconds)}</div></div> },
    { key: 'p', label: 'Cloud / scope', render: (r) => <div className="max-w-[170px] text-xs"><div>{PROVIDER_LABEL[r.provider]}</div><div className="truncate text-ink-3"><ScopeName provider={r.provider} id={r.scope} name={r.scope_name} />{r.region ? ` · ${r.region}` : ''}</div></div> },
    { key: 'op', label: 'Operation', render: (r) => <div className="max-w-[260px]"><div className="truncate font-medium">{r.operation}</div><div className="truncate text-[11px] text-ink-3">{r.event_category ?? r.service}</div></div> },
    { key: 'who', label: 'Initiated by', render: (r) => <span className="max-w-[200px] truncate text-xs" title={r.actor ?? ''}>{r.actor ?? '—'}</span> },
    { key: 'res', label: 'Resource', render: (r) => <span className="max-w-[220px] truncate text-xs" title={r.resource_id ?? ''}>{r.resource_id?.split('/').slice(-1)[0] ?? '—'}{r.resource_group ? ` (${r.resource_group})` : ''}</span> },
    { key: 'ip', label: 'Source IP', render: (r) => <span className="text-xs">{r.source_ip ?? '—'}</span> },
    { key: 'r', label: 'Result', render: (r) => <Pill value={RESULT_TONE[r.result]} text={r.result} /> },
    { key: 's', label: 'Severity / class', render: (r) => <div className="text-xs">{r.severity ? <Pill value={r.severity} /> : '—'}<div className="text-ink-3">{r.classification.replace(/_/g, ' ').toLowerCase()}</div></div> },
  ]
  const exportQs = new URLSearchParams(params).toString()
  return (
    <>
      <PageHeader eyebrow="Live Cloud Activity" title="Live cloud activity" description="CloudTrail, Azure Activity Log, Microsoft Entra audit and sign-in logs, and Google Cloud Audit Logs in one feed. The sources are polled on a schedule: a new event appears here (highlighted) as soon as LV NEXUS collects it, after the provider's delivery delay plus the polling interval. Event time and collection time are shown separately."
        action={<div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 text-xs text-ink-3"><Radio size={13} aria-hidden style={{ color: state === 'live' ? 'var(--good)' : undefined }} />{historyMode ? 'history (date range set)' : state}</span>
          <button className="cn-btn cn-btn-ghost h-9 text-sm" onClick={() => setLive((l) => !l)} disabled={historyMode}>{live ? <><Pause size={14} aria-hidden />Pause</> : <><Play size={14} aria-hidden />Resume</>}</button>
          <DownloadButton url={`/api/v1/activity/export?format=csv&${exportQs}`}>CSV</DownloadButton><DownloadButton url={`/api/v1/activity/export?format=json&${exportQs}`}>JSON</DownloadButton>
        </div>} />
      <div className="mb-4"><Anomalies /></div>
      <FilterPanel onClear={() => { setF({ provider: '', scope: '', user: '', resource: '', severity: '', category: '', result: '', classification: '', q: '', start: '', end: '' }); setPage(1) }}>
        <Select label="Cloud" value={f.provider} onChange={set('provider')} options={[{ value: 'aws', label: 'AWS' }, { value: 'azure', label: 'Azure' }, { value: 'gcp', label: 'GCP' }]} />
        <TextFilter label="Account / subscription / project" value={f.scope} onChange={set('scope')} />
        <TextFilter label="User / principal" value={f.user} onChange={set('user')} />
        <TextFilter label="Resource" value={f.resource} onChange={set('resource')} />
        <Select label="Severity" value={f.severity} onChange={set('severity')} options={['Critical', 'High', 'Medium', 'Low']} />
        <TextFilter label="Category" value={f.category} onChange={set('category')} placeholder="e.g. Administrative, EntraSignIn" />
        <Select label="Result" value={f.result} onChange={set('result')} options={[{ value: 'success', label: 'Succeeded' }, { value: 'failure', label: 'Failed or denied' }]} />
        <Select label="Classification" value={f.classification} onChange={set('classification')} options={['NORMAL', 'AUTHORIZED', 'REVIEW_REQUIRED', 'SUSPICIOUS', 'RULE_VIOLATION'].map((x) => ({ value: x, label: x.replace(/_/g, ' ').toLowerCase() }))} />
        <label className="text-xs text-ink-3">From<input type="date" className="cn-input mt-1 block h-8" value={f.start} onChange={(e) => set('start')(e.target.value)} /></label>
        <label className="text-xs text-ink-3">To<input type="date" className="cn-input mt-1 block h-8" value={f.end} onChange={(e) => set('end')(e.target.value)} /></label>
        <TextFilter label="Search" value={f.q} onChange={set('q')} placeholder="operation, ID, IP" />
      </FilterPanel>
      {!hist.data ? <PageSkeleton tiles={0} /> : <Panel icon={<Activity size={15} />} title={`Activity (${hist.data.total} matching${rows.length > hist.data.items.length ? `, +${rows.length - hist.data.items.length} live` : ''})`}>
        <DataGrid label="Cloud activity" cols={cols} rows={rows} onOpen={setOpen} empty="No activity matches. If nothing appears at all, check Cloud Connections: audit log access may not be granted or the collection job has not run." />
        <Pager page={page} pageSize={100} total={hist.data.total} onPage={(p) => { setPage(p); if (p > 1) setLive(false) }} />
      </Panel>}
      {fr.data && <Panel title="Collection freshness" subtitle="Provider delay = collection time minus event time">
        <div className="grid gap-3 md:grid-cols-3">{['aws', 'azure', 'gcp'].map((p) => <div key={p} className="text-sm"><b>{PROVIDER_LABEL[p]}</b>: median delay {delay(fr.data!.delay[p]?.median_seconds ?? null)} ({fr.data!.delay[p]?.sample ?? 0} events sampled)
          <ul className="text-xs text-ink-3">{fr.data!.by_source.filter((s) => s.provider === p).map((s) => <li key={`${s.provider}${s.category}`}>{s.category ?? 'uncategorised'}: {s.events_24h} in 24 h, last {fmtAgo(s.last_event_time)}</li>)}</ul></div>)}</div>
        <ul className="mt-2 text-xs text-ink-3">{Object.entries(fr.data.jobs).map(([k, j]) => <li key={k}>{k}: {j.last_status ?? 'never run'} {j.last_run_at ? fmtAgo(j.last_run_at) : ''} (schedule {j.schedule})</li>)}
          {fr.data.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
      </Panel>}
      {open && <EventDrawer row={open} onClose={() => setOpen(null)} />}
    </>
  )
}
