import { AlertTriangle, Clock, FileSearch, OctagonAlert, PieChart as PieIcon, ShieldAlert, ShieldCheck, TrendingUp } from 'lucide-react'
import { useState } from 'react'
import { useCan } from '../auth/AuthContext'
import { ArcDonut, CARD_ORDER, ComparisonChart, HeroLayout, KpiCard, Panel, ProviderCard, Segmented, TrendArea } from '../components/hero'
import Modal from '../components/Modal'
import { useToast } from '../components/Toast'
import {
  Card, CollectionNotice, EmptyState, ErrorNote, ExportButton, Freshness, PageHeader, PageSkeleton, PROVIDER_LABEL, PROVIDERS, ProviderTag,
  StatusBadge, Table, fmtAgo, fmtInt, fmtTime,
} from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useFilters } from '../hooks/useFilters'
import { api, type FindingDetail, type Soc } from '../services/api'

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational']
const STATUSES = ['Pending Review', 'Under Investigation', 'Confirmed Legitimate', 'Confirmed Suspicious', 'Remediation Required', 'Escalated', 'Closed']
const SEV_COLOR: Record<string, string> = { Critical: 'var(--critical)', High: 'var(--serious)', Medium: 'var(--warning)', Low: 'var(--accent)', Informational: 'var(--neutral-mark)' }

function FindingDialog({ id, onClose, onSaved }: { id: number; onClose: () => void; onSaved: () => void }) {
  const { data, error, reload } = useApi<FindingDetail>(`/soc/findings/${id}`)
  const canReview = useCan('soc:review')
  const toast = useToast()
  const [status, setStatus] = useState('')
  const [notes, setNotes] = useState('')
  const [evidence, setEvidence] = useState('')
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    try {
      await api.post(`/soc/findings/${id}/review`, { status: status || data?.review_status, notes: notes || null, evidence_reference: evidence || null })
      toast({ kind: 'success', title: 'Review recorded', text: `Finding #${id} is now ${status || data?.review_status}. The decision is in the audit history.` })
      setNotes(''); setEvidence(''); void reload(); onSaved()
    } catch (e) {
      toast({ kind: 'error', title: 'Review not saved', text: e instanceof Error ? e.message : 'Unknown error' })
    } finally { setBusy(false) }
  }
  const events = ((data?.evidence as { events?: Record<string, string>[] })?.events ?? [])
  return (
    <Modal title={data?.title ?? 'Finding'} onClose={onClose} subtitle={data && <>{PROVIDER_LABEL[data.provider]} · {data.scope} · rule <code>{data.rule_id}</code></>}>
      {error && <ErrorNote message={error.message} />}
      {!data ? <div className="cn-skeleton h-40" /> : (
        <div className="space-y-4 text-sm">
          <div className="flex flex-wrap gap-2">
            <StatusBadge status={data.severity} /><span className="cn-chip">Risk {data.risk_score}</span><span className="cn-chip">{fmtInt(data.occurrence_count)} occurrence(s)</span>
            <span className="cn-chip"><StatusBadge status={data.review_status} /></span>
          </div>
          <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
            <div><dt className="text-xs text-ink-3">Principal</dt><dd className="break-all">{data.principal ?? 'unknown'}</dd></div>
            <div><dt className="text-xs text-ink-3">Affected resource</dt><dd className="break-all">{data.resource_id ?? 'not recorded by the source'}</dd></div>
            <div><dt className="text-xs text-ink-3">First seen / last seen</dt><dd>{fmtTime(data.first_seen_at)} / {fmtTime(data.last_seen_at)}</dd></div>
            <div><dt className="text-xs text-ink-3">Source · last updated</dt><dd>{data.source ?? "Cloud audit log"} · {fmtTime(data.updated_at ?? data.last_seen_at)}</dd></div>
          </dl>
          <div className="rounded-[var(--radius-md)] border border-line bg-surface-2 p-3">
            <div className="text-xs font-semibold uppercase tracking-wide text-ink-3">Recommended action</div>
            <p className="mt-1">{data.recommended_action ?? 'None recorded.'}</p>
            <p className="mt-2 text-xs text-ink-3">Guidance only. CloudNexus is read-only and has not changed anything in the cloud.</p>
          </div>
          {data.ai_analysis && <div className="rounded-[var(--radius-md)] border border-line p-3"><div className="text-xs font-semibold uppercase tracking-wide text-ink-3">AI-assisted analysis (advisory)</div><p className="mt-1 whitespace-pre-wrap">{data.ai_analysis}</p></div>}
          <div>
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-3">Evidence: source events</div>
            <Table dense empty="No events attached" head={['Time', 'Event', 'Outcome', 'Source IP', 'Event ID']} rows={events.map((e) => [
              <span className="whitespace-nowrap text-xs">{fmtTime(e.time)}</span>, e.event_name, e.outcome ?? '—', e.source_ip ?? '—', <code className="break-all text-[11px]">{e.event_id}</code>])} />
          </div>
          <div>
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-3">Review history (append-only)</div>
            {data.reviews.length === 0 ? <p className="text-xs text-ink-3">No analyst has reviewed this finding yet.</p> : (
              <ol className="space-y-1.5">{data.reviews.map((r) => (
                <li key={r.id} className="rounded-md bg-surface-2 px-3 py-2 text-xs"><span className="font-medium">{r.reviewer}</span> · {r.previous_status} → <span className="font-medium">{r.new_status}</span> · {fmtTime(r.created_at)}
                  {r.notes && <div className="mt-0.5 text-ink-2">{r.notes}</div>}{r.evidence_reference && <div className="text-ink-3">Evidence: {r.evidence_reference}</div>}</li>))}</ol>
            )}
          </div>
          {canReview ? (
            <div className="rounded-[var(--radius-md)] border border-line p-3">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-3">Record a review decision</div>
              <div className="grid gap-2 sm:grid-cols-2">
                <select className="cn-input" value={status || data.review_status} onChange={(e) => setStatus(e.target.value)} aria-label="New review status">{STATUSES.map((s) => <option key={s}>{s}</option>)}</select>
                <input className="cn-input" placeholder="Evidence link or ticket reference" value={evidence} onChange={(e) => setEvidence(e.target.value)} aria-label="Evidence reference" />
                <textarea className="cn-input h-20 py-2 sm:col-span-2" placeholder="Notes (required to confirm or close)" value={notes} onChange={(e) => setNotes(e.target.value)} aria-label="Review notes" />
              </div>
              <div className="mt-2 flex items-center justify-between gap-2">
                <p className="text-xs text-ink-3">Confirming as suspicious opens an incident and alerts the team. No cloud change is made.</p>
                <button className="cn-btn cn-btn-primary" onClick={save} disabled={busy}>{busy && <span className="cn-spinner" aria-hidden />}Record review</button>
              </div>
            </div>
          ) : <p className="text-xs text-ink-3">Your role can view findings but not record reviews.</p>}
        </div>
      )}
    </Modal>
  )
}

export default function SocPage() {
  const { filters: f, set, refreshKey, refresh } = useFilters()
  const [bump, setBump] = useState(0)
  const [view, setView] = useState<'trend' | 'severity' | 'cloud'>('trend')
  const [open, setOpen] = useState<number | null>(null)
  const { data, error, loading, reload } = useApi<Soc>('/dashboard/soc', { provider: f.provider, scope: f.scope, severity: f.severity, review_status: f.reviewStatus, date_from: f.dateFrom, date_to: f.dateTo }, refreshKey + bump)
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return loading ? <PageSkeleton tiles={6} /> : null
  const has = data.collection.state === 'collected'
  const posture = data.posture
  const openTotal = PROVIDERS.reduce((n, p) => n + (posture[p]?.open ?? 0), 0)
  const resolvedTotal = PROVIDERS.reduce((n, p) => n + (posture[p]?.resolved ?? 0), 0)
  const sevChart = SEVERITIES.map((s) => ({ severity: s, findings: data.by_severity[s] ?? 0 }))
  const top = (rec: Record<string, number>) => Object.entries(rec).sort((a, b) => b[1] - a[1]).slice(0, 8)
  const n = (v: number | undefined) => (has ? v ?? 0 : null)
  const sevOpen = Object.fromEntries(['Critical', 'High', 'Medium', 'Low'].map((k) => [k, PROVIDERS.reduce((x, p) => x + (posture[p]?.[k] ?? 0), 0)])) as Record<'Critical' | 'High' | 'Medium' | 'Low', number>
  const byCloud = PROVIDERS.map((p) => ({ cloud: PROVIDER_LABEL[p], Critical: posture[p]?.Critical ?? 0, High: posture[p]?.High ?? 0, Medium: posture[p]?.Medium ?? 0, Low: posture[p]?.Low ?? 0 }))
  return (
    <>
      <PageHeader eyebrow="Security operations" title="SOC posture and findings"
        description="Findings come from cloud audit logs through rule-based detection. Collection, detection and human review are separate states; only an analyst changes a review status."
        action={<Freshness at={data.collection.last_run_at} label="Audit logs collected" state={data.collection.last_status} onRefresh={refresh} />} />
      <CollectionNotice collection={data.collection} what="audit log data" />
      <HeroLayout
        kpis={<>
          <KpiCard icon={<ShieldAlert size={15} />} label="Open findings" num={n(openTotal)} note={has ? 'awaiting or under review' : 'Audit logs not collected'} />
          <KpiCard icon={<OctagonAlert size={15} />} label="Critical (open)" num={n(sevOpen.Critical)} note="highest priority" />
          <KpiCard icon={<AlertTriangle size={15} />} label="High (open)" num={n(sevOpen.High)} note={`Medium ${fmtInt(sevOpen.Medium)} · Low ${fmtInt(sevOpen.Low)}`} />
          <KpiCard icon={<Clock size={15} />} label="Pending review" num={n(data.by_review_status['Pending Review'])} note="no analyst decision yet" />
          <KpiCard icon={<ShieldCheck size={15} />} label="Resolved" num={n(resolvedTotal)} note="closed or confirmed legitimate" />
          <KpiCard icon={<FileSearch size={15} />} label="Audit events" num={n(data.events_collected)} note="collected from cloud audit logs" />
        </>}
        main={
          <Panel icon={<ShieldAlert size={15} />} title="Security findings" subtitle={view === 'trend' ? 'New findings per day (UTC)' : view === 'severity' ? 'All findings matching the filters, by severity' : 'Open findings by cloud and severity'}
            action={<Segmented label="View" value={view} onChange={setView} options={[{ value: 'trend', label: 'Daily' }, { value: 'severity', label: 'Severity' }, { value: 'cloud', label: 'By cloud' }]} />}
            bodyClass="px-5 pb-4 pt-3 xl:pr-16">
            {view === 'trend' ? <ComparisonChart key="t" data={data.trend} x="date" xFmt={(d) => d.slice(5)} series={[{ key: 'findings', label: 'New findings', color: 'var(--compare-current)' }]} empty={<EmptyState title="No trend data yet" />} />
              : view === 'severity' ? <ComparisonChart key="s" data={sevChart} x="severity" series={[{ key: 'findings', label: 'Findings', color: 'var(--compare-current)' }]} empty={<EmptyState title="No findings to chart" />} />
              : <ComparisonChart key="c" stacked data={byCloud} x="cloud" series={(['Critical', 'High', 'Medium', 'Low'] as const).map((k) => ({ key: k, label: k, color: SEV_COLOR[k] }))} empty={<EmptyState title="No open findings" />} />}
          </Panel>
        }
        trend={
          <Panel float icon={<TrendingUp size={15} />} title="Detection trend" subtitle="New findings per day; change vs 7 days earlier">
            <TrendArea points={data.trend.map((t) => ({ x: t.date, y: t.findings }))} xFmt={(x) => x} compare={(i) => (i >= 7 ? data.trend[i - 7].findings || null : null)} />
          </Panel>
        }
        donut={
          <Panel float icon={<PieIcon size={15} />} title="Security distribution" subtitle="Open findings by severity">
            <ArcDonut centre={has ? fmtInt(openTotal) : '—'} centreNote="open" emptyText={has ? 'No open findings.' : 'Audit logs not collected yet.'}
              items={(['Critical', 'High', 'Medium', 'Low'] as const).map((k) => ({ key: k, label: k, value: sevOpen[k], color: SEV_COLOR[k] }))} />
          </Panel>
        }
        bottom={CARD_ORDER.filter((p) => !f.provider || p === f.provider).map((p) => {
          const r = posture[p] ?? {}
          const open = r.open ?? 0, resolved = r.resolved ?? 0
          return (
            <ProviderCard key={p} provider={p} to="/soc" action="View findings" onAction={() => set({ provider: p, scope: '' })}
              value={has ? fmtInt(open) : '—'} valueLabel="Open findings" side={{ value: has ? fmtInt((r.Critical ?? 0) + (r.High ?? 0)) : '—', label: 'Critical + high' }}
              split={open + resolved ? { left: { label: 'Resolved', value: fmtInt(resolved) }, right: { label: 'Open', value: fmtInt(open) }, ratio: resolved / (open + resolved) } : null}
              note={!has ? 'Audit logs not collected' : open + resolved ? `${fmtInt(r.Medium ?? 0)} medium · ${fmtInt(r.Low ?? 0)} low open` : 'No findings for this cloud'} />
          )
        })}
      />

      <Card icon={<ShieldCheck size={15} />} title="Security posture by cloud" subtitle="Open findings by severity; resolved = closed or confirmed legitimate by an analyst">
        <Table head={['Cloud', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Open', 'Resolved']} empty="No findings" rows={PROVIDERS.map((p) => {
          const r = posture[p] ?? {}
          return [<ProviderTag provider={p} full />, ...['Critical', 'High', 'Medium', 'Low', 'Informational'].map((s) => (
            <span key={s} className={`tabular inline-flex items-center gap-1.5 ${r[s] ? 'font-semibold text-ink' : 'text-ink-3'}`}>
              {r[s] ? <span className="h-2 w-2 rounded-sm" style={{ background: SEV_COLOR[s] }} aria-hidden /> : null}{fmtInt(r[s] ?? 0)}</span>)),
            <span className="tabular font-semibold">{fmtInt(r.open ?? 0)}</span>, <span className="tabular text-ink-2">{fmtInt(r.resolved ?? 0)}</span>]
        })} />
      </Card>

      <Card icon={<ShieldAlert size={15} />} title="Findings" subtitle="Highest risk first. Select a finding for its evidence, remediation guidance and review."
        action={<ExportButton name="Security findings" head={['ID', 'Cloud', 'Scope', 'Severity', 'Risk', 'Title', 'Rule', 'Principal', 'Resource', 'Occurrences', 'Review status', 'Source', 'Last seen (UTC)']}
          rows={data.recent_findings.map((x) => [x.id, x.provider, x.scope, x.severity, x.risk_score, x.title, x.rule_id, x.principal, x.resource_id, x.occurrences, x.review_status, x.source, x.last_seen_at])} />}>
        <Table empty="No findings recorded" head={['Severity', 'Finding', 'Cloud / scope', 'Affected resource', 'Risk', 'Review status', 'Last updated']} rows={data.recent_findings.map((x) => [
          <StatusBadge status={x.severity} />,
          <button className="text-left font-medium text-accent hover:underline" onClick={() => setOpen(x.id)}>{x.title}<div className="text-xs font-normal text-ink-3">{x.occurrences}× · {x.principal ?? 'unknown principal'}</div></button>,
          <div className="text-xs"><ProviderTag provider={x.provider} /><div className="mt-0.5 break-all text-ink-3">{x.scope}</div></div>,
          <span className="block max-w-[18rem] truncate text-xs text-ink-2" title={x.resource_id ?? ''}>{x.resource_id ?? '—'}</span>,
          <span className="tabular">{x.risk_score}</span>, <StatusBadge status={x.review_status} />,
          <span className="whitespace-nowrap text-xs text-ink-3" title={fmtTime(x.updated_at)}>{fmtAgo(x.updated_at ?? x.last_seen_at)}</span>,
        ])} />
      </Card>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card icon={<ShieldAlert size={15} />} title="Latest security events" subtitle="Audit events, newest first, with their source log" className="xl:col-span-2">
          <Table dense maxHeight={380} empty="No audit events collected" head={['Time', 'Cloud', 'Event', 'Principal', 'Outcome', 'Detection']} rows={data.recent_events.map((e) => [
            <span className="whitespace-nowrap text-xs">{fmtTime(e.time)}</span>, <span title={e.source}><ProviderTag provider={e.provider} /></span>,
            <span className="block max-w-[20rem] truncate text-xs font-medium" title={e.event_name}>{e.event_name}</span>,
            <span className="block max-w-[14rem] truncate text-xs text-ink-2" title={e.principal ?? ''}>{e.principal ?? '—'}</span>,
            <span className="text-xs">{e.outcome ?? '—'}</span>, e.flagged ? <StatusBadge status={e.severity ?? 'Low'} /> : <span className="text-xs text-ink-3">no rule matched</span>])} />
        </Card>
        <div className="space-y-4">
          <Card icon={<ShieldAlert size={15} />} title="By account / subscription"><Table dense empty="No findings" head={['Scope', 'Findings']} rows={top(data.by_scope).map(([k, v]) => [<code className="break-all text-xs">{k}</code>, <span className="tabular">{fmtInt(v)}</span>])} /></Card>
          <Card icon={<ShieldAlert size={15} />} title="Most affected resources"><Table dense empty="No resources recorded" head={['Resource', 'Findings']} rows={data.affected_resources.map((r) => [<span className="block max-w-[14rem] truncate text-xs" title={r.resource}>{r.resource}</span>, <span className="tabular">{fmtInt(r.findings)}</span>])} /></Card>
          <Card icon={<ShieldAlert size={15} />} title="Most active principals"><Table dense empty="No audit events" head={['Principal', 'Events']} rows={top(data.by_principal).map(([k, v]) => [<span className="block max-w-[14rem] truncate text-xs" title={k}>{k}</span>, <span className="tabular">{fmtInt(v)}</span>])} /></Card>
        </div>
      </div>
      <p className="flex items-center justify-center gap-1.5 text-[11px] text-ink-3"><ShieldCheck size={12} aria-hidden />No finding is marked resolved unless an analyst recorded that decision. Generated {fmtTime(data.generated_at)}.</p>
      {open !== null && <FindingDialog id={open} onClose={() => setOpen(null)} onSaved={() => setBump((b) => b + 1)} />}
    </>
  )
}
