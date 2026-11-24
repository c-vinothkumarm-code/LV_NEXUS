import { useState } from 'react'
import { useAuth, useCan } from '../../auth/AuthContext'
import { Panel, SubTabs } from '../../components/hero'
import { Confirm, DataGrid, Drawer, DownloadButton, KV, Pill, Section, Select, Timeline, fmtDT, post, put, useAction } from '../../components/secops'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_LABEL, Skeleton } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { AUDIT_TABS } from '../vuln/tabs'
import EventPanel from './EventPanel'
import { EvidenceForm, EvidenceList } from '../vuln/FindingPanel'
import { ScopeName } from '../../hooks/useScopeNames'

/* eslint-disable @typescript-eslint/no-explicit-any */
const CASE_NEXT: Record<string, string[]> = {
  PROPOSED: ['DETECTED', 'DISMISSED'], DETECTED: ['REVIEWING', 'INVESTIGATING', 'AUTHORIZED', 'ESCALATED', 'NO_ACTION_REQUIRED'],
  REVIEWING: ['INVESTIGATING', 'AUTHORIZED', 'ESCALATED', 'NO_ACTION_REQUIRED', 'CLOSED'], INVESTIGATING: ['ESCALATED', 'AUTHORIZED', 'NO_ACTION_REQUIRED', 'CLOSED'],
  ESCALATED: ['INVESTIGATING', 'AUTHORIZED', 'NO_ACTION_REQUIRED', 'CLOSED'], AUTHORIZED: ['CLOSED', 'REOPENED'], NO_ACTION_REQUIRED: ['CLOSED', 'REOPENED'],
  CLOSED: ['REOPENED'], REOPENED: ['REVIEWING', 'INVESTIGATING', 'ESCALATED', 'AUTHORIZED', 'NO_ACTION_REQUIRED', 'CLOSED'], DISMISSED: [],
}

const DISPOSITION_LABEL: Record<string, string> = {
  suspicious: 'Suspicious activity (under review)', confirmed_malicious: 'Confirmed malicious activity', expected_legitimate: 'Expected / legitimate activity',
  approved_admin: 'Approved administrative activity', false_positive: 'False positive', insufficient_evidence: 'Insufficient evidence',
}

function RuleDetail({ r, cats, onClose, onEdit }: { r: any; cats: Record<string, string>; onClose: () => void; onEdit?: () => void }) {
  return (
    <Drawer title={`${r.rule_key} · ${r.name}`} onClose={onClose} subtitle={<span className="flex flex-wrap gap-2"><Pill value={r.severity} /><Pill value={r.action} />
      <span>{r.soc_category ? `${r.soc_category}. ${cats[r.soc_category]}` : 'Uncategorised'}</span></span>}>
      {onEdit && <div className="mb-4"><button className="cn-btn cn-btn-primary" onClick={onEdit}>Edit rule</button></div>}
      <Section title="What it detects"><p className="text-[13px]">{r.description || '—'}</p></Section>
      <Section title="MITRE ATT&CK">{(r.mitre ?? []).length ? <ul className="space-y-1 text-[13px]">{r.mitre.map((m: any) => <li key={m.id}><a className="text-accent hover:underline" href={m.url} target="_blank" rel="noreferrer">{m.id}</a> {m.name}</li>)}</ul> : <p className="text-[13px] text-ink-3">Not mapped</p>}</Section>
      <Section title="Recommended investigation"><p className="whitespace-pre-line text-[13px]">{r.investigation_steps || '—'}</p></Section>
      <Section title="Recommended remediation"><p className="text-[13px]">{r.remediation || '—'}</p></Section>
      <Section title="Detection logic"><KV items={[['Cloud', r.provider ? PROVIDER_LABEL[r.provider] : 'Any'], ['Event types', (r.event_types ?? []).join(', ') || 'pattern-based (see conditions)'],
        ['Required event fields', (r.required_fields ?? []).join(', ')], ['Threshold', r.threshold_count > 1 ? `${r.threshold_count} matches in ${r.threshold_window_minutes} min by the same ${r.group_by}` : 'every match'],
        ['Change window', r.change_window ? 'fires only outside the approved change window' : '—'], ['Exclusions', `${(r.exclusions ?? []).length} (provider-managed identities, LV NEXUS reader)`],
        ['Data source', r.data_status === 'needs data source' ? `Needs ${r.missing_data.join(', ')} – not collected, so this rule cannot fire yet` : r.data_status],
        ['Last triggered', r.last_triggered_at ? fmtDT(r.last_triggered_at) : 'never'], ['Matching events', String(r.match_count ?? 0)], ['Version', `v${r.version} · ${r.updated_by ?? ''}`]]} /></Section>
      <Section title="Conditions"><pre className="max-h-72 overflow-auto rounded-xl bg-surface-2 p-3 text-[11.5px]">{JSON.stringify(r.conditions, null, 2)}</pre></Section>
    </Drawer>
  )
}

function CasePanel({ id, onClose, onChanged }: { id: number; onClose: () => void; onChanged: () => void }) {
  const [bump, setBump] = useState(0)
  const d = useApi<any>(`/audit/cases/${id}`, undefined, bump)
  const refresh = () => { setBump((b) => b + 1); onChanged() }
  const { run } = useAction(refresh)
  const canInv = useCan('audit:investigate'), canAuth = useCan('audit:authorize')
  const me = useAuth()?.me
  const [act, setAct] = useState<string | null>(null)
  const [ref, setRef] = useState('')
  const [esc, setEsc] = useState('Cloud Security')
  const [note, setNote] = useState('')
  const [event, setEvent] = useState<number | null>(null)
  const [disp, setDisp] = useState(''), [dispNote, setDispNote] = useState('')
  if (!d.data) return <Drawer title="Investigation case" onClose={onClose}>{d.error ? <ErrorNote message={d.error.message} /> : <Skeleton className="h-64" />}</Drawer>
  const { case: c, timeline, notes, evidence } = d.data
  return (
    <Drawer title={`${c.incident_id ?? `Case #${c.id}`}: ${c.title}`} onClose={onClose} subtitle={<span className="flex flex-wrap gap-2"><Pill value={c.status} /><Pill value={c.risk} />{c.confidence && <span>confidence {c.confidence.toLowerCase()}</span>}<span>{c.origin.replace('_', ' ')}{c.validated_by ? ` · validated by ${c.validated_by}` : ''}</span></span>}>
      {canInv && <div className="mb-4 flex flex-wrap gap-2">{(CASE_NEXT[c.status] ?? []).filter((s) => s !== 'AUTHORIZED' || canAuth).map((s) => (
        <button key={s} className="cn-btn cn-btn-ghost" onClick={() => setAct(s)}>{s === 'DETECTED' && c.status === 'PROPOSED' ? 'Validate (open case)' : s.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (x) => x.toUpperCase())}</button>))}
        {me && <button className="cn-btn cn-btn-ghost" onClick={() => run(() => post(`/audit/cases/${id}/assign`, { owner: me.email }), 'Case assigned to you')}>Assign to me</button>}</div>}
      {c.status === 'PROPOSED' && <p className="mb-4 rounded-xl bg-surface-2 px-3 py-2 text-xs">Correlation is a recommendation. It becomes an investigation only when an analyst validates it.</p>}
      {c.summary && <Section title="Investigation summary"><p className="whitespace-pre-line rounded-xl bg-surface-2 px-3 py-2 text-[13px]">{c.summary}</p></Section>}
      <Section title="Analyst conclusion" action={<a className="cn-btn cn-btn-ghost h-7 text-xs" href={`/api/v1/audit/cases/${id}/evidence.csv`}>Download raw events (CSV)</a>}>
        <p className="mb-2 text-[13px]"><b>{c.disposition_label ?? 'Not set'}</b>{c.notified_at && <span className="ml-2 text-[11.5px] text-ink-3">SOC e-mail queued {fmtDT(c.notified_at)}</span>}</p>
        {canInv && <div className="grid gap-2 sm:grid-cols-[220px_1fr_auto]">
          <select className="cn-input" value={disp} onChange={(x) => setDisp(x.target.value)} aria-label="Disposition"><option value="">Record a conclusion…</option>
            {Object.entries(DISPOSITION_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
          <input className="cn-input" value={dispNote} onChange={(x) => setDispNote(x.target.value)} placeholder="Reason / evidence (required)" aria-label="Disposition reason" />
          <button className="cn-btn cn-btn-primary" disabled={!disp || dispNote.trim().length < 3} onClick={async () => { if (await run(() => post(`/audit/cases/${id}/disposition`, { disposition: disp, notes: dispNote }), 'Conclusion recorded')) { setDisp(''); setDispNote('') } }}>Save</button></div>}
        <p className="mt-1 text-[11px] text-ink-3">A detection is not a confirmed incident until an analyst records “Confirmed malicious activity”. The conclusion is separate from the workflow status and is kept in the case history.</p>
      </Section>
      <Section title="Case"><KV items={[['Actor / correlation', `${c.actor ?? '—'} (${c.correlation_type ?? '—'})`], ['Cloud / scope', <>{PROVIDER_LABEL[c.provider] ?? '—'} · <ScopeName provider={c.provider} id={c.scope} name={c.scope_name} /></>],
        ['Risk assessment', c.risk_assessment], ['Owner', c.owner], ['Affected resources', (c.resources ?? []).join(', ') || '—'], ['Related findings', (c.finding_ids ?? []).map((x: number) => `#${x}`).join(', ') || '—'],
        ['First / last event', `${fmtDT(c.first_event_at)} – ${fmtDT(c.last_event_at)}`], ['Outcome', c.outcome], ['Closure reason', c.closure_reason]]} /></Section>
      <Section title={`Investigation timeline (${timeline.length} events)`}>
        <Timeline items={timeline.map((e: any) => ({ at: e.time, tone: e.classification, title: <button className="text-left hover:text-accent" onClick={() => setEvent(e.id)}>{e.operation}</button>,
          body: `${e.actor ?? '—'} · ${e.source_ip ?? '—'} · ${e.resource_id ?? ''} · ${e.rules.join(', ')}` }))} />
      </Section>
      <Section title={`Notes and status changes (${notes.length})`}>
        <Timeline items={notes.map((n: any) => ({ at: n.at, title: n.author, body: n.body }))} />
        {canInv && <div className="mt-2 flex gap-2"><input className="cn-input flex-1" value={note} onChange={(x) => setNote(x.target.value)} aria-label="Case note" placeholder="Add an investigation note" />
          <button className="cn-btn cn-btn-ghost" disabled={!note.trim()} onClick={async () => { if (await run(() => post(`/audit/cases/${id}/notes`, { body: note }), 'Note added')) setNote('') }}>Add</button></div>}
      </Section>
      <Section title="Supporting evidence"><EvidenceList items={evidence} />{canInv && <EvidenceForm path={`/audit/cases/${id}/evidence`} onSaved={refresh} />}</Section>
      {act && <Confirm title={`Case: ${act.replace(/_/g, ' ').toLowerCase()}`} needReason={['CLOSED', 'NO_ACTION_REQUIRED', 'REOPENED', 'DISMISSED', 'AUTHORIZED'].includes(act)} reasonLabel="Reason / outcome"
        extra={act === 'AUTHORIZED' ? <input className="cn-input mt-3 w-full" placeholder="Approval reference (required)" value={ref} onChange={(x) => setRef(x.target.value)} aria-label="Approval reference" />
          : act === 'ESCALATED' ? <select className="cn-input mt-3" value={esc} onChange={(x) => setEsc(x.target.value)} aria-label="Escalate to"><option>Cloud Security</option><option>Cloud Governance</option><option>CISO</option></select> : undefined}
        onCancel={() => setAct(null)} onConfirm={(reason) => { const a = act; setAct(null); void run(() => post(`/audit/cases/${id}/status`, { status: a, reason: reason || undefined, outcome: reason || undefined, approval_reference: ref || undefined, escalated_to: a === 'ESCALATED' ? esc : undefined }), 'Case updated') }} />}
      {event && <EventPanel id={event} onClose={() => setEvent(null)} onChanged={refresh} onOpenEvent={setEvent} />}
    </Drawer>
  )
}

export function Cases() {
  const [status, setStatus] = useState('')
  const [bump, setBump] = useState(0)
  const [open, setOpen] = useState<number | null>(null)
  const data = useApi<{ total: number; items: any[] }>('/audit/cases', { status, page_size: 200 }, bump)
  return (
    <>
      <PageHeader eyebrow="Live Cloud Activity" title="Investigation history" description="Investigation cases opened by detection rules (related flagged events grouped by rule and actor) and correlation proposals awaiting validation."
        action={<div className="flex gap-2"><DownloadButton url="/api/v1/security/reports/open-investigations?format=xlsx">Open investigations</DownloadButton><DownloadButton url="/api/v1/security/reports/closed-investigations?format=xlsx">Closed investigations</DownloadButton></div>} />
      <SubTabs items={AUDIT_TABS} />
      <div className="cn-card p-4">
        <div className="mb-3"><Select label="Status" value={status} onChange={setStatus} options={['PROPOSED', 'DETECTED', 'REVIEWING', 'INVESTIGATING', 'ESCALATED', 'AUTHORIZED', 'NO_ACTION_REQUIRED', 'CLOSED', 'REOPENED', 'DISMISSED']} /></div>
        {data.error ? <ErrorNote message={data.error.message} /> : !data.data ? <PageSkeleton tiles={0} /> : (
          <DataGrid label="Investigation cases" rows={data.data.items} onOpen={(r) => setOpen(r.id)} empty="No investigation cases." cols={[
            { key: 'id', label: 'Case', render: (r) => <b>#{r.id}</b> },
            { key: 't', label: 'Title', render: (r) => <span className="font-medium text-accent">{r.title}</span> },
            { key: 's', label: 'Status', render: (r) => <Pill value={r.status} /> }, { key: 'r', label: 'Risk', render: (r) => <Pill value={r.risk} /> },
            { key: 'a', label: 'Actor', render: (r) => <span className="block max-w-[14rem] truncate text-xs">{r.actor}</span> },
            { key: 'e', label: 'Events', render: (r) => <span className="tabular">{r.event_ids.length}</span> },
            { key: 'o', label: 'Owner', render: (r) => <span className="text-xs">{r.owner ?? '—'}</span> },
            { key: 'l', label: 'Last event', render: (r) => <span className="text-xs">{fmtDT(r.last_event_at)}</span> },
          ]} />
        )}
      </div>
      {open && <CasePanel id={open} onClose={() => setOpen(null)} onChanged={() => setBump((b) => b + 1)} />}
    </>
  )
}

const EMPTY_RULE = { rule_key: '', name: '', description: '', provider: '', category: '', action: 'REVIEW_REQUIRED', severity: 'Medium', threshold_count: 1, threshold_window_minutes: 0,
  group_by: 'principal', change_window: null, approved_change_reference: '', create_case: true, notify: false, owner: '', enabled: true,
  conditions: { all: [{ field: 'operation', op: 'eq', value: 'ExampleOperation' }] } }

export function Rules() {
  const [bump, setBump] = useState(0)
  const rules = useApi<{ items: any[]; categories: Record<string, string>; coverage: Record<string, number>; data_sources: Record<string, boolean> }>('/audit/rules', undefined, bump)
  const [cat, setCat] = useState(''), [detail, setDetail] = useState<any | null>(null)
  const auths = useApi<{ items: any[] }>('/audit/authorization-rules', undefined, bump)
  const canEdit = useCan('audit:rules'), canAuthorize = useCan('audit:authorize')
  const [edit, setEdit] = useState<any | null>(null)
  const [text, setText] = useState('')
  const [test, setTest] = useState<any | null>(null)
  const [hist, setHist] = useState<any[] | null>(null)
  const [auth, setAuth] = useState({ name: '', actor: '', operation: '', provider: '', scope_external_id: '', resource_prefix: '', reason: '', approval_reference: '', valid_until: '' })
  const { run, busy } = useAction(() => { setBump((b) => b + 1) })
  const openEditor = (r: any) => { setEdit(r); setText(JSON.stringify(r.conditions, null, 2)); setTest(null) }
  const body = () => ({ ...edit, provider: edit.provider || null, conditions: JSON.parse(text), change_window: edit.change_window || null,
    mitre: (edit.mitre ?? []).map((m: any) => (typeof m === 'string' ? m : m.id)) })
  const shown = (rules.data?.items ?? []).filter((r) => !cat || r.soc_category === cat)
  return (
    <>
      <PageHeader eyebrow="Live Cloud Activity" title="SOC detection rule library" description="Rules in seven SOC categories (A–G) with MITRE ATT&CK mapping, investigation steps and remediation. Provider-managed identities are excluded. Administrator-defined rules. Conditions combine event attributes with all (AND), any (OR) and not (NOT). Each rule decides what a match means: rule violation (case), suspicious (case when the threshold is reached) or review required (queue only). Every change is versioned." />
      <SubTabs items={AUDIT_TABS} />
      {rules.data && <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7" role="group" aria-label="SOC categories">
        {Object.entries(rules.data.categories).map(([k, v]) => <button key={k} type="button" aria-pressed={cat === k} onClick={() => setCat(cat === k ? '' : k)}
          className={`cn-card px-3 py-2 text-left transition hover:-translate-y-0.5 ${cat === k ? 'ring-2 ring-accent' : ''}`}>
          <div className="text-[11px] font-semibold text-accent">{k}</div><div className="text-[12px] leading-tight">{v}</div>
          <div className="tabular mt-1 text-[18px] font-semibold">{rules.data!.coverage[k] ?? 0}<span className="ml-1 text-[11px] font-normal text-ink-3">enabled</span></div></button>)}</div>}
      <Panel title={`Rules (${shown.length}${cat ? ` in ${cat}` : ''})`} subtitle="Click a rule for its MITRE mapping, investigation steps, remediation and data source." action={canEdit && <button className="cn-btn cn-btn-primary" onClick={() => openEditor({ ...EMPTY_RULE })}>New rule</button>}>
        {rules.data ? <DataGrid label="Detection rules" rows={shown} onOpen={setDetail} cols={[
          { key: 'k', label: 'Rule ID', render: (r) => <b>{r.rule_key}</b> }, { key: 'n', label: 'Name', render: (r) => <div className="max-w-[22rem]"><div>{r.name}</div><div className="text-[11px] text-ink-3">{r.soc_category ? `${r.soc_category}. ${rules.data!.categories[r.soc_category]}` : ''}</div></div> },
          { key: 'm', label: 'MITRE', render: (r) => <span className="text-[11.5px]">{(r.mitre ?? []).map((m: any) => m.id).join(', ') || '—'}</span> },
          { key: 'p', label: 'Cloud', render: (r) => <span className="text-xs">{r.provider ? PROVIDER_LABEL[r.provider] : 'Any'}</span> },
          { key: 'a', label: 'Action', render: (r) => <Pill value={r.action} /> }, { key: 's', label: 'Severity', render: (r) => <Pill value={r.severity} /> },
          { key: 't', label: 'Threshold', render: (r) => <span className="text-xs">{r.threshold_count > 1 ? `${r.threshold_count} in ${r.threshold_window_minutes} min by ${r.group_by}` : 'every match'}{r.change_window ? ' · outside change window' : ''}</span> },
          { key: 'e', label: 'State', render: (r) => <span className="text-xs">{r.data_status === 'needs data source' ? <span style={{ color: '#b54708' }}>Needs data source</span> : r.enabled ? 'Enabled' : 'Disabled'} · v{r.version}{r.notify ? ' · e-mails SOC' : ''}</span> },
          { key: 'l', label: 'Last triggered', render: (r) => <span className="text-xs">{r.last_triggered_at ? fmtDT(r.last_triggered_at) : 'never'}{r.match_count ? ` · ${r.match_count}` : ''}</span> },
          { key: 'h', label: '', render: (r) => <button className="cn-btn cn-btn-ghost h-7 text-xs" onClick={async () => setHist((await (await fetch(`/api/v1/audit/rules/${r.id}/history`, { credentials: 'include' })).json()).items)}>History</button> },
        ]} /> : <PageSkeleton tiles={0} />}
      </Panel>
      {detail && <RuleDetail r={detail} cats={rules.data?.categories ?? {}} onClose={() => setDetail(null)} onEdit={canEdit ? () => { const r = detail; setDetail(null); openEditor(r) } : undefined} />}
      <Panel title="Authorization rules" subtitle="Explicitly approved, scoped authorizations: one actor, one operation, optional scope and resource prefix, limited validity. Matching events are classified AUTHORIZED. Nothing is authorized automatically from past decisions.">
        {auths.data && <DataGrid label="Authorization rules" rows={auths.data.items} empty="No authorization rules." cols={[
          { key: 'n', label: 'Name', render: (r) => r.name }, { key: 'a', label: 'Actor / operation', render: (r) => <span className="text-xs">{r.actor}<div className="text-ink-3">{r.operation}</div></span> },
          { key: 's', label: 'Scope', render: (r) => <span className="text-xs">{r.provider || r.scope || r.resource_prefix ? <>{[r.provider && PROVIDER_LABEL[r.provider]].filter(Boolean).join('')}{r.scope && <> · <ScopeName provider={r.provider} id={r.scope} /></>}{r.resource_prefix && ` · ${r.resource_prefix}`}</> : 'Any'}</span> },
          { key: 'r', label: 'Approval', render: (r) => <span className="text-xs">{r.approval_reference} · {r.approved_by}</span> },
          { key: 'v', label: 'Valid until', render: (r) => <span className="text-xs">{fmtDT(r.valid_until)}{r.enabled ? '' : ' (disabled)'}</span> },
          { key: 'x', label: '', render: (r) => canEdit && r.enabled ? <button className="cn-btn cn-btn-ghost h-7 text-xs" onClick={() => run(() => post(`/audit/authorization-rules/${r.id}/disable`), 'Rule disabled')}>Disable</button> : null },
        ]} />}
        {canEdit && canAuthorize && (
          <div className="mt-3 grid gap-2 md:grid-cols-3">
            {(['name', 'actor', 'operation', 'provider', 'scope_external_id', 'resource_prefix', 'approval_reference'] as const).map((k) => (
              <input key={k} className="cn-input" placeholder={k.replace(/_/g, ' ')} value={auth[k]} onChange={(e) => setAuth({ ...auth, [k]: e.target.value })} aria-label={k} />))}
            <input className="cn-input" type="date" value={auth.valid_until} onChange={(e) => setAuth({ ...auth, valid_until: e.target.value })} aria-label="Valid until" />
            <input className="cn-input md:col-span-2" placeholder="Reason (approved change)" value={auth.reason} onChange={(e) => setAuth({ ...auth, reason: e.target.value })} aria-label="Reason" />
            <button className="cn-btn cn-btn-primary" disabled={busy} onClick={() => run(() => post('/audit/authorization-rules', { ...auth, provider: auth.provider || null, scope_external_id: auth.scope_external_id || null, resource_prefix: auth.resource_prefix || null, valid_until: `${auth.valid_until}T23:59:59Z` }), 'Authorization rule created')}>Create authorization rule</button>
          </div>
        )}
      </Panel>
      {edit && (
        <Drawer title={edit.id ? `Edit ${edit.rule_key}` : 'New detection rule'} onClose={() => setEdit(null)} width={820}>
          <div className="grid gap-3 sm:grid-cols-2">
            {(['rule_key', 'name', 'description', 'category', 'owner', 'approved_change_reference'] as const).map((k) => (
              <label key={k} className="text-xs text-ink-3">{k.replace(/_/g, ' ')}<input className="cn-input mt-1 w-full text-sm text-ink" value={edit[k] ?? ''} onChange={(e) => setEdit({ ...edit, [k]: e.target.value })} disabled={k === 'rule_key' && !!edit.id} /></label>))}
            <Select label="Cloud" value={edit.provider ?? ''} onChange={(v) => setEdit({ ...edit, provider: v })} options={['aws', 'azure', 'gcp']} all="Any cloud" />
            <Select label="Action on match" value={edit.action} onChange={(v) => setEdit({ ...edit, action: v || 'REVIEW_REQUIRED' })} options={['RULE_VIOLATION', 'SUSPICIOUS', 'REVIEW_REQUIRED']} all="Choose" />
            <Select label="Severity" value={edit.severity} onChange={(v) => setEdit({ ...edit, severity: v || 'Medium' })} options={['Critical', 'High', 'Medium', 'Low', 'Informational']} all="Choose" />
            <Select label="Group / count by" value={edit.group_by} onChange={(v) => setEdit({ ...edit, group_by: v || 'principal' })} options={['principal', 'source_ip', 'resource_id', 'scope']} all="principal" />
            <label className="text-xs text-ink-3">Frequency threshold (events)<input type="number" min={1} className="cn-input mt-1 w-full text-ink" value={edit.threshold_count} onChange={(e) => setEdit({ ...edit, threshold_count: Number(e.target.value) })} /></label>
            <label className="text-xs text-ink-3">Time window (minutes)<input type="number" min={0} className="cn-input mt-1 w-full text-ink" value={edit.threshold_window_minutes} onChange={(e) => setEdit({ ...edit, threshold_window_minutes: Number(e.target.value) })} /></label>
            <label className="text-xs text-ink-3 sm:col-span-2">Approved change window (JSON, optional; the rule fires only outside it) e.g. {'{"days":[0,1,2,3,4],"start":"09:00","end":"19:00","tz":"Asia/Kolkata"}'}
              <input className="cn-input mt-1 w-full font-mono text-xs text-ink" value={edit.change_window ? JSON.stringify(edit.change_window) : ''} onChange={(e) => { try { setEdit({ ...edit, change_window: e.target.value ? JSON.parse(e.target.value) : null }) } catch { /* typing */ } }} /></label>
            <div className="flex flex-wrap gap-4 text-sm sm:col-span-2">
              {(['create_case', 'notify', 'enabled'] as const).map((k) => <label key={k} className="flex items-center gap-1.5"><input type="checkbox" checked={!!edit[k]} onChange={(e) => setEdit({ ...edit, [k]: e.target.checked })} />{k.replace('_', ' ')}</label>)}
            </div>
            <label className="text-xs text-ink-3 sm:col-span-2">Conditions (fields: provider, scope, region, operation, actor, source_ip, resource_id, resource_type, category, result, user_agent, hour_utc, weekday_utc, raw_text, raw.&lt;path&gt;, actor_new_operation; operators: eq, neq, in, not_in, contains, contains_any, startswith, endswith, regex, cidr, not_cidr, exists, gt, gte, lt, lte)
              <textarea className="cn-input mt-1 h-56 w-full py-2 font-mono text-xs text-ink" style={{ borderRadius: 12 }} value={text} onChange={(e) => setText(e.target.value)} /></label>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            <button className="cn-btn cn-btn-ghost" disabled={busy} onClick={() => run(async () => setTest(await post('/audit/rules/test', { rule: body(), days: 7 })), 'Dry run finished (nothing saved)')}>Test against last 7 days</button>
            <button className="cn-btn cn-btn-primary" disabled={busy} onClick={async () => { if (await run(() => edit.id ? put(`/audit/rules/${edit.id}`, body()) : post('/audit/rules', body()), 'Rule saved (new version recorded)')) setEdit(null) }}>Save rule</button>
          </div>
          {test && <Section title={`Dry run: ${test.matches} of ${test.evaluated} events would match`}>
            <Timeline items={test.sample.map((s: any) => ({ at: s.time, title: s.operation, body: s.explanation }))} /></Section>}
        </Drawer>
      )}
      {hist && <Drawer title="Rule change history" onClose={() => setHist(null)}><Timeline items={hist.map((h) => ({ at: h.at, title: `v${h.version} ${h.action} by ${h.actor}`, body: <pre className="mt-1 max-h-40 overflow-auto text-[10.5px]">{JSON.stringify(h.snapshot, null, 1)}</pre> }))} /></Drawer>}
    </>
  )
}

