import { ClipboardCheck, FileUp, Landmark, Plus, Rocket } from 'lucide-react'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useCan, useMe } from '../../auth/AuthContext'
import { Panel, SubTabs } from '../../components/hero'
import { DataGrid, Drawer, KV, Pill, Section, useAction, type Col } from '../../components/secops'
import { ErrorNote, ExportButton, PageHeader, PageSkeleton, PROVIDER_LABEL, fmtTime } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { api, type Scope } from '../../services/api'

export const GOV_TABS = [{ to: '/governance', label: 'Overview' }, { to: '/governance/compliance', label: 'Frameworks and controls' }, { to: '/governance/onboarding', label: 'Onboarding governance' }]
interface Fw { id: number; key: string; name: string; version: string | null; source: string; owner: string | null; controls: number; assessed: number; passed: number; failed: number; not_assessed: number; pass_rate: number | null }
interface Ctl { id: number; control_id: string; title: string; status: string; failing_findings: number; assessed_findings: number; excepted: number; evidence: number; owner: string | null; review_date: string | null; review_overdue: boolean; basis: string | null }
const TONE: Record<string, string> = { PASS: 'APPROVED', FAIL: 'Critical', NOT_ASSESSED: 'NOT_CONFIGURED' }

function ControlPanel({ c, onClose, onChanged }: { c: Ctl; onClose: () => void; onChanged: () => void }) {
  const canManage = useCan('governance:manage')
  const [bump, setBump] = useState(0)
  const ev = useApi<{ items: { id: number; kind: string; reference: string; notes: string | null; added_by: string; at: string }[] }>(`/governance/controls/${c.id}/evidence`, undefined, bump)
  const { run, busy } = useAction(() => { setBump((b) => b + 1); onChanged() })
  const [f, setF] = useState({ kind: 'link', reference: '', notes: '', owner: c.owner ?? '', review_date: c.review_date ?? '', manual_status: '' })
  return (
    <Drawer title={`${c.control_id} · ${c.title}`} subtitle={<Pill value={TONE[c.status]} text={c.status.replace('_', ' ').toLowerCase()} />} onClose={onClose}>
      <Section title="Status"><KV items={[['Basis', c.basis ?? 'No mapped findings and no evidence'], ['Failing findings', c.failing_findings], ['Assessed findings', c.assessed_findings], ['With approved exception', c.excepted], ['Owner', c.owner], ['Review date', c.review_date ?? '—']]} /></Section>
      <Section title={`Evidence (${ev.data?.items.length ?? 0})`}>
        <ul className="space-y-1 text-sm">{(ev.data?.items ?? []).map((e) => <li key={e.id}><b>{e.kind}</b> · <span className="break-all">{e.reference}</span><div className="text-[11px] text-ink-3">{e.added_by} · {fmtTime(e.at)}{e.notes ? ` · ${e.notes}` : ''}</div></li>)}</ul>
        {canManage && <form className="mt-2 grid gap-2 sm:grid-cols-[120px_1fr]" onSubmit={(e) => { e.preventDefault(); run(() => api.post(`/governance/controls/${c.id}/evidence`, { kind: f.kind, reference: f.reference, notes: f.notes || null }), 'Evidence added') }}>
          <select className="cn-input" aria-label="Kind" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>{['link', 'document', 'finding_export', 'screenshot', 'note'].map((k) => <option key={k}>{k}</option>)}</select>
          <input className="cn-input" required minLength={3} placeholder="Reference (URL, document ID)" aria-label="Reference" value={f.reference} onChange={(e) => setF({ ...f, reference: e.target.value })} />
          <input className="cn-input sm:col-span-2" placeholder="Notes" aria-label="Notes" value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} />
          <button className="cn-btn cn-btn-primary h-8 w-fit text-xs" disabled={busy}>Add evidence</button></form>}
      </Section>
      {canManage && <Section title="Ownership and manual assessment">
        <div className="grid gap-2 sm:grid-cols-3">
          <input className="cn-input" placeholder="Owner" aria-label="Owner" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} />
          <input className="cn-input" type="date" aria-label="Review date" value={f.review_date} onChange={(e) => setF({ ...f, review_date: e.target.value })} />
          <select className="cn-input" aria-label="Manual status" value={f.manual_status} onChange={(e) => setF({ ...f, manual_status: e.target.value })}><option value="">Manual status (needs evidence)…</option>{['PASS', 'FAIL', 'NOT_ASSESSED'].map((s) => <option key={s}>{s}</option>)}</select>
        </div>
        <button className="cn-btn cn-btn-ghost mt-2 h-8 text-xs" disabled={busy} onClick={() => run(() => api.patch(`/governance/controls/${c.id}`, { owner: f.owner || null, review_date: f.review_date || null, manual_status: f.manual_status || null }), 'Control updated')}>Save</button>
        <p className="mt-1 text-[11px] text-ink-3">A manual status counts only for controls without mapped findings, and only when evidence is attached.</p>
      </Section>}
    </Drawer>
  )
}

export function Compliance() {
  const canManage = useCan('governance:manage')
  const [params, setParams] = useSearchParams()
  const [bump, setBump] = useState(0)
  const [importing, setImporting] = useState(false)
  const [imp, setImp] = useState({ key: '', name: '', version: '', csv_text: '' })
  const [ctl, setCtl] = useState<Ctl | null>(null)
  const list = useApi<{ items: Fw[]; disclaimer: string }>('/governance/frameworks', undefined, bump)
  const fwId = Number(params.get('framework')) || list.data?.items[0]?.id || null
  const detail = useApi<Fw & { control_list: Ctl[] }>(fwId ? `/governance/frameworks/${fwId}` : null, undefined, bump)
  const { run, busy } = useAction(() => { setBump((b) => b + 1); setImporting(false) })
  if (list.error) return <ErrorNote message={list.error.message} onRetry={list.reload} />
  if (!list.data) return <PageSkeleton tiles={4} />
  const cols: Col<Ctl>[] = [
    { key: 'id', label: 'Control', render: (c) => <span className="font-mono text-xs">{c.control_id}</span> }, { key: 't', label: 'Title', render: (c) => <span className="line-clamp-2 max-w-md">{c.title}</span> },
    { key: 's', label: 'Status', render: (c) => <Pill value={TONE[c.status]} text={c.status.replace('_', ' ').toLowerCase()} /> },
    { key: 'f', label: 'Failing / assessed', render: (c) => <span className="tabular">{c.failing_findings} / {c.assessed_findings}</span> }, { key: 'e', label: 'Evidence', render: (c) => c.evidence },
    { key: 'o', label: 'Owner', render: (c) => c.owner ?? '—' }, { key: 'r', label: 'Review', render: (c) => <span style={{ color: c.review_overdue ? 'var(--critical)' : undefined }}>{c.review_date ?? '—'}</span> },
  ]
  return (
    <>
      <PageHeader eyebrow="Governance & Compliance" title="Frameworks and controls" description={list.data.disclaimer}
        action={canManage ? <button className="cn-btn cn-btn-ghost h-9 text-sm" onClick={() => setImporting(true)}><FileUp size={14} aria-hidden />Import a framework (CSV)</button> : undefined} />
      <SubTabs items={GOV_TABS} />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">{list.data.items.map((f) => (
        <button key={f.id} onClick={() => setParams({ framework: String(f.id) })} className={`cn-card cn-lift px-4 py-3 text-left ${fwId === f.id ? 'ring-2 ring-[var(--accent)]' : ''}`}>
          <div className="flex items-center justify-between gap-2"><span className="truncate text-sm font-semibold">{f.name}</span><span className="text-[10.5px] uppercase text-ink-3">{f.source}</span></div>
          <div className="tabular mt-1 text-[22px] font-semibold">{f.pass_rate === null ? '—' : `${f.pass_rate}%`}</div>
          <div className="text-[11px] text-ink-3">{f.passed} pass · {f.failed} fail · {f.not_assessed} not assessed · pass rate, not a certification</div>
        </button>))}
        {list.data.items.length === 0 && <div className="text-sm text-ink-3 md:col-span-2 xl:col-span-4">No frameworks yet. Native frameworks appear once security findings with compliance standards are synchronized; others can be imported.</div>}
      </div>
      {detail.data && <Panel icon={<Landmark size={15} />} title={`${detail.data.name}: ${detail.data.controls} controls`}
        action={<ExportButton name={`Controls ${detail.data.name}`} head={['Control', 'Title', 'Status', 'Failing findings', 'Assessed findings', 'Excepted', 'Evidence', 'Owner', 'Review date']} rows={detail.data.control_list.map((c) => [c.control_id, c.title, c.status, c.failing_findings, c.assessed_findings, c.excepted, c.evidence, c.owner, c.review_date])} />}>
        <DataGrid label="Controls" cols={cols} rows={detail.data.control_list} onOpen={setCtl} empty="No controls." /></Panel>}
      {ctl && <ControlPanel c={ctl} onClose={() => setCtl(null)} onChanged={() => setBump((b) => b + 1)} />}
      {importing && <Drawer title="Import a framework" subtitle="Your organisation supplies the control text (e.g. ISO 27001, SOC 2, internal standards)." onClose={() => setImporting(false)}>
        <form className="grid gap-2" onSubmit={(e) => { e.preventDefault(); run(() => api.post('/governance/frameworks', { ...imp, version: imp.version || null }), 'Framework imported') }}>
          <input className="cn-input" required pattern="[a-z0-9\-]+" placeholder="key (e.g. iso-27001-2022)" aria-label="Key" value={imp.key} onChange={(e) => setImp({ ...imp, key: e.target.value })} />
          <input className="cn-input" required placeholder="Name" aria-label="Name" value={imp.name} onChange={(e) => setImp({ ...imp, name: e.target.value })} />
          <input className="cn-input" placeholder="Version" aria-label="Version" value={imp.version} onChange={(e) => setImp({ ...imp, version: e.target.value })} />
          <p className="text-xs text-ink-3">CSV columns: control_id, title, description, mapped_control_ids (semicolon list of native control IDs), mapped_keywords (semicolon list), owner, review_date (YYYY-MM-DD).</p>
          <input type="file" accept=".csv" aria-label="CSV file" onChange={async (e) => { const f = e.target.files?.[0]; if (f) setImp({ ...imp, csv_text: await f.text() }) }} />
          <textarea className="cn-input min-h-32 font-mono text-xs" aria-label="CSV" value={imp.csv_text} onChange={(e) => setImp({ ...imp, csv_text: e.target.value })} />
          <button className="cn-btn cn-btn-primary h-9 w-fit text-sm" disabled={busy}>Import</button>
        </form></Drawer>}
    </>
  )
}

interface Stage { key: string; label: string; permission: string; status: string; by?: string; at?: string; evidence?: string; notes?: string; checks?: Record<string, boolean> }
interface Onb { id: number; request_key: string; title: string; business_purpose: string; provider: string; environment: string; internet_facing: boolean; estimated_monthly_cost_usd: number | null
  scope_external_id: string | null; requester: string; stages: Stage[]; current_stage: number; waiting_for: string | null; status: string; created_at: string }

export function OnboardingGovernance() {
  const me = useMe()
  const canRequest = useCan('access:request')
  const [bump, setBump] = useState(0)
  const [creating, setCreating] = useState(false)
  const [open, setOpen] = useState<Onb | null>(null)
  const [f, setF] = useState({ title: '', business_purpose: '', provider: 'azure', environment: 'Production', internet_facing: false, estimated_monthly_cost_usd: '' })
  const [d, setD] = useState({ evidence: '', notes: '', scope_external_id: '', checks: {} as Record<string, boolean> })
  const list = useApi<{ items: Onb[] }>('/governance/onboarding', undefined, bump)
  const scopes = useApi<{ items: Scope[] }>(open ? '/inventory/scopes' : null)
  const { run, busy } = useAction(() => { setBump((b) => b + 1); setCreating(false); setOpen(null) })
  if (list.error) return <ErrorNote message={list.error.message} onRetry={list.reload} />
  if (!list.data) return <PageSkeleton tiles={0} />
  const cols: Col<Onb>[] = [
    { key: 'k', label: 'ID', render: (o) => <span className="font-mono text-xs">{o.request_key}</span> }, { key: 't', label: 'Request', render: (o) => <div><div className="font-medium">{o.title}</div><div className="text-[11px] text-ink-3">{PROVIDER_LABEL[o.provider]} · {o.environment}{o.internet_facing ? ' · internet-facing' : ''}</div></div> },
    { key: 'p', label: 'Progress', render: (o) => <div className="flex gap-0.5">{o.stages.map((s) => <span key={s.key} title={`${s.label}: ${s.status}`} className="h-2 w-4 rounded-sm" style={{ background: s.status === 'APPROVED' ? 'var(--success,#0ca30c)' : s.status === 'REJECTED' ? 'var(--critical)' : 'var(--line)' }} />)}</div> },
    { key: 'w', label: 'Waiting for', render: (o) => o.waiting_for ?? '—' }, { key: 's', label: 'Status', render: (o) => <Pill value={o.status === 'APPROVED_FOR_PRODUCTION' ? 'APPROVED' : o.status === 'REJECTED' ? 'REJECTED' : 'PENDING'} text={o.status.replace(/_/g, ' ').toLowerCase()} /> },
    { key: 'r', label: 'Requester', render: (o) => o.requester },
  ]
  const st = open && open.status === 'IN_PROGRESS' ? open.stages[open.current_stage] : null
  const canAct = !!st && !!me?.permissions.includes(st.permission)
  return (
    <>
      <PageHeader eyebrow="Governance & Compliance" title="Cloud onboarding governance" description="Requirement → manager → cost → Finance → governance → architecture & security → setup → deployment → VAPT → production. Production approval is blocked while Critical or High findings are open without an approved exception."
        action={canRequest ? <button className="cn-btn cn-btn-primary h-9 text-sm" onClick={() => setCreating(true)}><Plus size={14} aria-hidden />New onboarding request</button> : undefined} />
      <SubTabs items={GOV_TABS} />
      <Panel icon={<Rocket size={15} />} title={`Requests (${list.data.items.length})`}><DataGrid label="Onboarding requests" cols={cols} rows={list.data.items} onOpen={(o) => { setOpen(o); setD({ evidence: '', notes: '', scope_external_id: '', checks: {} }) }} empty="No onboarding requests." /></Panel>
      {creating && <Drawer title="New cloud onboarding request" onClose={() => setCreating(false)}>
        <form className="grid gap-2" onSubmit={(e) => { e.preventDefault(); run(() => api.post('/governance/onboarding', { ...f, estimated_monthly_cost_usd: f.estimated_monthly_cost_usd ? Number(f.estimated_monthly_cost_usd) : null }), 'Request created') }}>
          <input className="cn-input" required minLength={3} placeholder="Title" aria-label="Title" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} />
          <textarea className="cn-input min-h-16" required minLength={10} placeholder="Business purpose" aria-label="Business purpose" value={f.business_purpose} onChange={(e) => setF({ ...f, business_purpose: e.target.value })} />
          <div className="grid grid-cols-3 gap-2">
            <select className="cn-input" aria-label="Cloud" value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value })}>{['azure', 'aws', 'gcp'].map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p]}</option>)}</select>
            <select className="cn-input" aria-label="Environment" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })}>{['Production', 'UAT', 'Development', 'POC', 'Sandbox'].map((x) => <option key={x}>{x}</option>)}</select>
            <input className="cn-input" type="number" min={0} placeholder="Est. USD / month" aria-label="Estimated monthly cost" value={f.estimated_monthly_cost_usd} onChange={(e) => setF({ ...f, estimated_monthly_cost_usd: e.target.value })} />
          </div>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.internet_facing} onChange={(e) => setF({ ...f, internet_facing: e.target.checked })} />Internet-facing (adds WAF, DAST, domain, TLS, network exposure and logging checks)</label>
          <button className="cn-btn cn-btn-primary h-9 w-fit text-sm" disabled={busy}>Create</button>
        </form></Drawer>}
      {open && <Drawer title={`${open.request_key} · ${open.title}`} subtitle={open.waiting_for ? `Waiting for: ${open.waiting_for}` : open.status.replace(/_/g, ' ').toLowerCase()} onClose={() => setOpen(null)}>
        <Section title="Stages"><ol className="space-y-1 text-sm">{open.stages.map((s, i) => <li key={s.key} className="flex justify-between gap-2"><span>{i + 1}. {s.label}</span><span className="text-xs text-ink-3">{s.status.toLowerCase()}{s.by ? ` · ${s.by}` : ''}{s.evidence ? ` · ${s.evidence}` : ''}</span></li>)}</ol></Section>
        {st && <Section title={`Decide: ${st.label}`}>
          {!canAct ? <p className="text-xs text-ink-3">This stage needs the permission {st.permission}.</p> : <>
            {st.key === 'setup' && <select className="cn-input mb-2 w-full" aria-label="Account" value={d.scope_external_id} onChange={(e) => setD({ ...d, scope_external_id: e.target.value })}><option value="">Link the account / subscription / project…</option>{(scopes.data?.items ?? []).filter((s) => s.provider === open.provider).map((s) => <option key={s.external_id} value={s.external_id}>{s.name || s.external_id}</option>)}</select>}
            {st.checks && <div className="mb-2 grid grid-cols-2 gap-1 text-sm">{Object.keys(st.checks).map((c) => <label key={c} className="flex items-center gap-1"><input type="checkbox" checked={!!d.checks[c]} onChange={(e) => setD({ ...d, checks: { ...d.checks, [c]: e.target.checked } })} />{c}</label>)}</div>}
            <input className="cn-input mb-2 w-full" placeholder="Evidence reference (required for VAPT and production)" aria-label="Evidence" value={d.evidence} onChange={(e) => setD({ ...d, evidence: e.target.value })} />
            <textarea className="cn-input min-h-14 w-full" placeholder="Notes (required to reject)" aria-label="Notes" value={d.notes} onChange={(e) => setD({ ...d, notes: e.target.value })} />
            <div className="mt-2 flex gap-2"><button className="cn-btn cn-btn-primary h-8 text-xs" disabled={busy} onClick={() => run(() => api.post(`/governance/onboarding/${open.id}/stage`, { decision: 'APPROVED', evidence: d.evidence || null, notes: d.notes || null, scope_external_id: d.scope_external_id || null, checks: st.checks ? d.checks : null }), 'Stage approved')}>Approve stage</button>
              <button className="cn-btn cn-btn-ghost h-8 text-xs" disabled={busy} onClick={() => run(() => api.post(`/governance/onboarding/${open.id}/stage`, { decision: 'REJECTED', notes: d.notes }), 'Rejected')}>Reject</button></div></>}
        </Section>}
        <Section title="Request"><KV items={[['Purpose', open.business_purpose], ['Estimated cost', open.estimated_monthly_cost_usd ? `${open.estimated_monthly_cost_usd} USD / month` : '—'], ['Linked scope', open.scope_external_id], ['Requester', open.requester]]} /></Section>
      </Drawer>}
      <ClipboardCheck className="hidden" aria-hidden />
    </>
  )
}
