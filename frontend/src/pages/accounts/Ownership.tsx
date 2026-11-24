import { FileDown, History, Mail, Pencil, Save, UserRound, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useCan } from '../../auth/AuthContext'
import { download, fmtDT } from '../../components/secops'
import { useToast } from '../../components/Toast'
import { fmtUsd } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'

const FIELDS: [string, string, 'email' | 'text'][] = [
  ['spoc_name', 'Account SPOC', 'text'], ['spoc_email', 'SPOC e-mail', 'email'], ['owner_name', 'Account owner', 'text'], ['owner_email', 'Owner e-mail', 'email'],
  ['entity', 'Entity', 'text'], ['entity_lead', 'Entity lead', 'text'], ['entity_lead_email', 'Entity lead e-mail', 'email'], ['cloud_admin_email', 'Cloud admin e-mail', 'email'],
  ['finops_spoc_name', 'FinOps SPOC', 'text'], ['finops_spoc_email', 'FinOps SPOC e-mail', 'email'], ['cost_centre', 'Cost centre', 'text'], ['notes', 'Notes', 'text'],
]
interface Own {
  provider: string; scope: string; name: string | null; [k: string]: unknown
  approved_budget: { monthly_usd: number | null; budgets: { key: string; name: string; monthly_usd: number; shared: boolean }[]; source: string }
  updated_by: string | null; updated_at: string | null; history: { field: string; old: string | null; new: string | null; by: string; at: string }[]; can_edit: boolean
}

function lastMonth() {
  const d = new Date(); d.setDate(1); d.setMonth(d.getMonth() - 1)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`
}

/** Ownership of one account / subscription / project (with change history) and its monthly audit report. */
export default function OwnershipPanel({ provider, scope }: { provider: string; scope: string }) {
  const toast = useToast()
  const [bump, setBump] = useState(0)
  const { data, error } = useApi<Own>(`/accounts/ownership/${provider}/${encodeURIComponent(scope)}`, undefined, bump)
  const [edit, setEdit] = useState(false), [form, setForm] = useState<Record<string, string>>({}), [busy, setBusy] = useState(false)
  const [month, setMonth] = useState(lastMonth()), [showHist, setShowHist] = useState(false)
  const c1 = useCan('reports:export'), c2 = useCan('access:read'), c3 = useCan('vuln:read'), c4 = useCan('finops:read')
  const canReport = c1 && c2 && c3 && c4
  const canSend = useCan('automation:run')
  useEffect(() => { if (data) setForm(Object.fromEntries(FIELDS.map(([k]) => [k, (data[k] as string) ?? '']))) }, [data])
  if (error) return <p className="text-xs text-ink-3">Ownership: {error.message}</p>
  if (!data) return <div className="cn-skeleton h-24" />
  const save = async () => {
    setBusy(true)
    try { await api.put(`/accounts/ownership/${provider}/${encodeURIComponent(scope)}`, { fields: form }); toast({ kind: 'success', title: 'Ownership saved' }); setEdit(false); setBump((b) => b + 1) }
    catch (e) { toast({ kind: 'error', title: 'Not saved', text: e instanceof Error ? e.message : '' }) }
    finally { setBusy(false) }
  }
  const send = async () => {
    setBusy(true)
    try {
      const r = await api.post<{ status: string; reason?: string; to?: string }>(`/reports/audit/${provider}/${encodeURIComponent(scope)}/send?month=${month}`)
      toast({ kind: r.status === 'queued' ? 'success' : 'error', title: r.status === 'queued' ? `Queued for ${r.to}` : r.status === 'already_sent' ? 'Already sent for this month' : 'Not sent', text: r.reason })
    } catch (e) { toast({ kind: 'error', title: 'Not sent', text: e instanceof Error ? e.message : '' }) }
    finally { setBusy(false) }
  }
  const b = data.approved_budget
  const base = `/api/v1/reports/audit/${provider}/${encodeURIComponent(scope)}?month=${month}`
  return (
    <section className="rounded-2xl border border-line p-4" aria-label="Ownership and monthly audit">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h3 className="flex items-center gap-2 text-sm font-semibold"><UserRound size={15} aria-hidden />Ownership</h3>
        <div className="flex gap-2">
          <button className="cn-btn cn-btn-ghost h-8 text-xs" onClick={() => setShowHist((s) => !s)} aria-expanded={showHist}><History size={13} />History ({data.history.length})</button>
          {data.can_edit && !edit && <button className="cn-btn cn-btn-ghost h-8 text-xs" onClick={() => setEdit(true)}><Pencil size={13} />Edit</button>}
        </div>
      </div>
      {edit ? (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {FIELDS.map(([k, label, kind]) => (
            <label key={k} className="text-xs text-ink-2">{label}
              <input className="cn-input mt-1 h-8 w-full rounded-md" type={kind} value={form[k] ?? ''} onChange={(e) => setForm({ ...form, [k]: e.target.value })} autoComplete="off" /></label>))}
          <div className="col-span-full mt-1 flex gap-2">
            <button className="cn-btn cn-btn-primary" disabled={busy} onClick={save}><Save size={13} />{busy ? 'Saving…' : 'Save'}</button>
            <button className="cn-btn cn-btn-ghost" onClick={() => setEdit(false)}><X size={13} />Cancel</button>
          </div>
        </div>
      ) : (
        <dl className="grid grid-cols-1 gap-x-6 gap-y-1.5 text-xs sm:grid-cols-2">
          {FIELDS.filter(([k]) => k !== 'notes').map(([k, label]) => <div key={k} className="flex justify-between gap-2 border-b border-line/60 py-1">
            <dt className="text-ink-3">{label}</dt><dd className="truncate text-right text-ink">{(data[k] as string) || <span className="text-ink-3">not set</span>}</dd></div>)}
          <div className="flex justify-between gap-2 border-b border-line/60 py-1"><dt className="text-ink-3">Approved budget (monthly)</dt>
            <dd className="text-right text-ink" title={b.source}>{b.monthly_usd === null ? <span className="text-ink-3">no active budget</span> : `${fmtUsd(b.monthly_usd)} · ${b.budgets.map((x) => x.key).join(', ')}`}</dd></div>
        </dl>
      )}
      <p className="mt-2 text-[11px] text-ink-3">Approved budget comes from the budget tracker. {data.updated_by ? `Last changed by ${data.updated_by} ${fmtDT(data.updated_at)}.` : ''}</p>
      {showHist && <ul className="mt-2 max-h-48 space-y-1 overflow-auto rounded-lg bg-surface-2 p-2 text-[11.5px]">
        {data.history.length === 0 ? <li className="text-ink-3">No changes yet.</li> : data.history.map((h, i) => <li key={i}>
          <b>{h.field.replace(/_/g, ' ')}</b>: {h.old ?? '∅'} → {h.new ?? '∅'} <span className="text-ink-3">· {h.by} · {fmtDT(h.at)}</span></li>)}</ul>}

      {canReport && (
        <div className="mt-4 border-t border-line pt-3">
          <h3 className="mb-2 text-sm font-semibold">Monthly Cloud Security & Governance Audit</h3>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <label className="flex items-center gap-1.5 text-ink-2">Month<input type="month" className="cn-input h-8" value={month} max={lastMonth()} onChange={(e) => setMonth(e.target.value)} /></label>
            <button className="cn-btn cn-btn-ghost h-8 text-xs" onClick={() => download(base).catch((e) => toast({ kind: 'error', title: 'Download failed', text: e.message }))}><FileDown size={13} />PDF report</button>
            <button className="cn-btn cn-btn-ghost h-8 text-xs" onClick={() => download(`${base}&format=docx`).catch((e) => toast({ kind: 'error', title: 'Download failed', text: e.message }))}><FileDown size={13} />Word report</button>
            <button className="cn-btn cn-btn-ghost h-8 text-xs" onClick={() => download(`${base}&format=zip`).catch((e) => toast({ kind: 'error', title: 'Download failed', text: e.message }))}><FileDown size={13} />Report + attachments A, B, C (ZIP)</button>
            {canSend && <button className="cn-btn cn-btn-ghost h-8 text-xs" disabled={busy || !data.spoc_email} title={data.spoc_email ? `To ${data.spoc_email}` : 'Set the SPOC e-mail first'} onClick={send}><Mail size={13} />E-mail to SPOC now</button>}
          </div>
          <p className="mt-2 text-[11px] text-ink-3">Sent automatically on the 1st of every month for the previous month: to the SPOC, copy to the entity lead, owner, cloud admin and FinOps SPOC. Once per account and month.</p>
        </div>
      )}
    </section>
  )
}
