import { Bot } from 'lucide-react'
import { useState } from 'react'
import { useAuth, useCan } from '../../auth/AuthContext'
import { Confirm, Drawer, KV, Pill, Section, Timeline, fmtDT, post, useAction } from '../../components/secops'
import { ErrorNote, PROVIDER_NAME, Skeleton } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { EvidenceForm, EvidenceList } from '../vuln/FindingPanel'

/* eslint-disable @typescript-eslint/no-explicit-any */
const NEXT: Record<string, string[]> = {
  DETECTED: ['REVIEWING', 'INVESTIGATING', 'AUTHORIZED', 'ESCALATED', 'NO_ACTION_REQUIRED'],
  REVIEWING: ['INVESTIGATING', 'AUTHORIZED', 'ESCALATED', 'NO_ACTION_REQUIRED', 'CLOSED'],
  INVESTIGATING: ['ESCALATED', 'AUTHORIZED', 'NO_ACTION_REQUIRED', 'CLOSED'],
  ESCALATED: ['INVESTIGATING', 'AUTHORIZED', 'NO_ACTION_REQUIRED', 'CLOSED'],
  AUTHORIZED: ['CLOSED', 'REOPENED'], NO_ACTION_REQUIRED: ['CLOSED', 'REOPENED'], CLOSED: ['REOPENED'],
  REOPENED: ['REVIEWING', 'INVESTIGATING', 'ESCALATED', 'AUTHORIZED', 'NO_ACTION_REQUIRED', 'CLOSED'],
}
const ACTION_LABEL: Record<string, string> = { REVIEWING: 'Start review', INVESTIGATING: 'Mark investigating', AUTHORIZED: 'Mark authorized', ESCALATED: 'Escalate',
  NO_ACTION_REQUIRED: 'No action required', CLOSED: 'Close investigation', REOPENED: 'Reopen' }

export default function EventPanel({ id, onClose, onChanged, onOpenEvent }: { id: number; onClose: () => void; onChanged: () => void; onOpenEvent?: (id: number) => void }) {
  const [bump, setBump] = useState(0)
  const d = useApi<any>(`/audit/events/${id}`, undefined, bump)
  const refresh = () => { setBump((b) => b + 1); onChanged() }
  const { run, busy } = useAction(refresh)
  const me = useAuth()?.me
  const canInv = useCan('audit:investigate'), canAuth = useCan('audit:authorize')
  const [act, setAct] = useState<string | null>(null)
  const [form, setForm] = useState({ approval_reference: '', change_ticket: '', valid_until: '', escalated_to: 'Cloud Security' })
  const [note, setNote] = useState('')
  const [investigator, setInvestigator] = useState('')
  if (d.error) return <Drawer title="Activity" onClose={onClose}><ErrorNote message={d.error.message} /></Drawer>
  if (!d.data) return <Drawer title="Loading activity…" onClose={onClose}><Skeleton className="h-64" /></Drawer>
  const { event: e, history, notes, evidence, related, case: kase } = d.data
  const inv = e.investigation
  const options = e.status ? (NEXT[e.status] ?? []).filter((s) => s !== 'AUTHORIZED' || canAuth) : []
  return (
    <Drawer title={`${e.operation}`} onClose={onClose} subtitle={<span className="flex flex-wrap items-center gap-2"><Pill value={e.classification} />{e.status && <Pill value={e.status} />}
      {e.severity && <Pill value={e.severity} />}<span>{PROVIDER_NAME[e.provider]} · {fmtDT(e.time)}</span></span>}>
      {canInv && (
        <div className="mb-5 flex flex-wrap gap-2">
          {options.map((s) => <button key={s} className="cn-btn cn-btn-ghost" disabled={busy} onClick={() => setAct(s)}>{ACTION_LABEL[s]}</button>)}
          {!e.status && <button className="cn-btn cn-btn-ghost" onClick={() => setAct('FLAG')}>Flag for review (mark suspicious)</button>}
          <button className="cn-btn cn-btn-ghost" disabled={busy} onClick={() => run(() => post(`/audit/events/${id}/ai`), 'AI analysis generated (advisory)')}><Bot size={13} />AI analysis</button>
        </div>
      )}
      {!e.status && <p className="mb-4 rounded-xl bg-surface-2 px-3 py-2 text-xs text-ink-2">This activity was classified <b>{e.classification.toLowerCase().replace('_', ' ')}</b> by the rule engine. It is retained for audit and forensics and has no investigation{inv?.authorization_reference ? `; covered by ${inv.authorization_reference}` : ''}.</p>}
      <Section title="Detection">
        <KV items={[['Classification', <Pill value={e.classification} />], ['Category', e.category], ['Matched rules', inv?.matched_rules?.length ? inv.matched_rules.map((m: any) => `${m.rule_key} ${m.name} (${m.severity}, ${m.action.toLowerCase().replace('_', ' ')})`).join('; ') : 'None'],
          ['Detection explanation', inv?.explanation], ['Evaluated', fmtDT(inv?.evaluated_at)], ['Detected', fmtDT(inv?.detected_at)], ['Case', kase ? `#${kase.id} ${kase.title} (${kase.status})` : '—'],
          ['Investigator', e.investigator]]} />
      </Section>
      <Section title="Activity">
        <KV items={[['Event ID', <code className="break-all text-xs">{e.event_id}</code>], ['Cloud', PROVIDER_NAME[e.provider]], ['Account / subscription / project', e.scope], ['Region', e.region],
          ['Time (UTC)', fmtDT(e.time)], ['Actor', e.actor], ['Source IP', e.source_ip], ['User agent', e.user_agent], ['API operation', e.operation], ['Result', e.result],
          ['Resource', <span className="break-all">{e.resource_id ?? '—'}</span>], ['Resource type', e.resource_type], ['Error code', e.error_code]]} />
        {e.request && <details className="mt-2"><summary className="cursor-pointer text-xs text-accent">Request / new configuration</summary><pre className="mt-1 max-h-60 overflow-auto rounded-xl bg-surface-2 p-2 text-[11px]">{JSON.stringify(e.request, null, 2)}</pre></details>}
        {e.response && <details className="mt-1"><summary className="cursor-pointer text-xs text-accent">Response</summary><pre className="mt-1 max-h-60 overflow-auto rounded-xl bg-surface-2 p-2 text-[11px]">{JSON.stringify(e.response, null, 2)}</pre></details>}
        {e.authentication && <details className="mt-1"><summary className="cursor-pointer text-xs text-accent">Authentication context</summary><pre className="mt-1 max-h-60 overflow-auto rounded-xl bg-surface-2 p-2 text-[11px]">{JSON.stringify(e.authentication, null, 2)}</pre></details>}
      </Section>
      {inv?.authorized_by && <Section title="Authorization"><KV items={[['Authorized by', inv.authorized_by], ['Reason', inv.authorization_reason], ['Approval reference', inv.authorization_reference],
        ['Change / ticket', inv.change_ticket], ['Valid until', fmtDT(inv.authorized_until)], ['Authorization rule', inv.authorization_rule_id ? `#${inv.authorization_rule_id}` : 'This event only']]} /></Section>}
      {inv?.closure_reason && <Section title="Closure"><p className="text-sm">{inv.closure_reason}</p></Section>}
      {inv?.ai_analysis && <Section title="AI analysis (advisory, verify before acting)"><div className="space-y-2 rounded-xl border border-line bg-surface-2 p-3 text-sm">
        {Object.entries(inv.ai_analysis).filter(([k]) => !['advisory', 'generated_at', 'model_provider', 'note'].includes(k)).map(([k, v]) => (
          <div key={k}><div className="text-[11px] font-semibold uppercase text-ink-3">{k.replace(/_/g, ' ')}</div><div className="whitespace-pre-wrap">{Array.isArray(v) ? (v as string[]).map((x, i) => <div key={i}>• {x}</div>) : String(v ?? '—')}</div></div>))}
        <div className="text-[11px] text-ink-3">{String(inv.ai_analysis.note)}</div></div></Section>}
      {canInv && e.status && <Section title="Investigator"><div className="flex gap-2">
        <input className="cn-input w-64" placeholder="investigator@company.com" value={investigator} onChange={(x) => setInvestigator(x.target.value)} aria-label="Investigator" />
        <button className="cn-btn cn-btn-ghost" disabled={!investigator} onClick={() => run(() => post(`/audit/events/${id}/assign`, { investigator }), 'Investigator assigned')}>Assign</button>
        {me && <button className="cn-btn cn-btn-ghost" onClick={() => run(() => post(`/audit/events/${id}/assign`, { investigator: me.email }), 'Assigned to you')}>Assign to me</button>}</div></Section>}
      <Section title={`Investigation notes (${notes.length})`}>
        <div className="space-y-2">{notes.map((n: any, i: number) => <div key={i} className="rounded-xl bg-surface-2 p-3 text-sm"><div className="text-[11px] text-ink-3">{n.author} · {fmtDT(n.at)}</div><div className="whitespace-pre-wrap">{n.body}</div></div>)}</div>
        {canInv && <div className="mt-2 flex flex-col gap-2"><textarea className="cn-input h-20 w-full py-2" style={{ borderRadius: 12 }} value={note} onChange={(x) => setNote(x.target.value)} aria-label="Note" />
          <button className="cn-btn cn-btn-primary w-fit" disabled={!note.trim()} onClick={async () => { if (await run(() => post(`/audit/events/${id}/notes`, { body: note }), 'Note added')) setNote('') }}>Add note</button></div>}
      </Section>
      <Section title={`Evidence (${evidence.length})`}><EvidenceList items={evidence} />{canInv && <EvidenceForm path={`/audit/events/${id}/evidence`} onSaved={refresh} />}</Section>
      <Section title="Investigation history"><Timeline items={history.map((h: any) => ({ at: h.at, title: `${h.from ?? '—'} → ${h.to}`, body: `${h.actor}${h.reason ? ` — ${h.reason}` : ''}${h.details && Object.keys(h.details).length ? ` (${Object.entries(h.details).map(([k, v]) => `${k}: ${v}`).join(', ')})` : ''}`, tone: h.to }))} /></Section>
      <Section title={`Related events, ±24 h (${related.length})`}>
        <Timeline items={related.map((r: any) => ({ at: r.time, tone: r.classification, title: <button className="text-left hover:text-accent" onClick={() => onOpenEvent?.(r.id)}>{r.operation}</button>,
          body: `${r.actor ?? '—'} · ${r.source_ip ?? '—'} · ${r.classification.toLowerCase().replace('_', ' ')}${r.resource_id ? ` · ${r.resource_id}` : ''}` }))} />
      </Section>
      {act && <Confirm title={act === 'FLAG' ? 'Flag for review' : ACTION_LABEL[act]} needReason={act !== 'REVIEWING' && act !== 'INVESTIGATING' && act !== 'ESCALATED'}
        body={act === 'AUTHORIZED' ? 'Applies to this activity only. Future activities need an approved authorization rule.' : act === 'FLAG' ? 'Adds this activity to the investigation queue without declaring an incident.' : 'Recorded in the investigation history.'}
        extra={act === 'AUTHORIZED' ? (
          <div className="mt-3 grid gap-2 sm:grid-cols-3">
            <input className="cn-input" placeholder="Approval reference (required)" value={form.approval_reference} onChange={(x) => setForm({ ...form, approval_reference: x.target.value })} aria-label="Approval reference" />
            <input className="cn-input" placeholder="Change / ticket ID" value={form.change_ticket} onChange={(x) => setForm({ ...form, change_ticket: x.target.value })} aria-label="Change or ticket" />
            <input className="cn-input" type="date" value={form.valid_until} onChange={(x) => setForm({ ...form, valid_until: x.target.value })} aria-label="Valid until" />
          </div>) : act === 'ESCALATED' ? (
          <select className="cn-input mt-3" value={form.escalated_to} onChange={(x) => setForm({ ...form, escalated_to: x.target.value })} aria-label="Escalate to">
            <option>Cloud Security</option><option>Cloud Governance</option><option>CISO</option></select>) : undefined}
        onCancel={() => setAct(null)} onConfirm={(reason) => {
          const a = act; setAct(null)
          if (a === 'FLAG') return void run(() => post(`/audit/events/${id}/flag`, { reason }), 'Added to the investigation queue')
          void run(() => post(`/audit/events/${id}/status`, { status: a, reason: reason || undefined, ...(a === 'AUTHORIZED' ? { approval_reference: form.approval_reference, change_ticket: form.change_ticket || undefined, valid_until: form.valid_until || undefined } : {}),
            ...(a === 'ESCALATED' ? { escalated_to: form.escalated_to } : {}) }), ACTION_LABEL[a])
        }} />}
    </Drawer>
  )
}
