import { Bot, FileDown, Paperclip, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { useAuth, useCan } from '../../auth/AuthContext'
import { Confirm, Drawer, DownloadButton, KV, Pill, Section, Timeline, download, fileToBase64, fmtDT, post, useAction } from '../../components/secops'
import { ErrorNote, PROVIDER_NAME, Skeleton } from '../../components/ui'
import { useApi } from '../../hooks/useApi'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Detail = { finding: any; history: any[]; comments: any[]; evidence: any[]; exceptions: any[]; approvals: any[]; related_findings: any[]; related_cases: any[] }

const NEXT: Record<string, { to: string; label: string; reason?: boolean }[]> = {
  OPEN: [{ to: 'UNDER_REVIEW', label: 'Mark under review' }, { to: 'RESOLVED', label: 'Mark resolved', reason: true }, { to: 'FALSE_POSITIVE', label: 'False positive', reason: true }],
  UNDER_REVIEW: [{ to: 'OPEN', label: 'Mark open' }, { to: 'RESOLVED', label: 'Mark resolved', reason: true }, { to: 'FALSE_POSITIVE', label: 'False positive', reason: true }],
  REOPENED: [{ to: 'UNDER_REVIEW', label: 'Mark under review' }, { to: 'OPEN', label: 'Mark open' }, { to: 'RESOLVED', label: 'Mark resolved', reason: true }],
  RESOLVED: [{ to: 'REOPENED', label: 'Reopen', reason: true }],
  FALSE_POSITIVE: [{ to: 'REOPENED', label: 'Reopen', reason: true }],
  EXCEPTION: [],
}

export default function FindingPanel({ id, onClose, onChanged }: { id: number; onClose: () => void; onChanged: () => void }) {
  const [bump, setBump] = useState(0)
  const d = useApi<Detail>(`/security/findings/${id}`, undefined, bump)
  const refresh = () => { setBump((b) => b + 1); onChanged() }
  const { run, busy } = useAction(refresh)
  const me = useAuth()?.me
  const canTriage = useCan('vuln:triage'), canRemediate = useCan('vuln:remediate'), canRequest = useCan('exception:request'), canApprove = useCan('exception:approve')
  const [confirm, setConfirm] = useState<{ to: string; label: string; reason?: boolean } | null>(null)
  const [comment, setComment] = useState({ kind: 'comment', body: '' })
  const [owner, setOwner] = useState('')
  const [excForm, setExcForm] = useState(false)
  const [decide, setDecide] = useState<{ id: number; approve: boolean } | null>(null)
  if (d.error) return <Drawer title="Finding" onClose={onClose}><ErrorNote message={d.error.message} /></Drawer>
  if (!d.data) return <Drawer title="Loading finding…" onClose={onClose}><Skeleton className="h-64" /></Drawer>
  const { finding: f, history, comments, evidence, exceptions, approvals } = d.data
  const pending = exceptions.find((e) => e.status === 'PENDING_APPROVAL')
  const active = exceptions.find((e) => e.status === 'ACTIVE')

  return (
    <Drawer title={f.title} onClose={onClose} subtitle={<span className="flex flex-wrap items-center gap-2"><Pill value={f.severity} /><Pill value={f.internal_status} />
      <span>Native: <b className="text-ink">{f.native_state}</b>{f.native_workflow_status ? ` (${f.native_workflow_status})` : ''}</span>
      {f.overdue && <Pill value="EXPIRED" text="SLA overdue" />}{f.needs_reassessment && <Pill value="REOPENED" text="Needs reassessment" />}</span>}>
      {/* actions */}
      <div className="mb-5 flex flex-wrap gap-2">
        {canTriage && (NEXT[f.internal_status] ?? []).map((a) => (
          <button key={a.to} className="cn-btn cn-btn-ghost" disabled={busy} onClick={() => a.reason ? setConfirm(a) : run(() => post(`/security/findings/${id}/status`, { status: a.to }), a.label)}>{a.label}</button>
        ))}
        {canRequest && !pending && !active && !['RESOLVED', 'FALSE_POSITIVE'].includes(f.internal_status) &&
          <button className="cn-btn cn-btn-ghost" onClick={() => setExcForm(true)}><ShieldCheck size={13} />Request exception</button>}
        {(canTriage || canRemediate) && <button className="cn-btn cn-btn-ghost" disabled={busy} onClick={() => run(() => post(`/security/findings/${id}/ai`), 'AI analysis generated (advisory)')}><Bot size={13} />AI analysis</button>}
        <button className="cn-btn cn-btn-ghost" onClick={() => download(`/api/v1/security/findings/${id}/export`)}><FileDown size={13} />Export</button>
      </div>

      {(() => {
        const threat = /threat|guardduty|alert|intrusion|malware|anomal|suspicious|ttp|event_threat/i.test(`${f.category ?? ''} ${f.source} ${f.title}`)
        return (
          <div className="mb-4 rounded-xl border px-3 py-2 text-[12.5px]" role="note"
            style={{ borderColor: `color-mix(in srgb, ${threat ? 'var(--serious)' : 'var(--low)'} 40%, var(--line))`, background: `color-mix(in srgb, ${threat ? 'var(--serious)' : 'var(--low)'} 7%, transparent)` }}>
            <b className="text-ink">{threat ? 'Threat detection: possible malicious activity' : 'Potential risk (posture / configuration)'}</b>
            <span className="text-ink-2"> · {threat ? 'Reported by the provider\'s threat detection. It is not a confirmed compromise until an analyst investigates and confirms it.'
              : 'A weakness the provider found in configuration or software. It is a risk, not evidence that the resource was compromised.'}</span>
          </div>
        )
      })()}
      <Section title="Finding">
        <KV items={[['Native finding ID', <code className="break-all text-xs">{f.native_id}</code>], ['Cloud', `${PROVIDER_NAME[f.provider] ?? f.provider} · ${f.source.replace('_', ' ')}`],
          ['Account / subscription / project', f.scope], ['Organization / management group / folder', [f.organization_id, f.parent_id].filter(Boolean).join(' / ') || '—'],
          ['Region / location', f.region], ['Resource', <span className="break-all">{f.resource_name ?? '—'}<div className="text-[11px] text-ink-3">{f.resource_id}</div></span>],
          ['Resource type', f.resource_type], ['Resource group', f.resource_group], ['Category', f.category], ['Control / standard', [f.control_id, f.compliance_standard].filter(Boolean).join(' · ') || '—'],
          ['First detected', fmtDT(f.first_observed_at)], ['Last observed', fmtDT(f.last_observed_at)], ['Last synchronized', fmtDT(f.last_synced_at)],
          ['SLA due', `${fmtDT(f.sla_due_at)}${f.sla_paused ? ' (paused by exception)' : ''}`], ['Owner', f.owner], ['Security analyst', f.analyst]]} />
        {f.description && <p className="mt-3 whitespace-pre-wrap text-sm text-ink-2">{f.description}</p>}
      </Section>

      <Section title="Remediation guidance (from the provider)">
        <p className="whitespace-pre-wrap text-sm">{f.remediation || 'The provider did not supply remediation text.'}</p>
        {f.remediation_url && <a className="mt-1 inline-block text-xs text-accent hover:underline" href={f.remediation_url} target="_blank" rel="noreferrer noopener">Provider documentation</a>}
      </Section>

      {f.ai_analysis && (
        <Section title="AI analysis (advisory, verify before acting)">
          <div className="space-y-2 rounded-xl border border-line bg-surface-2 p-3 text-sm">
            {Object.entries(f.ai_analysis).filter(([k]) => !['advisory', 'generated_at', 'model_provider', 'note'].includes(k)).map(([k, v]) => (
              <div key={k}><div className="text-[11px] font-semibold uppercase text-ink-3">{k.replace(/_/g, ' ')}</div>
                <div className="whitespace-pre-wrap">{Array.isArray(v) ? (v as string[]).map((x, i) => <div key={i}>• {x}</div>) : String(v ?? '—')}</div></div>
            ))}
            <div className="text-[11px] text-ink-3">{String(f.ai_analysis.note)} Generated {fmtDT(f.ai_analysis.generated_at)}.</div>
          </div>
        </Section>
      )}

      {canTriage && (
        <Section title="Assignment">
          <div className="flex flex-wrap items-end gap-2">
            <input className="cn-input w-64" placeholder="owner@company.com" value={owner} onChange={(e) => setOwner(e.target.value)} aria-label="Assignee email" />
            <button className="cn-btn cn-btn-ghost" disabled={busy || !owner} onClick={() => run(() => post(`/security/findings/${id}/assign`, { field: 'owner', value: owner }), 'Owner assigned')}>Assign owner</button>
            <button className="cn-btn cn-btn-ghost" disabled={busy || !owner} onClick={() => run(() => post(`/security/findings/${id}/assign`, { field: 'analyst', value: owner }), 'Analyst assigned')}>Assign analyst</button>
            {me && <button className="cn-btn cn-btn-ghost" disabled={busy} onClick={() => run(() => post(`/security/findings/${id}/assign`, { field: 'analyst', value: me.email }), 'Assigned to you')}>Assign to me</button>}
          </div>
        </Section>
      )}

      <Section title={`Exceptions (${exceptions.length})`}>
        {exceptions.length === 0 ? <div className="text-xs text-ink-3">No exception requested.</div> : exceptions.map((e) => (
          <div key={e.id} className="mb-2 rounded-xl border border-line p-3 text-sm">
            <div className="flex flex-wrap items-center justify-between gap-2"><b>Exception #{e.id}</b><Pill value={e.status} /></div>
            <KV items={[['Justification', e.business_justification], ['Risk accepted', e.risk_acceptance], ['Business impact', e.business_impact], ['Compensating controls', e.compensating_controls],
              ['Risk owner', e.risk_owner], ['Technical owner', e.technical_owner], ['Requester', e.requester], ['Approver', e.approver], ['Expires', fmtDT(e.expires_at)], ['Decision notes', e.decision_notes]]} />
            {canApprove && e.status === 'PENDING_APPROVAL' && e.requester !== me?.email && (
              <div className="mt-2 flex gap-2"><button className="cn-btn cn-btn-primary" onClick={() => setDecide({ id: e.id, approve: true })}>Approve</button>
                <button className="cn-btn cn-btn-ghost" onClick={() => setDecide({ id: e.id, approve: false })}>Reject</button></div>
            )}
          </div>
        ))}
        {approvals.length > 0 && <Timeline items={approvals.map((a) => ({ at: a.at, title: `#${a.exception_id} ${a.action}`, body: `${a.actor}${a.notes ? ` — ${a.notes}` : ''}`, tone: a.action === 'approved' ? 'RESOLVED' : a.action === 'rejected' || a.action === 'expired' ? 'OPEN' : 'UNDER_REVIEW' }))} />}
      </Section>

      <Section title={`Comments and notes (${comments.length})`}>
        <div className="space-y-2">{comments.map((c) => (
          <div key={c.id} className="rounded-xl bg-surface-2 p-3 text-sm"><div className="mb-1 text-[11px] text-ink-3">{c.author} · {label(c.kind)} · {fmtDT(c.at)}</div><div className="whitespace-pre-wrap">{c.body}</div></div>
        ))}</div>
        {(canTriage || canRemediate) && (
          <div className="mt-2 flex flex-col gap-2">
            <select className="cn-input w-56" value={comment.kind} onChange={(e) => setComment({ ...comment, kind: e.target.value })} aria-label="Comment type">
              <option value="comment">Comment</option><option value="investigation_note">Investigation note</option><option value="verification_request">Request resolution verification</option>
            </select>
            <textarea className="cn-input h-20 w-full py-2" style={{ borderRadius: 12 }} value={comment.body} onChange={(e) => setComment({ ...comment, body: e.target.value })} aria-label="Comment text" />
            <button className="cn-btn cn-btn-primary w-fit" disabled={busy || !comment.body.trim()} onClick={async () => { if (await run(() => post(`/security/findings/${id}/comments`, comment), 'Saved')) setComment({ ...comment, body: '' }) }}>Add</button>
          </div>
        )}
      </Section>

      <Section title={`Evidence (${evidence.length})`}>
        <EvidenceList items={evidence} />
        {(canTriage || canRemediate) && <EvidenceForm path={`/security/findings/${id}/evidence`} onSaved={refresh} />}
      </Section>

      <Section title="Complete history">
        <Timeline items={history.map((h) => ({ at: h.at, title: `${h.field.replace(/_/g, ' ')}: ${h.from ?? '—'} → ${h.to ?? '—'}`, body: `${h.actor}${h.reason ? ` — ${h.reason}` : ''}`, tone: h.field === 'internal_status' ? h.to : undefined }))} />
      </Section>

      <Section title="Original provider payload"><details><summary className="cursor-pointer text-xs text-accent">Show JSON</summary>
        <pre className="mt-2 max-h-80 overflow-auto rounded-xl bg-surface-2 p-3 text-[11px]">{JSON.stringify(f.raw, null, 2)}</pre></details></Section>

      {confirm && <Confirm title={confirm.label} needReason body="This is recorded in the finding's history." onCancel={() => setConfirm(null)}
        onConfirm={(reason) => { setConfirm(null); run(() => post(`/security/findings/${id}/status`, { status: confirm.to, reason }), confirm.label) }} />}
      {decide && <Confirm title={decide.approve ? 'Approve exception' : 'Reject exception'} needReason={!decide.approve} reasonLabel="Decision notes"
        body={decide.approve ? 'The finding becomes EXCEPTION until the expiry date. The provider status is not changed and the risk still exists.' : 'The finding stays in its current status.'}
        confirm={decide.approve ? 'Approve' : 'Reject'} onCancel={() => setDecide(null)}
        onConfirm={(notes) => { const x = decide; setDecide(null); run(() => post(`/security/exceptions/${x.id}/decision`, { approve: x.approve, notes }), x.approve ? 'Exception approved' : 'Exception rejected') }} />}
      {excForm && <ExceptionForm id={id} onClose={() => setExcForm(false)} onSaved={refresh} />}
    </Drawer>
  )
}

const label = (s: string) => s.replace(/_/g, ' ')

export function EvidenceList({ items }: { items: any[] }) {
  if (!items.length) return <div className="text-xs text-ink-3">No evidence attached.</div>
  return (
    <ul className="space-y-1.5 text-sm">{items.map((e) => (
      <li key={e.id} className="flex flex-wrap items-center gap-2"><Paperclip size={13} className="text-ink-3" aria-hidden /><b>{e.name}</b>
        <span className="text-xs text-ink-3">{e.kind} · {e.uploaded_by} · {fmtDT(e.at)}</span>
        {e.kind === 'file' ? <DownloadButton url={`/api/v1/security/evidence/${e.id}/download`}>Download</DownloadButton>
          : e.kind === 'link' ? <a className="text-xs text-accent hover:underline" href={e.reference} target="_blank" rel="noreferrer noopener">{e.reference}</a> : <span className="text-xs">{e.reference}</span>}
        {e.sha256 && <code className="text-[10px] text-ink-3">sha256 {e.sha256.slice(0, 12)}…</code>}
      </li>))}</ul>
  )
}

export function EvidenceForm({ path, onSaved }: { path: string; onSaved: () => void }) {
  const [kind, setKind] = useState('link')
  const [name, setName] = useState('')
  const [ref, setRef] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const { run, busy } = useAction(onSaved)
  const save = async () => {
    const body = kind === 'file' && file ? { kind, name: name || file.name, content_base64: await fileToBase64(file), content_type: file.type } : { kind, name, reference: ref }
    if (await run(() => post(path, body), 'Evidence attached')) { setName(''); setRef(''); setFile(null) }
  }
  return (
    <div className="mt-2 flex flex-wrap items-end gap-2">
      <select className="cn-input" value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Evidence type"><option value="link">Link</option><option value="ticket">Ticket</option><option value="text">Text</option><option value="file">File (max 10 MB)</option></select>
      <input className="cn-input w-40" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} aria-label="Evidence name" />
      {kind === 'file' ? <input type="file" className="text-xs" onChange={(e) => setFile(e.target.files?.[0] ?? null)} aria-label="Evidence file" />
        : <input className="cn-input w-64" placeholder={kind === 'link' ? 'https://…' : kind === 'ticket' ? 'CHG-1234' : 'Description'} value={ref} onChange={(e) => setRef(e.target.value)} aria-label="Evidence reference" />}
      <button className="cn-btn cn-btn-ghost" disabled={busy || (kind === 'file' ? !file : !(name && ref))} onClick={() => void save()}>Attach</button>
    </div>
  )
}

function ExceptionForm({ id, onClose, onSaved }: { id: number; onClose: () => void; onSaved: () => void }) {
  const [b, setB] = useState({ business_justification: '', risk_acceptance: '', business_impact: '', compensating_controls: '', risk_owner: '', technical_owner: '', validity_days: 90 })
  const { run, busy } = useAction(() => { onSaved(); onClose() })
  const field = (k: keyof typeof b, l: string, area = false) => (
    <label className="block text-xs text-ink-3">{l}
      {area ? <textarea className="cn-input mt-1 h-20 w-full py-2 text-sm text-ink" style={{ borderRadius: 12 }} value={String(b[k])} onChange={(e) => setB({ ...b, [k]: e.target.value })} />
        : <input className="cn-input mt-1 w-full text-sm text-ink" value={String(b[k])} onChange={(e) => setB({ ...b, [k]: k === 'validity_days' ? Number(e.target.value) : e.target.value })} type={k === 'validity_days' ? 'number' : 'text'} />}
    </label>
  )
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/45 p-4" role="dialog" aria-modal="true" aria-label="Request risk exception">
      <div className="cn-card max-h-[90vh] w-full max-w-xl overflow-y-auto p-5">
        <h2 className="text-base font-semibold">Request risk exception</h2>
        <p className="mb-3 text-xs text-ink-2">An exception accepts the risk for a limited time after approval. It does not change the provider's status and does not remove the risk.</p>
        <div className="space-y-2">
          {field('business_justification', 'Business justification (required, 20+ characters)', true)}{field('risk_acceptance', 'Risk acceptance description (required)', true)}
          {field('business_impact', 'Business impact', true)}{field('compensating_controls', 'Compensating controls', true)}
          <div className="grid gap-2 sm:grid-cols-3">{field('risk_owner', 'Risk owner (required)')}{field('technical_owner', 'Technical owner')}{field('validity_days', 'Validity (days)')}</div>
        </div>
        <div className="mt-4 flex justify-end gap-2"><button className="cn-btn cn-btn-ghost" onClick={onClose}>Cancel</button>
          <button className="cn-btn cn-btn-primary" disabled={busy} onClick={() => run(() => post(`/security/findings/${id}/exceptions`, b), 'Exception submitted for approval')}>Submit for approval</button></div>
      </div>
    </div>
  )
}
