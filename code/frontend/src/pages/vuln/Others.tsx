import { useState } from 'react'
import { useAuth, useCan } from '../../auth/AuthContext'
import { Panel, SubTabs } from '../../components/hero'
import { Confirm, DataGrid, DownloadButton, Pill, Select, fmtDT, post, put, useAction } from '../../components/secops'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_LABEL } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import FindingPanel from './FindingPanel'
import { VULN_TABS } from './tabs'
import { ScopeName } from '../../hooks/useScopeNames'

/* eslint-disable @typescript-eslint/no-explicit-any */

export function Exceptions() {
  const [status, setStatus] = useState('')
  const [bump, setBump] = useState(0)
  const [open, setOpen] = useState<number | null>(null)
  const [act, setAct] = useState<{ id: number; kind: 'approve' | 'reject' | 'close' } | null>(null)
  const data = useApi<{ items: any[] }>('/security/exceptions', { status }, bump)
  const me = useAuth()?.me
  const canApprove = useCan('exception:approve'), canTriage = useCan('vuln:triage')
  const { run } = useAction(() => setBump((b) => b + 1))
  return (
    <>
      <PageHeader eyebrow="Security Center" title="Exceptions management"
        description="Risk exceptions: requested → pending approval → approved (active) or rejected → expired or closed. Approval does not change the provider's status; expired exceptions return the finding for reassessment."
        action={<div className="flex gap-2"><DownloadButton url="/api/v1/security/reports/exceptions?format=xlsx">Exception register</DownloadButton><DownloadButton url="/api/v1/security/reports/expired-exceptions?format=xlsx">Expired register</DownloadButton></div>} />
      <SubTabs items={VULN_TABS} />
      <div className="cn-card p-4">
        <div className="mb-3"><Select label="Status" value={status} onChange={setStatus} options={['PENDING_APPROVAL', 'ACTIVE', 'REJECTED', 'EXPIRED', 'CLOSED']} /></div>
        {data.error ? <ErrorNote message={data.error.message} /> : !data.data ? <PageSkeleton tiles={0} /> : (
          <DataGrid label="Exceptions" rows={data.data.items} onOpen={(r) => setOpen(r.finding_id)} empty="No exceptions." cols={[
            { key: 'id', label: 'Exception', render: (r) => <b>#{r.id}</b> },
            { key: 'status', label: 'Status', render: (r) => <Pill value={r.status} /> },
            { key: 'finding', label: 'Finding', render: (r) => <div className="max-w-[22rem]"><div className="font-medium text-accent">{r.title}</div><div className="text-[11px] text-ink-3">{PROVIDER_LABEL[r.provider]} · <ScopeName provider={r.provider} id={r.scope} name={r.scope_name} /> · {r.resource_id ?? '—'}</div></div> },
            { key: 'sev', label: 'Severity', render: (r) => <Pill value={r.severity} /> },
            { key: 'just', label: 'Justification', render: (r) => <div className="max-w-[18rem] text-xs">{r.business_justification}</div> },
            { key: 'owners', label: 'Risk owner / requester', render: (r) => <div className="text-xs">{r.risk_owner}<div className="text-ink-3">{r.requester}</div></div> },
            { key: 'approver', label: 'Approver', render: (r) => <span className="text-xs">{r.approver ?? '—'}</span> },
            { key: 'expires', label: 'Expires', render: (r) => <span className="text-xs">{fmtDT(r.expires_at)}</span> },
            { key: 'act', label: '', render: (r) => <div className="flex gap-1">
              {canApprove && r.status === 'PENDING_APPROVAL' && r.requester !== me?.email && <>
                <button className="cn-btn cn-btn-primary h-7 text-xs" onClick={() => setAct({ id: r.id, kind: 'approve' })}>Approve</button>
                <button className="cn-btn cn-btn-ghost h-7 text-xs" onClick={() => setAct({ id: r.id, kind: 'reject' })}>Reject</button></>}
              {(canApprove || canTriage) && r.status === 'ACTIVE' && <button className="cn-btn cn-btn-ghost h-7 text-xs" onClick={() => setAct({ id: r.id, kind: 'close' })}>Close</button>}
            </div> },
          ]} />
        )}
      </div>
      {open && <FindingPanel id={open} onClose={() => setOpen(null)} onChanged={() => setBump((b) => b + 1)} />}
      {act && <Confirm title={act.kind === 'approve' ? 'Approve exception' : act.kind === 'reject' ? 'Reject exception' : 'Close exception'} needReason={act.kind !== 'approve'}
        reasonLabel="Notes" confirm={act.kind === 'approve' ? 'Approve' : act.kind === 'reject' ? 'Reject' : 'Close'}
        body={act.kind === 'close' ? 'The finding returns to OPEN for reassessment.' : act.kind === 'approve' ? 'The finding becomes EXCEPTION until expiry. The risk still exists.' : undefined}
        onCancel={() => setAct(null)} onConfirm={(notes) => {
          const a = act; setAct(null)
          run(() => a.kind === 'close' ? post(`/security/exceptions/${a.id}/close`, { notes }) : post(`/security/exceptions/${a.id}/decision`, { approve: a.kind === 'approve', notes }), 'Saved')
        }} />}
    </>
  )
}

export function Sla() {
  const [bump, setBump] = useState(0)
  const pol = useApi<{ items: any[] }>('/security/sla-policies', undefined, bump)
  const over = useApi<{ total: number; items: any[] }>('/security/findings', { overdue: 'true', sort: 'sla_due_at', order: 'asc', page_size: 100 }, bump)
  const canAdmin = useCan('security:admin')
  const [edit, setEdit] = useState<Record<string, number>>({})
  const [open, setOpen] = useState<number | null>(null)
  const { run } = useAction(() => setBump((b) => b + 1))
  return (
    <>
      <PageHeader eyebrow="Security Center" title="SLA monitoring" description="Remediation targets by severity, counted from first detection. Overdue Critical and High findings are escalated hourly; owners get one reminder per day."
        action={<DownloadButton url="/api/v1/security/reports/sla?format=xlsx">SLA report</DownloadButton>} />
      <SubTabs items={VULN_TABS} />
      <Panel title="SLA policies" subtitle={canAdmin ? 'Changing a target recalculates due dates of unresolved findings and records it in their history.' : 'Set by a security administrator.'}>
        {pol.data ? (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{pol.data.items.map((p) => (
            <div key={p.severity} className="rounded-2xl border border-line p-4">
              <Pill value={p.severity} />
              <div className="mt-2 text-2xl font-semibold">{p.target_hours >= 48 ? `${Math.round(p.target_hours / 24)} days` : `${p.target_hours} h`}</div>
              <div className="text-[11px] text-ink-3">{p.pause_on_exception ? 'Paused while an approved exception is active' : 'Not paused by exceptions'} · {p.updated_by}</div>
              {canAdmin && <div className="mt-2 flex gap-1"><input type="number" min={1} className="cn-input w-24" aria-label={`${p.severity} target hours`} value={edit[p.severity] ?? p.target_hours}
                onChange={(e) => setEdit({ ...edit, [p.severity]: Number(e.target.value) })} />
                <button className="cn-btn cn-btn-ghost" onClick={() => run(() => put('/security/sla-policies', { severity: p.severity, target_hours: edit[p.severity] ?? p.target_hours, pause_on_exception: p.pause_on_exception }), 'SLA policy saved')}>Save hours</button></div>}
            </div>))}</div>
        ) : <PageSkeleton tiles={0} />}
      </Panel>
      <Panel title={`Overdue findings (${over.data?.total ?? '…'})`} subtitle="Unresolved, past due, not paused by an approved exception">
        {over.data && <DataGrid label="Overdue findings" rows={over.data.items} onOpen={(r) => setOpen(r.id)} empty="Nothing is overdue." cols={[
          { key: 'sev', label: 'Severity', render: (r) => <Pill value={r.severity} /> },
          { key: 't', label: 'Finding', render: (r) => <span className="font-medium text-accent">{r.title}</span> },
          { key: 'c', label: 'Cloud / scope', render: (r) => <span className="text-xs">{PROVIDER_LABEL[r.provider]} · <ScopeName provider={r.provider} id={r.scope} name={r.scope_name} /></span> },
          { key: 'o', label: 'Owner', render: (r) => <span className="text-xs">{r.owner ?? 'UNASSIGNED'}</span> },
          { key: 's', label: 'Status', render: (r) => <Pill value={r.internal_status} /> },
          { key: 'd', label: 'Due', render: (r) => <span className="text-xs font-semibold">{fmtDT(r.sla_due_at)}</span> },
        ]} />}
      </Panel>
      {open && <FindingPanel id={open} onClose={() => setOpen(null)} onChanged={() => setBump((b) => b + 1)} />}
    </>
  )
}

export function History() {
  const [field, setField] = useState('')
  const h = useApi<{ items: any[] }>('/security/history', { field, limit: 300 })
  const [open, setOpen] = useState<number | null>(null)
  return (
    <>
      <PageHeader eyebrow="Security Center" title="Finding history" description="Every status, owner, SLA, native-state and exception change, newest first. Append-only: entries cannot be edited or deleted." />
      <SubTabs items={VULN_TABS} />
      <div className="cn-card p-4">
        <div className="mb-3"><Select label="Change type" value={field} onChange={setField} options={['internal_status', 'native_state', 'owner', 'analyst', 'exception', 'sla_due_at', 'sla_paused', 'severity', 'ai_analysis']} /></div>
        {h.data ? <DataGrid label="Finding history" rows={h.data.items.map((x, i) => ({ ...x, id: i }))} onOpen={(r) => setOpen(r.finding_id)} cols={[
          { key: 'at', label: 'When', render: (r) => <span className="whitespace-nowrap text-xs">{fmtDT(r.at)}</span> },
          { key: 'f', label: 'Finding', render: (r) => <div className="max-w-[22rem]"><span className="text-xs text-ink-3">#{r.finding_id} </span><span className="text-accent">{r.title}</span></div> },
          { key: 'ch', label: 'Change', render: (r) => <span className="text-xs">{r.field.replace(/_/g, ' ')}: <b>{r.from ?? '—'}</b> → <b>{r.to ?? '—'}</b></span> },
          { key: 'a', label: 'By', render: (r) => <span className="text-xs">{r.actor}</span> },
          { key: 'r', label: 'Reason', render: (r) => <span className="text-xs text-ink-2">{r.reason ?? ''}</span> },
        ]} /> : <PageSkeleton tiles={0} />}
      </div>
      {open && <FindingPanel id={open} onClose={() => setOpen(null)} onChanged={() => undefined} />}
    </>
  )
}
