import { Fingerprint, ScrollText } from 'lucide-react'
import { useState } from 'react'
import { Panel } from '../../components/hero'
import { DataGrid, Drawer, FilterPanel, KV, Pager, Section, Select, TextFilter, useAction } from '../../components/secops'
import { ErrorNote, ExportButton, PageHeader, PageSkeleton, fmtTime } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'

interface Entry { audit_id: string; category: string; provider: string | null; scope: string | null; actor: string; action: string; target: string | null
  previous_state: unknown; new_state: unknown; approval_reference: string | null; execution_result: string | null; verification_result: string | null
  evidence_reference: string | null; at: string; hash: string }

/** Central append-only audit trail with a hash chain (each row carries the hash of the previous one). */
export default function AuditTrail() {
  const [f, setF] = useState({ category: '', actor: '', action: '', q: '', start: '', end: '' })
  const [page, setPage] = useState(1)
  const [open, setOpen] = useState<Entry | null>(null)
  const [check, setCheck] = useState<{ valid: boolean; checked: number; broken_at: string | null } | null>(null)
  const params = Object.fromEntries(Object.entries(f).filter(([, v]) => v))
  const { data, error, reload } = useApi<{ total: number; by_category: Record<string, number>; items: Entry[] }>('/audit-trail', { ...params, page, page_size: 100 })
  const { run, busy } = useAction()
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  const rows = (data?.items ?? []).map((e, i) => ({ ...e, id: i }))
  return (
    <>
      <PageHeader eyebrow="Administration" title="Central audit trail" description="Every platform action (approvals, revocations, budget and access changes, exports, AI analyses, configuration) in one append-only, tamper-evident record. Updates and deletes are blocked in the database; the hash chain shows if a row was altered or removed."
        action={<button className="cn-btn cn-btn-ghost h-9 text-sm" disabled={busy} onClick={() => run(async () => setCheck(await api.get('/audit-trail/verify')), 'Chain checked')}><Fingerprint size={14} aria-hidden />Verify integrity</button>} />
      {check && <div className="cn-card px-4 py-3 text-sm" style={{ borderColor: check.valid ? undefined : 'var(--critical)' }}>{check.valid ? `Hash chain intact: ${check.checked} entries verified.` : `Hash chain broken at entry ${check.broken_at} (after ${check.checked} valid entries). Investigate immediately.`}</div>}
      {!data ? <PageSkeleton tiles={0} /> : <Panel icon={<ScrollText size={15} />} title={`Entries (${data.total})`} subtitle={Object.entries(data.by_category).map(([k, v]) => `${k} ${v}`).join(' · ')}
        action={<ExportButton name="Audit trail" head={['Audit ID', 'Time', 'Category', 'Actor', 'Action', 'Target', 'Approval', 'Execution', 'Verification', 'Evidence', 'Hash']}
          rows={rows.map((e) => [e.audit_id, e.at, e.category, e.actor, e.action, e.target, e.approval_reference, e.execution_result, e.verification_result, e.evidence_reference, e.hash])} />}>
        <FilterPanel onClear={() => setF({ category: '', actor: '', action: '', q: '', start: '', end: '' })}>
          <Select label="Category" value={f.category} onChange={(v) => setF({ ...f, category: v })} options={Object.keys(data.by_category)} />
          <TextFilter label="Actor" value={f.actor} onChange={(v) => setF({ ...f, actor: v })} />
          <TextFilter label="Action" value={f.action} onChange={(v) => setF({ ...f, action: v })} />
          <TextFilter label="Target / audit ID" value={f.q} onChange={(v) => setF({ ...f, q: v })} />
          <label className="text-xs text-ink-3">From<input type="date" className="cn-input mt-1 block h-8" value={f.start} onChange={(e) => setF({ ...f, start: e.target.value })} /></label>
          <label className="text-xs text-ink-3">To<input type="date" className="cn-input mt-1 block h-8" value={f.end} onChange={(e) => setF({ ...f, end: e.target.value })} /></label>
        </FilterPanel>
        <DataGrid label="Audit trail" rows={rows} onOpen={setOpen} empty="No entries match." cols={[
          { key: 't', label: 'Time', render: (e) => fmtTime(e.at) }, { key: 'c', label: 'Category', render: (e) => e.category },
          { key: 'a', label: 'Action', render: (e) => <span className="font-medium">{e.action}</span> }, { key: 'w', label: 'Actor', render: (e) => <span className="text-xs">{e.actor}</span> },
          { key: 'g', label: 'Target', render: (e) => <span className="max-w-[260px] truncate text-xs">{e.target ?? '—'}</span> },
          { key: 'r', label: 'Approval / result', render: (e) => <span className="text-xs">{[e.approval_reference, e.execution_result, e.verification_result].filter(Boolean).join(' · ') || '—'}</span> },
          { key: 'h', label: 'Hash', render: (e) => <span className="font-mono text-[11px] text-ink-3">{e.hash}</span> }]} />
        <Pager page={page} pageSize={100} total={data.total} onPage={setPage} />
      </Panel>}
      {open && <Drawer title={open.action} subtitle={`${open.audit_id} · ${fmtTime(open.at)}`} onClose={() => setOpen(null)}>
        <Section title="Entry"><KV items={[['Category', open.category], ['Actor', open.actor], ['Cloud', open.provider], ['Scope', open.scope], ['Target', open.target], ['Approval reference', open.approval_reference],
          ['Execution result', open.execution_result], ['Verification result', open.verification_result], ['Evidence', open.evidence_reference], ['Hash (prefix)', open.hash]]} /></Section>
        <Section title="Previous state"><pre className="max-h-48 overflow-auto rounded bg-surface-2 p-2 text-[11px]">{JSON.stringify(open.previous_state, null, 2) ?? '—'}</pre></Section>
        <Section title="New state"><pre className="max-h-48 overflow-auto rounded bg-surface-2 p-2 text-[11px]">{JSON.stringify(open.new_state, null, 2) ?? '—'}</pre></Section>
      </Drawer>}
    </>
  )
}
