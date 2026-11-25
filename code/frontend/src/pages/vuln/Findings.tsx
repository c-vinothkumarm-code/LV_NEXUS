import { useCallback, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useCan } from '../../auth/AuthContext'
import { SubTabs } from '../../components/hero'
import { Confirm, DataGrid, DownloadButton, FilterPanel, Pager, Pill, Select, TextFilter, fmtDT, post, useAction, type Col } from '../../components/secops'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_LABEL } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import FindingPanel from './FindingPanel'
import { VULN_TABS } from './tabs'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Row = any
const FILTER_KEYS = ['provider', 'scope', 'region', 'severity', 'status', 'category', 'resource_type', 'owner', 'org', 'parent', 'q', 'date_from', 'date_to', 'overdue', 'native_state', 'security_only'] as const

export default function Findings({ provider, title, description, eyebrow = 'Vulnerability management', preset = {}, report }: {
  provider?: string; title: string; description: string; eyebrow?: string; preset?: Record<string, string>; report?: string
}) {
  const [params, setParams] = useSearchParams()
  const f = useMemo(() => Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? preset[k] ?? ''])), [params, preset]) as Record<string, string>
  if (provider) f.provider = provider
  const [sort, setSort] = useState<{ key: string; order: 'asc' | 'desc' }>({ key: preset.sort ?? 'severity', order: (preset.order as 'asc' | 'desc') ?? 'asc' })
  const [page, setPage] = useState(1)
  const [bump, setBump] = useState(0)
  const [open, setOpen] = useState<number | null>(Number(params.get('id')) || null)
  const [sel, setSel] = useState<Set<number>>(new Set())
  const [bulk, setBulk] = useState<{ action: string; status?: string } | null>(null)
  const [bulkOwner, setBulkOwner] = useState('')
  const canTriage = useCan('vuln:triage')
  const query = { ...f, security_only: f.security_only === 'false' ? 'false' : 'true', sort: sort.key, order: sort.order, page, page_size: 50 }
  const data = useApi<{ total: number; items: Row[] }>('/security/findings', query, bump)
  const facets = useApi<Record<string, { value: string; count: number }[]>>('/security/findings/facets', { security_only: query.security_only }, bump)
  const reload = useCallback(() => setBump((b) => b + 1), [])
  const { run } = useAction(() => { setSel(new Set()); reload() })
  const set = (k: string, v: string) => { const n = new URLSearchParams(params); if (v) n.set(k, v); else n.delete(k); setParams(n, { replace: true }); setPage(1) }
  const fc = facets.data ?? {}

  const cols: Col<Row>[] = [
    { key: 'severity', label: 'Severity', sortable: true, render: (r) => <Pill value={r.severity} /> },
    { key: 'title', label: 'Finding', sortable: true, render: (r) => <div className="max-w-[28rem]"><div className="font-medium text-accent">{r.title}</div>
      <div className="truncate text-[11px] text-ink-3" title={r.resource_id}>{r.resource_name || r.resource_id || '—'}</div></div> },
    { key: 'provider', label: 'Cloud / scope', sortable: true, render: (r) => <div className="text-xs"><b>{PROVIDER_LABEL[r.provider]}</b> · {r.scope}<div className="text-ink-3">{r.region ?? 'global'}</div></div> },
    { key: 'category', label: 'Category', render: (r) => <span className="text-xs">{r.category ?? '—'}</span> },
    { key: 'internal_status', label: 'Status', sortable: true, render: (r) => <div className="space-y-1"><Pill value={r.internal_status} />{r.native_state !== 'ACTIVE' && <div className="text-[10.5px] text-ink-3">native: {r.native_state.toLowerCase()}</div>}</div> },
    { key: 'owner', label: 'Owner', render: (r) => <span className="text-xs">{r.owner ?? <span className="text-ink-3">unassigned</span>}</span> },
    { key: 'sla_due_at', label: 'SLA due', sortable: true, render: (r) => <span className={`text-xs ${r.overdue ? 'font-semibold' : ''}`}>{r.overdue && <><span className="mr-1 inline-block h-2 w-2 rounded-full bg-critical" aria-hidden /><span className="sr-only">Overdue: </span></>}{fmtDT(r.sla_due_at)}</span> },
    { key: 'last_observed_at', label: 'Last observed', sortable: true, render: (r) => <span className="text-xs">{fmtDT(r.last_observed_at)}</span> },
  ]
  const exportUrl = `/api/v1/security/reports/${report ?? (provider === 'aws' ? 'aws-security-hub' : provider === 'azure' ? 'azure-advisor' : provider === 'gcp' ? 'gcp-scc' : 'open-register')}`

  return (
    <>
      <PageHeader eyebrow={eyebrow} title={title} description={description}
        action={<div className="flex gap-2"><DownloadButton url={`${exportUrl}?format=csv`}>CSV</DownloadButton><DownloadButton url={`${exportUrl}?format=xlsx`}>Excel</DownloadButton><DownloadButton url={`${exportUrl}?format=pdf`}>PDF</DownloadButton></div>} />
      <SubTabs items={VULN_TABS} />
      <FilterPanel onClear={() => setParams(new URLSearchParams(), { replace: true })}>
        <TextFilter label="Search" value={f.q} onChange={(v) => set('q', v)} placeholder="Title, resource, control, ID" />
        {!provider && <Select label="Cloud" value={f.provider} onChange={(v) => set('provider', v)} options={(fc.provider ?? []).map((o) => ({ ...o, label: PROVIDER_LABEL[o.value] ?? o.value }))} />}
        <Select label="Account / subscription / project" value={f.scope} onChange={(v) => set('scope', v)} options={fc.scope ?? []} />
        <Select label="Organization" value={f.org} onChange={(v) => set('org', v)} options={fc.organization ?? []} />
        <Select label="Mgmt group / folder" value={f.parent} onChange={(v) => set('parent', v)} options={fc.parent ?? []} />
        <Select label="Region" value={f.region} onChange={(v) => set('region', v)} options={fc.region ?? []} />
        <Select label="Severity" value={f.severity} onChange={(v) => set('severity', v)} options={['Critical', 'High', 'Medium', 'Low', 'Informational']} />
        <Select label="Status" value={f.status} onChange={(v) => set('status', v)} options={['OPEN', 'UNDER_REVIEW', 'EXCEPTION', 'RESOLVED', 'REOPENED', 'FALSE_POSITIVE']} />
        <Select label="Native state" value={f.native_state} onChange={(v) => set('native_state', v)} options={['ACTIVE', 'RESOLVED', 'SUPPRESSED', 'NOT_APPLICABLE']} />
        <Select label="Category" value={f.category} onChange={(v) => set('category', v)} options={fc.category ?? []} />
        <Select label="Resource type" value={f.resource_type} onChange={(v) => set('resource_type', v)} options={fc.resource_type ?? []} />
        <Select label="Owner" value={f.owner} onChange={(v) => set('owner', v)} options={fc.owner ?? []} />
        <label className="flex flex-col gap-1 text-[11px] text-ink-3">First detected<span className="flex gap-1">
          <input type="date" className="cn-input text-[12.5px] text-ink" value={f.date_from} onChange={(e) => set('date_from', e.target.value)} aria-label="From" />
          <input type="date" className="cn-input text-[12.5px] text-ink" value={f.date_to} onChange={(e) => set('date_to', e.target.value)} aria-label="To" /></span></label>
        <label className="flex items-center gap-1.5 pb-2 text-xs text-ink-2"><input type="checkbox" checked={f.overdue === 'true'} onChange={(e) => set('overdue', e.target.checked ? 'true' : '')} />Overdue only</label>
        {provider === 'azure' && <label className="flex items-center gap-1.5 pb-2 text-xs text-ink-2"><input type="checkbox" checked={f.security_only === 'false'} onChange={(e) => set('security_only', e.target.checked ? 'false' : '')} />Include non-security Advisor recommendations</label>}
      </FilterPanel>

      {canTriage && sel.size > 0 && (
        <div className="cn-card flex flex-wrap items-center gap-2 px-4 py-2.5 text-sm" role="region" aria-label="Bulk actions">
          <b>{sel.size} selected</b>
          <button className="cn-btn cn-btn-ghost" onClick={() => setBulk({ action: 'status', status: 'UNDER_REVIEW' })}>Mark under review</button>
          <button className="cn-btn cn-btn-ghost" onClick={() => setBulk({ action: 'status', status: 'RESOLVED' })}>Mark resolved</button>
          <input className="cn-input w-56" placeholder="owner@company.com" value={bulkOwner} onChange={(e) => setBulkOwner(e.target.value)} aria-label="Bulk owner" />
          <button className="cn-btn cn-btn-ghost" disabled={!bulkOwner} onClick={() => setBulk({ action: 'assign' })}>Assign owner</button>
          <button className="ml-auto text-xs text-accent" onClick={() => setSel(new Set())}>Clear selection</button>
        </div>
      )}

      <div className="cn-card p-4">
        {data.error ? <ErrorNote message={data.error.message} onRetry={data.reload} /> : !data.data ? <PageSkeleton tiles={0} /> : (
          <>
            <DataGrid label="Security findings" cols={cols} rows={data.data.items} sort={sort} selected={canTriage ? sel : undefined} onSelect={canTriage ? setSel : undefined}
              onSort={(k) => setSort((s) => ({ key: k, order: s.key === k && s.order === 'asc' ? 'desc' : 'asc' }))} onOpen={(r) => setOpen(r.id)}
              empty="No findings match. If no cloud has been synchronized yet, see Integrations › Synchronization." />
            <Pager page={page} pageSize={50} total={data.data.total} onPage={setPage} />
          </>
        )}
      </div>
      {open && <FindingPanel id={open} onClose={() => setOpen(null)} onChanged={reload} />}
      {bulk && <Confirm title={`Apply to ${sel.size} findings?`} needReason={bulk.status === 'RESOLVED'} confirm="Apply"
        body={bulk.action === 'assign' ? `Assign ${bulkOwner} as owner.` : `Change status to ${bulk.status?.replace('_', ' ').toLowerCase()}. Findings that cannot make this change are skipped and listed.`}
        onCancel={() => setBulk(null)} onConfirm={(reason) => {
          const b = bulk; setBulk(null)
          run(async () => {
            const r = await post<{ updated: number[]; failed: { id: number; reason: string }[] }>('/security/findings/bulk',
              { ids: [...sel], action: b.action, status: b.status, reason, field: 'owner', value: bulkOwner })
            if (r.failed.length) throw new Error(`${r.updated.length} updated; ${r.failed.length} skipped: ${r.failed.slice(0, 3).map((x) => `#${x.id} ${x.reason}`).join('; ')}`)
          }, `${sel.size} findings updated`)
        }} />}
    </>
  )
}
