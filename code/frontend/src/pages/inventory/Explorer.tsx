import { Boxes, ChevronDown, ChevronRight, FolderTree, Server } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ProviderBadge, Panel } from '../../components/hero'
import { DataGrid, Drawer, FilterPanel, KV, Pager, Pill, Section, Select, TextFilter, type Col } from '../../components/secops'
import { ErrorNote, ExportButton, PageHeader, PageSkeleton, PROVIDER_LABEL, fmtAgo, fmtTime } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { useFilters } from '../../hooks/useFilters'

interface Summary {
  total_resources: number; by_category: Record<string, number>; by_provider: Record<string, number>; by_region: [string, number][]
  by_environment: Record<string, number>; by_scope: { key: string; name: string; count: number }[]; vms_with_public_ip: number
  scopes: Record<string, number>; category_rule: string; freshness: Record<string, string | null>
}
interface ScopeNode { provider: string; external_id: string; name: string; kind: string; environment: string | null; status: string; resources: number; vms: number; open_findings: number; last_seen_at: string | null; resource_groups: { name: string; resources: number }[] }
interface Tree { providers: { provider: string; parent_label: string; groups: { parent: string; scopes: ScopeNode[] }[] }[] }
interface Resource {
  id: number; provider: string; scope: string; scope_name: string; environment: string | null; resource_id: string; name: string; resource_type: string
  category: string; region: string | null; resource_group: string | null; state: string; tags: Record<string, string> | null; owner: string | null
  last_seen_at: string | null; stale: boolean; open_findings: number
}
interface Detail extends Resource {
  attributes: Record<string, unknown>; created_at: string | null; scope_status: string | null; cost: { available: boolean; note: string }
  findings: { id: number; title: string; severity: string; status: string; native_state: string; source: string; last_observed_at: string | null }[]
  vm: null | { power_state: string | null; instance_type: string | null; health_status: string; private_ip: string | null; public_ip: string | null; exposed_ports: number[]; launched_at: string | null; monitoring: string; not_collected: string[]
    metrics: null | { collected_at: string; cpu_percent: number | null; memory_percent: number | null; disk_percent: number | null; network_in_bytes: number | null; network_out_bytes: number | null } }
}
type Sel = { provider?: string; scope?: string; resource_group?: string; label?: string }

const pct = (v: number | null | undefined) => (v === null || v === undefined ? 'not collected' : `${v.toFixed(1)}%`)

/** Organisation -> parent (OU / folder / tenant) -> account / subscription / project -> resource group. */
function HierarchyTree({ tree, sel, onSelect }: { tree: Tree; sel: Sel; onSelect: (s: Sel) => void }) {
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const toggle = (k: string) => setOpen((o) => ({ ...o, [k]: !(o[k] ?? true) }))
  const isOpen = (k: string) => open[k] ?? true
  const btn = (active: boolean) => `flex w-full items-center gap-1.5 rounded-lg px-2 py-1 text-left text-[12.5px] ${active ? 'bg-[var(--accent-soft,#e8eefc)] font-semibold text-ink' : 'text-ink-2 hover:bg-surface-2'}`
  return (
    <nav aria-label="Cloud hierarchy" className="space-y-1 text-sm">
      <button className={btn(!sel.provider)} onClick={() => onSelect({})}><Boxes size={13} aria-hidden />All clouds</button>
      {tree.providers.map((p) => (
        <div key={p.provider}>
          <button className={btn(sel.provider === p.provider && !sel.scope)} aria-expanded={isOpen(p.provider)} onClick={() => { toggle(p.provider); onSelect({ provider: p.provider, label: PROVIDER_LABEL[p.provider] }) }}>
            {isOpen(p.provider) ? <ChevronDown size={12} aria-hidden /> : <ChevronRight size={12} aria-hidden />}<ProviderBadge provider={p.provider} size={18} />{PROVIDER_LABEL[p.provider]}
          </button>
          {isOpen(p.provider) && p.groups.map((g) => (
            <div key={g.parent} className="ml-4 border-l border-line pl-2">
              <div className="truncate px-2 py-0.5 text-[10.5px] uppercase tracking-wide text-ink-3" title={`${p.parent_label}: ${g.parent}`}>{g.parent}</div>
              {g.scopes.map((s) => (
                <div key={s.external_id}>
                  <button className={btn(sel.scope === s.external_id && !sel.resource_group)} onClick={() => onSelect({ provider: s.provider, scope: s.external_id, label: s.name })}
                    title={`${s.kind} ${s.external_id} · ${s.status}`}>
                    <Server size={12} aria-hidden className="shrink-0" /><span className="min-w-0 flex-1 truncate">{s.name}</span>
                    <span className="tabular text-[11px] text-ink-3">{s.resources}</span>
                  </button>
                  {sel.scope === s.external_id && s.resource_groups.map((rg) => (
                    <button key={rg.name} className={`${btn(sel.resource_group === rg.name)} ml-5 w-[calc(100%-1.25rem)]`} onClick={() => onSelect({ provider: s.provider, scope: s.external_id, resource_group: rg.name, label: `${s.name} / ${rg.name}` })}>
                      <FolderTree size={11} aria-hidden /><span className="min-w-0 flex-1 truncate">{rg.name}</span><span className="tabular text-[11px] text-ink-3">{rg.resources}</span>
                    </button>
                  ))}
                </div>
              ))}
            </div>
          ))}
        </div>
      ))}
    </nav>
  )
}

function ResourcePanel({ id, onClose }: { id: number; onClose: () => void }) {
  const { data } = useApi<Detail>(`/inventory/resources/${id}`)
  if (!data) return <Drawer title="Loading resource" onClose={onClose}><div className="text-sm text-ink-3">Loading…</div></Drawer>
  return (
    <Drawer title={data.name} subtitle={<span className="flex flex-wrap items-center gap-2"><Pill value={data.state === 'present' ? 'OK' : 'NOT_CONFIGURED'} text={data.state} />{data.category} · {data.resource_type}</span>} onClose={onClose}>
      <Section title="Resource">
        <KV items={[['Cloud', PROVIDER_LABEL[data.provider]], ['Account / subscription / project', `${data.scope_name} (${data.scope})`], ['Environment', data.environment ?? 'Not labelled'],
          ['Region', data.region ?? 'global'], ['Resource group', data.resource_group], ['Owner (from tags)', data.owner ?? 'No owner tag'],
          ['First recorded', fmtTime(data.created_at)], ['Last synchronized', <span>{fmtTime(data.last_seen_at)}{data.stale && <span className="ml-1 font-semibold" style={{ color: 'var(--warning,#b07a00)' }}>(stale)</span>}</span>],
          ['Scope onboarding', data.scope_status]]} />
        <div className="mt-2 break-all font-mono text-[11px] text-ink-3">{data.resource_id}</div>
      </Section>
      <Section title="Tags and labels">
        {data.tags && Object.keys(data.tags).length ? <div className="flex flex-wrap gap-1">{Object.entries(data.tags).map(([k, v]) => <span key={k} className="rounded-full border border-line px-2 py-0.5 text-xs">{k}: {v}</span>)}</div>
          : <div className="text-xs text-ink-3">No tags collected for this resource.</div>}
      </Section>
      {data.vm && (
        <Section title="Virtual machine">
          <KV items={[['Power state', data.vm.power_state], ['Size / machine type', data.vm.instance_type ?? 'not collected'], ['Health', data.vm.health_status],
            ['Private IP', data.vm.private_ip], ['Public IP', data.vm.public_ip ?? 'none'], ['Open to the internet', data.vm.exposed_ports.length ? data.vm.exposed_ports.join(', ') : 'no exposed ports found'],
            ['Monitoring', data.vm.monitoring], ['CPU', pct(data.vm.metrics?.cpu_percent)], ['Memory', pct(data.vm.metrics?.memory_percent)], ['Disk', pct(data.vm.metrics?.disk_percent)]]} />
          <p className="mt-2 text-[11px] text-ink-3">Not collected from the provider APIs in use: {data.vm.not_collected.join(', ')}. Memory and disk need a guest agent.</p>
        </Section>
      )}
      <Section title="Cost"><p className="text-xs text-ink-3">{data.cost.note}</p></Section>
      <Section title={`Security findings (${data.findings.length})`}>
        {data.findings.length ? <ul className="space-y-1 text-sm">{data.findings.map((f) => (
          <li key={f.id} className="flex items-center justify-between gap-2"><Link className="truncate text-accent hover:underline" to={`/vulnerabilities/findings?id=${f.id}`}>{f.title}</Link><span className="flex gap-1"><Pill value={f.severity} /><Pill value={f.status} /></span></li>))}</ul>
          : <div className="text-xs text-ink-3">No security findings recorded for this resource (or none visible to your role).</div>}
      </Section>
      <Section title="Attributes"><pre className="max-h-48 overflow-auto rounded-lg bg-surface-2 p-2 text-[11px]">{JSON.stringify(data.attributes, null, 2)}</pre></Section>
    </Drawer>
  )
}

/** Unified Cloud Inventory: hierarchy, category dashboard and drilldown to individual resources. */
export default function Explorer() {
  const { filters: gf, refreshKey } = useFilters()
  const [sel, setSel] = useState<Sel>({})
  const [f, setF] = useState({ category: '', region: '', environment: '', q: '' })
  const [page, setPage] = useState(1)
  const [open, setOpen] = useState<number | null>(null)
  const provider = sel.provider || gf.provider || undefined
  const scope = sel.scope || gf.scope || undefined
  const summary = useApi<Summary>('/inventory/summary', { provider, scope, environment: f.environment }, refreshKey)
  const tree = useApi<Tree>('/inventory/tree', undefined, refreshKey)
  const list = useApi<{ items: Resource[]; total: number; categories: string[] }>('/inventory/resources',
    { provider, scope, resource_group: sel.resource_group, ...f, page, size: 50 }, refreshKey)
  const regions = useMemo(() => (summary.data?.by_region ?? []).map(([r]) => r), [summary.data])
  if (summary.error) return <ErrorNote message={summary.error.message} onRetry={summary.reload} />
  if (!summary.data || !tree.data) return <PageSkeleton tiles={6} />
  const s = summary.data
  const cols: Col<Resource>[] = [
    { key: 'name', label: 'Resource', render: (r) => <div className="max-w-xs"><div className="truncate font-medium">{r.name}</div><div className="truncate text-[11px] text-ink-3">{r.resource_type}</div></div> },
    { key: 'cat', label: 'Category', render: (r) => r.category },
    { key: 'scope', label: 'Account / subscription / project', render: (r) => <span className="flex items-center gap-1.5"><ProviderBadge provider={r.provider} size={16} />{r.scope_name}</span> },
    { key: 'rg', label: 'Resource group', render: (r) => r.resource_group ?? '—' },
    { key: 'region', label: 'Region', render: (r) => r.region ?? 'global' },
    { key: 'env', label: 'Environment', render: (r) => r.environment ?? '—' },
    { key: 'owner', label: 'Owner', render: (r) => r.owner ?? '—' },
    { key: 'find', label: 'Open findings', render: (r) => (r.open_findings ? <Pill value="High" text={String(r.open_findings)} /> : '0') },
    { key: 'seen', label: 'Last synchronized', render: (r) => <span className={r.stale ? 'font-semibold' : ''} style={{ color: r.stale ? 'var(--warning,#b07a00)' : undefined }}>{fmtAgo(r.last_seen_at)}</span> },
  ]
  return (
    <>
      <PageHeader eyebrow="Cloud Resources" title="Inventory explorer"
        description="Every collected resource across AWS, Azure and Google Cloud, organised by hierarchy. Fields a provider did not return are shown as not collected."
        action={<span className="text-xs text-ink-3">Resources synchronized {fmtAgo(s.freshness.resources)} · VMs {fmtAgo(s.freshness.vms)} · discovery {fmtAgo(s.freshness.discovery)}</span>} />
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        {[['All resources', s.total_resources, ''], ...Object.entries(s.by_category).slice(0, 4).map(([k, v]) => [k, v, k]), ['VMs with public IP', s.vms_with_public_ip, '']].map(([label, n, cat]) => (
          <button key={label as string} onClick={() => { if (cat !== undefined) { setF({ ...f, category: cat as string }); setPage(1) } }}
            className={`cn-card cn-lift px-4 py-3 text-left ${f.category && f.category === cat ? 'ring-2 ring-[var(--accent)]' : ''}`}>
            <div className="text-[11.5px] text-ink-3">{label as string}</div><div className="tabular mt-1 text-[22px] font-semibold">{(n as number).toLocaleString('en-IN')}</div>
          </button>
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
        <Panel icon={<FolderTree size={15} />} title="Hierarchy" subtitle="OU / folder / tenant → account / project / subscription → resource group">
          <div className="max-h-[640px] overflow-auto"><HierarchyTree tree={tree.data} sel={sel} onSelect={(x) => { setSel(x); setPage(1) }} /></div>
        </Panel>
        <Panel icon={<Boxes size={15} />} title={`${sel.label ?? 'All clouds'}: ${list.data?.total ?? '…'} resources`}
          action={<ExportButton name="Cloud inventory" head={['Cloud', 'Scope', 'Name', 'Type', 'Category', 'Resource group', 'Region', 'Environment', 'Owner', 'Open findings', 'Last synchronized', 'Resource ID']}
            rows={(list.data?.items ?? []).map((r) => [r.provider, r.scope, r.name, r.resource_type, r.category, r.resource_group, r.region, r.environment, r.owner, r.open_findings, r.last_seen_at, r.resource_id])} />}>
          <FilterPanel onClear={() => { setF({ category: '', region: '', environment: '', q: '' }); setPage(1) }}>
            <Select label="Category" value={f.category} onChange={(v) => { setF({ ...f, category: v }); setPage(1) }} options={list.data?.categories ?? []} />
            <Select label="Region" value={f.region} onChange={(v) => { setF({ ...f, region: v }); setPage(1) }} options={regions} />
            <Select label="Environment" value={f.environment} onChange={(v) => { setF({ ...f, environment: v }); setPage(1) }} options={Object.keys(s.by_environment).filter((e) => e !== 'Not labelled')} />
            <TextFilter label="Search" value={f.q} onChange={(v) => { setF({ ...f, q: v }); setPage(1) }} placeholder="Name, ID or type" />
          </FilterPanel>
          {list.error ? <ErrorNote message={list.error.message} /> : <DataGrid label="Resources" cols={cols} rows={list.data?.items ?? []} onOpen={(r) => setOpen(r.id)} empty="No collected resources match." />}
          <Pager page={page} pageSize={50} total={list.data?.total ?? 0} onPage={setPage} />
          <p className="mt-2 text-[11px] text-ink-3">{s.category_rule} Azure lists all resource types; AWS and GCP currently contribute virtual machines.</p>
        </Panel>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        {[['By region', s.by_region.map(([k, v]) => [k, v])], ['By environment', Object.entries(s.by_environment)], ['By account / subscription / project', s.by_scope.map((x) => [x.name, x.count])]].map(([title, rows]) => (
          <Panel key={title as string} title={title as string}>
            <ul className="space-y-1 text-xs">{(rows as [string, number][]).slice(0, 12).map(([k, v]) => <li key={k} className="flex justify-between gap-2"><span className="truncate">{k}</span><span className="tabular font-semibold">{v}</span></li>)}
              {(rows as unknown[]).length === 0 && <li className="text-ink-3">No resources collected.</li>}</ul>
          </Panel>
        ))}
      </div>
      {open && <ResourcePanel id={open} onClose={() => setOpen(null)} />}
    </>
  )
}
