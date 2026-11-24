import { Boxes, Cpu, Search, ShieldAlert } from 'lucide-react'
import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { ProviderBadge, Segmented } from '../../components/hero'
import { DataGrid, Pager, Pill, type Col } from '../../components/secops'
import { Metric } from '../../components/shell'
import { Tree } from '../../components/tree'
import { ErrorNote, PageSkeleton, PROVIDER_LABEL, fmtAgo, fmtInt, fmtUsd, fmtUsdShort } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import type { TopoNode } from '../../components/TopologyScene'
import OwnershipPanel from './Ownership'

const TopologyScene = lazy(() => import('../../components/TopologyScene'))
const MAX_3D_NODES = 2500

function toTopo(clouds: Node[]): { nodes: TopoNode[]; trimmed: boolean } {
  const out: TopoNode[] = []
  const depth = { cloud: 0, group: 1, scope: 2, child: 3 } as const
  const walk = (n: Node, parent: string | null, lvl: number) => {
    out.push({ id: n.id, parent, level: Math.max(lvl, depth[n.level] ?? lvl), label: n.name, provider: n.provider,
      alert: n.critical ? 'critical' : n.high ? 'high' : null,
      detail: `${n.resources} resources · ${n.vms} VMs · ${n.findings} open findings${n.critical ? ` (${n.critical} critical)` : ''}` })
    n.children.forEach((c) => walk(c, n.id, lvl + 1))
  }
  clouds.forEach((c) => walk(c, null, 0))
  if (out.length <= MAX_3D_NODES) return { nodes: out, trimmed: false }
  return { nodes: out.filter((n) => n.level < 3), trimmed: true }
}

type P = 'azure' | 'aws' | 'gcp'
interface Node {
  id: string; level: 'cloud' | 'group' | 'scope' | 'child'; name: string; provider: P; kind?: string; external_id?: string; child?: string | null
  resources: number; vms: number; vms_unhealthy: number; critical: number; high: number; findings: number; cost_mtd: number | null
  health?: string; status?: string; environment?: string | null; last_seen_at?: string | null; scopes?: number; subcost_collected?: boolean; children: Node[]
}
interface TreeResp { clouds: Node[]; generated_at: string; notes: string[] }
interface Res { id: number; name: string; resource_id: string; type: string; region: string | null; resource_group: string | null; findings: number; cost_mtd: number | null; last_seen_at: string | null; stale: boolean }
interface Vm { name: string | null; instance_id: string; type: string | null; region: string | null; power_state: string | null; health: string; public_ip: boolean; exposed_ports: number[]; last_seen_at: string | null }
interface Fd { id: number; title: string; severity: string; resource: string | null; source: string }
interface NodeResp { total: number; items: Res[]; vms: Vm[]; findings: Fd[] }

const HEALTH_DOT: Record<string, string> = { Healthy: 'var(--good)', Attention: 'var(--warning)', Inactive: 'var(--ink-3)' }

function Row({ n }: { n: Node }) {
  return (
    <span className="flex min-w-0 items-center gap-2 text-[13px]">
      {n.level === 'cloud' ? <ProviderBadge provider={n.provider} size={20} /> : n.level === 'scope'
        ? <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: HEALTH_DOT[n.health ?? ''] ?? 'var(--ink-3)' }} title={n.health} aria-hidden /> : null}
      <span className={`min-w-0 flex-1 truncate ${n.level === 'cloud' ? 'font-semibold' : n.level === 'scope' ? 'font-medium' : ''}`}>{n.name}</span>
      {n.critical + n.high > 0 && <span className="tabular shrink-0 rounded-full px-1.5 text-[10.5px] font-semibold text-white" style={{ background: n.critical ? 'var(--critical)' : 'var(--serious)' }}
        title={`${n.critical} critical, ${n.high} high`}>{n.critical + n.high}</span>}
      <span className="tabular w-16 shrink-0 text-right text-[11.5px] text-ink-3">{n.cost_mtd === null ? '—' : fmtUsdShort(n.cost_mtd)}</span>
    </span>
  )
}

function Detail({ n }: { n: Node }) {
  const [tab, setTab] = useState<'resources' | 'vms' | 'findings'>('resources')
  const [q, setQ] = useState(''), [page, setPage] = useState(1)
  const scoped = n.level === 'scope' || n.level === 'child'
  const { data, error, loading } = useApi<NodeResp>(scoped ? '/accounts/node' : null,
    { provider: n.provider, scope: n.external_id, child: n.level === 'child' ? n.child ?? '' : undefined, q: q || undefined, page, size: 50 })
  useEffect(() => { setPage(1) }, [n.id, q])
  const cols: Col<Res>[] = [
    { key: 'name', label: 'Resource', render: (r) => <span className="block max-w-[280px] truncate font-medium" title={r.resource_id}>{r.name}{r.stale && <span className="ml-1 text-[10.5px] text-ink-3">(not seen recently)</span>}</span> },
    { key: 'type', label: 'Type', render: (r) => <span className="text-ink-2">{r.type}</span> },
    { key: 'region', label: n.provider === 'azure' ? 'Resource group' : 'Region', render: (r) => (n.provider === 'azure' ? r.resource_group : r.region) ?? '—' },
    { key: 'findings', label: 'Findings', render: (r) => r.findings ? <b style={{ color: 'var(--critical)' }}>{r.findings}</b> : <span className="text-ink-3">0</span> },
    { key: 'cost', label: 'Cost MTD', render: (r) => <span className="tabular">{r.cost_mtd === null ? '—' : fmtUsd(r.cost_mtd)}</span> },
    { key: 'seen', label: 'Last seen', render: (r) => <span className="text-ink-3">{fmtAgo(r.last_seen_at)}</span> },
  ]
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[11px] font-semibold uppercase tracking-[.12em] text-accent">{n.kind ?? (n.level === 'cloud' ? 'Cloud' : '')}</p>
          <h2 className="truncate text-xl font-semibold tracking-tight">{n.name}</h2>
          <p className="text-xs text-ink-3">{[n.external_id && n.level === 'scope' ? n.external_id : null, n.environment, n.status, n.last_seen_at ? `seen ${fmtAgo(n.last_seen_at)}` : null].filter(Boolean).join(' · ')}</p>
        </div>
        {n.health && <Pill value={n.health === 'Healthy' ? 'HEALTHY' : n.health === 'Inactive' ? 'INACTIVE' : 'WARNING'} text={n.health} />}
      </div>
      <div className="grid grid-cols-2 gap-4 rounded-2xl border border-line p-4 sm:grid-cols-5">
        <Metric label="Resources" value={fmtInt(n.resources)} />
        <Metric label="VMs" value={fmtInt(n.vms)} note={n.vms_unhealthy ? `${n.vms_unhealthy} need attention` : 'all healthy or unknown'} tone={n.vms_unhealthy ? '#c27c00' : undefined} />
        <Metric label="Critical / high" value={`${n.critical} / ${n.high}`} note={`${fmtInt(n.findings)} open findings`} tone={n.critical ? 'var(--critical)' : undefined} />
        <Metric label="Cost this month" value={n.cost_mtd === null ? null : fmtUsd(n.cost_mtd)} note={n.cost_mtd === null ? 'not collected at this level' : 'USD, month to date'} />
        {n.level === 'cloud' ? <Metric label={n.provider === 'azure' ? 'Subscriptions' : n.provider === 'aws' ? 'Accounts' : 'Projects'} value={fmtInt(n.scopes ?? 0)} />
          : <Metric label="Children" value={fmtInt(n.children.length)} />}
      </div>
      {n.level === 'scope' && n.external_id && <OwnershipPanel provider={n.provider} scope={n.external_id} />}
      {!scoped ? (
        <div>
          <h3 className="mb-2 text-sm font-semibold">{n.level === 'cloud' ? 'Groups' : n.provider === 'azure' ? 'Subscriptions' : n.provider === 'aws' ? 'Accounts' : 'Projects'}</h3>
          <div className="max-w-full overflow-auto rounded-xl border border-line"><table className="cn-table w-full text-sm"><thead><tr className="border-b border-line text-left text-[11px] uppercase tracking-wide text-ink-3">
            <th className="px-3 py-2">Name</th><th className="px-3 py-2">Resources</th><th className="px-3 py-2">VMs</th><th className="px-3 py-2">Critical / high</th><th className="px-3 py-2 text-right">Cost MTD</th></tr></thead>
            <tbody>{n.children.map((c) => <tr key={c.id} className="border-b border-line last:border-0"><td className="px-3 py-2 font-medium">{c.name}</td><td className="tabular px-3 py-2">{fmtInt(c.resources)}</td>
              <td className="tabular px-3 py-2">{fmtInt(c.vms)}</td><td className="tabular px-3 py-2">{c.critical} / {c.high}</td><td className="tabular px-3 py-2 text-right">{c.cost_mtd === null ? '—' : fmtUsd(c.cost_mtd)}</td></tr>)}</tbody></table></div>
        </div>
      ) : (
        <div>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <Segmented label="Detail" value={tab} onChange={setTab} options={[
              { value: 'resources', label: `Resources${data ? ` (${data.total})` : ''}`, icon: <Boxes size={13} aria-hidden /> },
              { value: 'vms', label: `VMs${data ? ` (${data.vms.length})` : ''}`, icon: <Cpu size={13} aria-hidden /> },
              { value: 'findings', label: `Findings${data ? ` (${data.findings.length})` : ''}`, icon: <ShieldAlert size={13} aria-hidden /> }]} />
            {tab === 'resources' && <label className="relative"><Search size={13} className="absolute left-2.5 top-2.5 text-ink-3" aria-hidden />
              <input className="cn-input h-8 w-56 pl-7 text-xs" placeholder="Search name or type" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search resources" /></label>}
          </div>
          {error ? <ErrorNote message={error.message} /> : loading && !data ? <PageSkeleton tiles={0} /> : data && (
            tab === 'resources' ? <><DataGrid label="Resources" cols={cols} rows={data.items} empty="No resources collected for this scope yet." />
              <Pager page={page} pageSize={50} total={data.total} onPage={setPage} /></>
              : tab === 'vms' ? (data.vms.length === 0 ? <p className="rounded-xl border border-dashed border-line py-8 text-center text-sm text-ink-3">No virtual machines here.</p> :
                <div className="max-w-full overflow-auto rounded-xl border border-line"><table className="cn-table w-full text-sm"><thead><tr className="border-b border-line text-left text-[11px] uppercase tracking-wide text-ink-3">
                  <th className="px-3 py-2">VM</th><th className="px-3 py-2">Size</th><th className="px-3 py-2">Power</th><th className="px-3 py-2">Health</th><th className="px-3 py-2">Exposure</th><th className="px-3 py-2">Last seen</th></tr></thead>
                  <tbody>{data.vms.map((v) => <tr key={v.instance_id} className="border-b border-line last:border-0"><td className="px-3 py-2 font-medium">{v.name ?? v.instance_id.split('/').pop()}</td>
                    <td className="px-3 py-2">{v.type ?? '—'}</td><td className="px-3 py-2">{v.power_state ?? '—'}</td><td className="px-3 py-2"><Pill value={v.health.toUpperCase()} text={v.health} /></td>
                    <td className="px-3 py-2 text-xs">{v.public_ip ? `Public IP${v.exposed_ports.length ? ` · ports ${v.exposed_ports.join(', ')}` : ''}` : 'Private'}</td>
                    <td className="px-3 py-2 text-ink-3">{fmtAgo(v.last_seen_at)}</td></tr>)}</tbody></table></div>)
              : (data.findings.length === 0 ? <p className="rounded-xl border border-dashed border-line py-8 text-center text-sm text-ink-3">No open security findings here.</p> :
                <ul className="divide-y divide-line rounded-xl border border-line">{data.findings.map((f) => <li key={f.id} className="flex items-start gap-2 px-3 py-2 text-sm">
                  <Pill value={f.severity} /><span className="min-w-0"><span className="block truncate">{f.title}</span><span className="block truncate text-[11px] text-ink-3">{f.source} · {f.resource ?? '—'}</span></span></li>)}</ul>)
          )}
        </div>
      )}
    </div>
  )
}

export default function CloudAccounts() {
  const [sp, setSp] = useSearchParams()
  const provider = (sp.get('provider') ?? 'all') as P | 'all'
  const { data, error, loading, reload } = useApi<TreeResp>('/accounts/tree')
  const [sel, setSel] = useState<string | null>(null), [find, setFind] = useState('')
  const [view, setView] = useState<'tree' | '3d'>('tree')
  const [noGl, setNoGl] = useState(false)
  const onFail = useCallback(() => { setNoGl(true); setView('tree') }, [])
  const onPick = useCallback((id: string) => setSel(id), [])
  const clouds = useMemo(() => (data?.clouds ?? []).filter((c) => provider === 'all' || c.provider === provider), [data, provider])
  const index = useMemo(() => { const m = new Map<string, Node>(); const walk = (n: Node) => { m.set(n.id, n); n.children.forEach(walk) }; clouds.forEach(walk); return m }, [clouds])
  const current = (sel && index.get(sel)) || clouds[0]
  const topo = useMemo(() => toTopo(clouds), [clouds])
  if (error && !data) return <ErrorNote message={error.message} onRetry={reload} />
  if (loading && !data) return <PageSkeleton />
  const f = find.trim().toLowerCase()
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><p className="text-[11px] font-semibold uppercase tracking-[.14em] text-accent">Cloud Accounts</p>
          <h1 className="cn-h-page mt-1">Every account, subscription and project</h1>
          <p className="mt-1 text-sm text-ink-3">Azure tenant → subscription → resource group, AWS organization → OU → account → region, Google Cloud organization → folder → project → region. Health, cost and open findings at every level.</p></div>
        <div className="flex flex-wrap items-center gap-2">
        <Segmented label="View" value={view} onChange={(v) => setView(v as 'tree' | '3d')}
          options={[{ value: 'tree', label: 'Tree' }, ...(noGl ? [] : [{ value: '3d', label: '3D topology' }])]} />
        <Segmented label="Cloud" value={provider} onChange={(v) => { setSel(null); setSp(v === 'all' ? {} : { provider: v }) }}
          options={[{ value: 'all', label: 'All clouds' }, ...(['azure', 'aws', 'gcp'] as const).map((p) => ({ value: p, label: PROVIDER_LABEL[p] }))]} />
        </div>
      </div>
      <div className={`grid grid-cols-1 gap-4 ${view === '3d' ? 'xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]' : 'lg:grid-cols-[minmax(320px,400px)_minmax(0,1fr)]'}`}>
        {view === '3d' ? (
          <section className="cn-card relative h-[68vh] min-h-[420px] overflow-hidden p-0" aria-label="3D topology"
            style={{ background: 'radial-gradient(ellipse at 50% 45%, color-mix(in srgb, var(--accent) 10%, var(--surface-1)), var(--surface-1))' }}>
            {topo.nodes.length <= 1 ? <p className="p-8 text-center text-sm text-ink-3">No accounts discovered yet.</p> :
              <Suspense fallback={<div className="cn-skeleton absolute inset-4" />}><TopologyScene nodes={topo.nodes} selected={current?.id} onSelect={onPick} onFail={onFail} /></Suspense>}
            <div className="pointer-events-none absolute bottom-2 left-3 right-3 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-ink-3">
              {(['azure', 'aws', 'gcp'] as const).map((p) => <span key={p} className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: `var(--series-${p})` }} />{PROVIDER_LABEL[p]}</span>)}
              <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: 'var(--critical)' }} />critical findings</span>
              <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: 'var(--serious)' }} />high findings</span>
              <span className="ml-auto">{topo.nodes.length} nodes{topo.trimmed ? ' (regions / resource groups hidden: use the tree)' : ''} · drag to rotate, scroll to zoom, click to open</span>
            </div>
          </section>
        ) : (
        <section className="cn-card p-3" aria-label="Account tree">
          <label className="relative mb-2 block"><Search size={13} className="absolute left-2.5 top-2.5 text-ink-3" aria-hidden />
            <input className="cn-input h-8 w-full pl-7 text-xs" placeholder="Find account, subscription, project, group or region" value={find} onChange={(e) => setFind(e.target.value)} aria-label="Find in tree" /></label>
          <div className="mb-1 flex justify-between px-2 text-[10.5px] uppercase tracking-wide text-ink-3"><span>Name</span><span>Cost MTD</span></div>
          <div className="max-h-[68vh] overflow-auto pr-1">
            {clouds.every((c) => c.children.length === 0) ? <p className="px-2 py-8 text-center text-sm text-ink-3">No accounts discovered yet. Connect a cloud under Integrations → Onboard a cloud.</p> :
              <Tree<Node> nodes={clouds} selected={current?.id} onSelect={(n) => setSel(n.id)} defaultOpen={2} render={(n) => <Row n={n} />}
                filter={f ? (n) => n.name.toLowerCase().includes(f) || (n.external_id ?? '').toLowerCase().includes(f) : undefined} />}
          </div>
          <ul className="mt-3 space-y-0.5 border-t border-line px-2 pt-2 text-[11px] text-ink-3">{data?.notes.map((t) => <li key={t}>{t}</li>)}</ul>
        </section>
        )}
        <section className="cn-card p-5" aria-label="Selected node">{current ? <Detail key={current.id} n={current} /> : <p className="text-sm text-ink-3">Select a node.</p>}</section>
      </div>
    </div>
  )
}
