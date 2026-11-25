import { ChevronDown, ChevronRight, KeyRound, Lock, Search, ShieldAlert, Users } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { ProviderBadge, Segmented } from '../../components/hero'
import { DataGrid, Drawer, FilterPanel, Pill, Select, TextFilter, type Col } from '../../components/secops'
import { Tree } from '../../components/tree'
import { ErrorNote, ExportButton, PageSkeleton, PROVIDER_LABEL, fmtAgo, fmtInt, fmtTime } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import type { Scope } from '../../services/api'
import { RelationGraph, type GEdge, type GNode } from '../../components/graph'

/** Read-only "who has access to what" for Azure, AWS and Google Cloud. No create / edit / remove / approve / request actions. */
type P = 'azure' | 'aws' | 'gcp'
interface Node {
  id: string; level: 'cloud' | 'group' | 'scope' | 'child'; provider: P; name: string; kind?: string; scope?: string; child?: string | null
  principals: number; privileged: number; assignments?: number; inherited?: number; resources?: number; scopes?: number
  unavailable: string[]; note?: string | null; environment?: string | null; children: Node[]
}
interface TreeResp { clouds: Node[]; last_refreshed: string | null; collected: boolean; notes: string[] }
interface Member { principal_id: string; type: string; display_name: string | null; sign_in_name: string | null; enabled: boolean | null }
interface Who {
  id: number; principal_id: string; type: string; display_name: string; sign_in_name: string | null; enabled: boolean | null; lifecycle: string | null
  last_sign_in: string | null; role: string; access_type: string; privileged: boolean; level: string; assigned_at: string; inherited_via: string | null
  cross_account: boolean; condition: string | null; pim_state: string | null; expires_at: string | null; resource: string | null
  members: Member[] | null; members_note: string | null
}
interface WhoResp { total: number; items: Who[]; resources: { resource: string; name: string }[] }
interface Person { provider: P; principal_id: string; type: string; display_name: string; sign_in_name: string | null; enabled: boolean | null; lifecycle: string
  last_sign_in: string | null; access: { scope: string; scope_name: string; level: string; where: string | null; role: string; privileged: boolean; access_type: string; through_group: string | null; inherited_via: string | null }[] }

const TYPE_ICON: Record<string, string> = { User: 'Person', Group: 'Group', ServicePrincipal: 'App', ServiceAccount: 'Service account', ManagedIdentity: 'Managed identity', Role: 'Role' }

function Unavailable({ msgs }: { msgs: string[] }) {
  if (!msgs.length) return null
  return <div className="space-y-1">{msgs.map((m) => <p key={m} className="flex items-start gap-2 rounded-lg border px-3 py-2 text-[12.5px]" style={{ borderColor: '#e0662b55', background: '#e0662b10' }}>
    <Lock size={13} className="mt-0.5 shrink-0" style={{ color: 'var(--serious)' }} aria-hidden />{m}</p>)}</div>
}

function WhoTable({ rows }: { rows: Who[] }) {
  const [open, setOpen] = useState<Record<number, boolean>>({})
  if (!rows.length) return <p className="rounded-xl border border-dashed border-line py-8 text-center text-sm text-ink-3">No one has access at this level in the collected data.</p>
  return (
    <div className="overflow-auto rounded-xl border border-line"><table className="cn-table w-full text-sm">
      <thead><tr className="border-b border-line text-left text-[11px] uppercase tracking-wide text-ink-3">
        <th className="px-3 py-2">Who</th><th className="px-3 py-2">Type</th><th className="px-3 py-2">Role / permissions</th><th className="px-3 py-2">How</th><th className="px-3 py-2">Last sign-in</th></tr></thead>
      <tbody>{rows.map((r) => {
        const isGroup = r.type === 'Group'
        return [
          <tr key={r.id} className="border-b border-line align-top last:border-0">
            <td className="px-3 py-2">
              <div className="flex items-start gap-1.5">
                {isGroup && r.members ? <button type="button" aria-label={open[r.id] ? 'Hide members' : 'Show members'} onClick={() => setOpen((o) => ({ ...o, [r.id]: !o[r.id] }))} className="mt-0.5 text-ink-3 hover:text-ink">
                  {open[r.id] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</button> : <span className="w-[14px]" />}
                <div className="min-w-0"><div className="truncate font-medium">{r.display_name}{r.enabled === false && <span className="ml-1.5 text-[11px] text-ink-3">(disabled)</span>}</div>
                  {r.sign_in_name && r.sign_in_name !== r.display_name && <div className="truncate text-[11.5px] text-ink-3">{r.sign_in_name}</div>}
                  {isGroup && <div className="text-[11.5px] text-ink-3">{r.members ? `${r.members.length} members` : r.members_note}</div>}</div>
              </div>
            </td>
            <td className="px-3 py-2 text-ink-2">{TYPE_ICON[r.type] ?? r.type}</td>
            <td className="px-3 py-2"><span className="font-medium">{r.role}</span>{r.privileged && <span className="ml-1.5 rounded-full px-1.5 py-px text-[10.5px] font-semibold text-white" style={{ background: 'var(--critical)' }}>privileged</span>}
              {r.pim_state === 'eligible' && <span className="ml-1.5 text-[11px] text-ink-3">PIM eligible</span>}
              {r.condition && <div className="truncate text-[11px] text-ink-3" title={r.condition}>Conditional</div>}
              {r.expires_at && <div className="text-[11px] text-ink-3">Expires {fmtTime(r.expires_at)}</div>}</td>
            <td className="px-3 py-2 text-[12.5px]">{r.inherited_via ? <span className="text-ink-2" title={r.inherited_via}>Inherited from {r.inherited_via.split('/').pop()}</span>
              : <span>{r.access_type === 'Group' ? 'Group assignment' : r.access_type === 'Federated' ? 'Federated (SSO)' : 'Assigned here'}</span>}
              {r.cross_account && <div className="text-[11px]" style={{ color: 'var(--serious)' }}>Other AWS account</div>}</td>
            <td className="px-3 py-2 text-ink-3">{r.last_sign_in ? fmtAgo(r.last_sign_in) : '—'}</td>
          </tr>,
          isGroup && open[r.id] && r.members ? <tr key={`${r.id}-m`} className="border-b border-line bg-surface-2/40"><td colSpan={5} className="px-10 py-2">
            <ul className="grid gap-x-6 gap-y-1 text-[12.5px] sm:grid-cols-2">{r.members.map((m) => <li key={m.principal_id} className="truncate">
              <Users size={11} className="mr-1 inline text-ink-3" aria-hidden />{m.display_name ?? m.sign_in_name ?? m.principal_id}
              {m.sign_in_name && m.display_name && <span className="ml-1 text-ink-3">{m.sign_in_name}</span>}{m.enabled === false && <span className="ml-1 text-ink-3">(disabled)</span>}</li>)}</ul>
          </td></tr> : null,
        ]
      })}</tbody></table></div>
  )
}

function NodeDetail({ n }: { n: Node }) {
  const [resource, setResource] = useState<string | null>(null)
  const [q, setQ] = useState(''), [priv, setPriv] = useState(false)
  useEffect(() => { setResource(null) }, [n.id])
  const askable = (n.level === 'scope' || (n.level === 'child' && n.child !== null)) && n.scope
  const { data, error, loading } = useApi<WhoResp>(askable ? '/access/who' : null,
    { provider: n.provider, scope: n.scope, child: n.level === 'child' ? n.child ?? undefined : undefined, resource: resource ?? undefined, q: q || undefined })
  const rows = (data?.items ?? []).filter((r) => !priv || r.privileged)
  const here = rows.filter((r) => !r.inherited_via), above = rows.filter((r) => r.inherited_via)
  return (
    <div className="space-y-4">
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[.12em] text-accent">{resource ? 'Resource' : n.kind ?? (n.level === 'cloud' ? 'Cloud' : 'Group')}</p>
        <h2 className="truncate text-xl font-semibold tracking-tight">{resource ? data?.resources.find((r) => r.resource === resource)?.name ?? resource.split('/').pop() : n.name}</h2>
        {resource && <button type="button" className="text-xs text-accent hover:underline" onClick={() => setResource(null)}>← back to {n.name}</button>}
      </div>
      <Unavailable msgs={n.unavailable} />
      {n.note && <p className="text-sm text-ink-3">{n.note}</p>}
      {!askable ? (
        <div className="grid grid-cols-2 gap-4 rounded-2xl border border-line p-4 sm:grid-cols-3">
          <div><div className="text-[11px] uppercase tracking-wide text-ink-3">Identities with access</div><div className="tabular text-2xl font-semibold">{fmtInt(n.principals)}</div></div>
          <div><div className="text-[11px] uppercase tracking-wide text-ink-3">Privileged assignments</div><div className="tabular text-2xl font-semibold" style={{ color: n.privileged ? 'var(--critical)' : undefined }}>{fmtInt(n.privileged)}</div></div>
          {n.scopes !== undefined && <div><div className="text-[11px] uppercase tracking-wide text-ink-3">{n.provider === 'azure' ? 'Subscriptions' : n.provider === 'aws' ? 'Accounts' : 'Projects'}</div><div className="tabular text-2xl font-semibold">{fmtInt(n.scopes)}</div></div>}
          <p className="col-span-full text-xs text-ink-3">Select a {n.provider === 'azure' ? 'subscription or resource group' : n.provider === 'aws' ? 'account or service' : 'project or service'} to see exactly who has access.</p>
        </div>
      ) : error ? <ErrorNote message={error.message} /> : loading && !data ? <PageSkeleton tiles={0} /> : data && <>
        <div className="flex flex-wrap items-center gap-2">
          <label className="relative"><Search size={13} className="absolute left-2.5 top-2.5 text-ink-3" aria-hidden />
            <input className="cn-input h-8 w-60 pl-7 text-xs" placeholder="Filter by name, e-mail or role" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter people" /></label>
          <label className="flex items-center gap-1.5 text-xs"><input type="checkbox" checked={priv} onChange={(e) => setPriv(e.target.checked)} />Privileged only</label>
          <span className="ml-auto text-xs text-ink-3">{rows.length} of {data.total} assignments</span>
        </div>
        <section><h3 className="mb-2 flex items-center gap-1.5 text-sm font-semibold"><KeyRound size={14} className="text-accent" aria-hidden />Assigned at this level ({here.length})</h3><WhoTable rows={here} /></section>
        {above.length > 0 && <section><h3 className="mb-2 text-sm font-semibold">Inherited from above ({above.length})</h3><WhoTable rows={above} /></section>}
        {!resource && data.resources.length > 0 && <section><h3 className="mb-2 text-sm font-semibold">Resources with their own permissions ({data.resources.length})</h3>
          <ul className="flex flex-wrap gap-2">{data.resources.map((r) => <li key={r.resource}><button type="button" onClick={() => setResource(r.resource)} title={r.resource}
            className="rounded-full border border-line px-3 py-1 text-xs hover:border-accent hover:text-accent">{r.name}</button></li>)}</ul></section>}
      </>}
    </div>
  )
}

function PeopleSearch({ q }: { q: string }) {
  const { data, error } = useApi<{ items: Person[] }>(q.length >= 2 ? '/access/search' : null, { q })
  if (error) return <ErrorNote message={error.message} />
  if (!data) return <PageSkeleton tiles={0} />
  if (!data.items.length) return <p className="py-8 text-center text-sm text-ink-3">No identity matches “{q}” in the collected data.</p>
  return (
    <div className="space-y-4">{data.items.map((p) => (
      <article key={`${p.provider}|${p.principal_id}`} className="rounded-2xl border border-line p-4">
        <div className="flex flex-wrap items-center gap-2"><ProviderBadge provider={p.provider} size={20} /><h3 className="font-semibold">{p.display_name}</h3>
          <span className="text-xs text-ink-3">{p.sign_in_name}</span><span className="text-xs text-ink-3">· {TYPE_ICON[p.type] ?? p.type}</span>
          {p.enabled === false && <Pill value="DISABLED" text="Disabled" />}{p.lifecycle && p.lifecycle !== 'Active' && <Pill value={p.lifecycle} />}
          <span className="ml-auto text-xs text-ink-3">Last sign-in {p.last_sign_in ? fmtAgo(p.last_sign_in) : '—'}</span></div>
        {p.access.length === 0 ? <p className="mt-2 text-sm text-ink-3">No active access in the collected data.</p> :
          <ul className="mt-3 divide-y divide-line text-sm">{p.access.map((a, i) => <li key={i} className="flex flex-wrap items-baseline gap-x-3 py-1.5">
            <span className="font-medium">{a.role}</span>{a.privileged && <span className="text-[11px] font-semibold" style={{ color: 'var(--critical)' }}>privileged</span>}
            <span className="text-ink-2">on {a.where ?? a.scope_name} <span className="text-ink-3">({a.level.replace('_', ' ')}{a.level !== 'subscription' && a.level !== 'account' && a.level !== 'project' ? ` in ${a.scope_name}` : ''})</span></span>
            {a.through_group && <span className="text-xs text-ink-3">through group {a.through_group}</span>}
            {a.inherited_via && <span className="text-xs text-ink-3">inherited from {a.inherited_via.split('/').pop()}</span>}</li>)}</ul>}
      </article>))}</div>
  )
}

function AccessTree() {
  const [provider, setProvider] = useState<P | 'all'>('all')
  const { data, error, reload } = useApi<TreeResp>('/access/tree')
  const [sel, setSel] = useState<string | null>(null), [person, setPerson] = useState(''), [debounced, setDebounced] = useState('')
  useEffect(() => { const t = setTimeout(() => setDebounced(person.trim()), 300); return () => clearTimeout(t) }, [person])
  const clouds = useMemo(() => (data?.clouds ?? []).filter((c) => provider === 'all' || c.provider === provider), [data, provider])
  const index = useMemo(() => { const m = new Map<string, Node>(); const walk = (n: Node) => { m.set(n.id, n); n.children.forEach(walk) }; clouds.forEach(walk); return m }, [clouds])
  if (error && !data) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton />
  const current = (sel && index.get(sel)) || clouds[0]
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <p className="text-sm text-ink-3">Every user, group and service identity at subscription / account / project, resource group and resource level. Last refreshed {data.last_refreshed ? `${fmtAgo(data.last_refreshed)} (${fmtTime(data.last_refreshed)})` : 'never'}.</p>
        <Segmented label="Cloud" value={provider} onChange={(v) => { setProvider(v); setSel(null) }}
          options={[{ value: 'all', label: 'All clouds' }, ...(['azure', 'aws', 'gcp'] as const).map((p) => ({ value: p, label: PROVIDER_LABEL[p] }))]} />
      </div>
      {!data.collected && <div className="cn-card border-l-4 p-4 text-sm" style={{ borderLeftColor: 'var(--warning)' }}>Access has not been collected yet. The access_inventory collection runs every 15 minutes once a cloud is connected.</div>}
      <label className="relative block max-w-xl"><Search size={15} className="absolute left-3 top-2.5 text-ink-3" aria-hidden />
        <input className="cn-input h-9 w-full pl-9 text-sm" placeholder="Search a person, group or service identity by name or e-mail" value={person} onChange={(e) => setPerson(e.target.value)} aria-label="Search identity" /></label>
      {debounced.length >= 2 ? <section className="cn-card p-5"><div className="mb-3 flex items-center justify-between"><h2 className="font-semibold">Access for “{debounced}”</h2>
        <button type="button" className="text-xs text-accent hover:underline" onClick={() => setPerson('')}>Clear search</button></div><PeopleSearch q={debounced} /></section> : (
        <div className="grid gap-4 lg:grid-cols-[minmax(300px,380px)_minmax(0,1fr)]">
          <section className="cn-card p-3" aria-label="Scope tree">
            <div className="mb-1 flex justify-between px-2 text-[10.5px] uppercase tracking-wide text-ink-3"><span>Scope</span><span>Identities</span></div>
            <div className="max-h-[70vh] overflow-auto pr-1">
              <Tree<Node> nodes={clouds} selected={current?.id} onSelect={(n) => setSel(n.id)} defaultOpen={2} render={(n) => (
                <span className="flex min-w-0 items-center gap-2 text-[13px]">
                  {n.level === 'cloud' && <ProviderBadge provider={n.provider} size={20} />}
                  {n.unavailable.length > 0 && <Lock size={12} style={{ color: 'var(--serious)' }} aria-label="Access data unavailable" />}
                  <span className={`min-w-0 flex-1 truncate ${n.level === 'cloud' ? 'font-semibold' : n.level === 'scope' ? 'font-medium' : ''}`}>{n.name}</span>
                  {n.privileged > 0 && <ShieldAlert size={12} style={{ color: 'var(--critical)' }} aria-label={`${n.privileged} privileged`} />}
                  <span className="tabular w-10 shrink-0 text-right text-[11.5px] text-ink-3">{n.unavailable.length && !n.principals ? '—' : fmtInt(n.principals)}</span>
                </span>)} />
            </div>
            <ul className="mt-3 space-y-0.5 border-t border-line px-2 pt-2 text-[11px] text-ink-3">{data.notes.map((t) => <li key={t}>{t}</li>)}</ul>
          </section>
          <section className="cn-card p-5" aria-label="Who has access">{current ? <NodeDetail key={current.id} n={current} /> : <p className="text-sm text-ink-3">No clouds connected.</p>}</section>
        </div>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ people table + monthly activity */
interface Row {
  id: number; provider: P; account_name: string; account_id: string; scope_level: string; scope_path: string; resource_group: string | null; resource_name: string | null
  principal_id: string; display_name: string | null; sign_in_name: string | null; identity_type: string; access_details: string; access_type: string
  privileged: boolean; first_seen_at: string | null; expires_at: string | null; identity_status: string | null; pim_state: string | null
  grant: { expiry: string | null } | null
}
interface Activity {
  period: { label: string; complete: boolean; note: string | null }; counts: Record<string, number>; failed_attempts: number; kinds: Record<string, string>
  coverage: { provider: P; events: number; collected: boolean; note: string | null }[]; total_events: number; basis: string
  events: { id: number; event_id: string; time: string; provider: P; account_id: string; account_name: string; kind: string; kind_label: string; target: string
    role: string | null; initiated_by: string | null; source_ip: string | null; operation: string; outcome: string }[]
}
const HUMAN = new Set(['User', 'Guest', 'Federated'])
const day = (v: string | null | undefined) => (v ? new Date(v).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }) : '—')
const scopeText = (r: Row) => r.resource_name ? `Resource · ${r.resource_name}` : r.resource_group ? `Resource group · ${r.resource_group}` : r.scope_level.replace('_', ' ')
const email = (r: Row) => r.sign_in_name ?? (/^user:(.+@.+)$/.exec(r.principal_id)?.[1] ?? null)
const expiry = (r: Row) => r.expires_at ?? r.grant?.expiry ?? null

/** Identity → access level (role) → account → scope, built only from this identity's collected assignments. */
function IdentityGraph({ rows }: { rows: Row[] }) {
  const { nodes, edges } = useMemo(() => {
    const n = new Map<string, GNode>(), e: GEdge[] = [], seen = new Set<string>()
    const add = (node: GNode) => { if (!n.has(node.id)) n.set(node.id, node) }
    const link = (edge: GEdge) => { const k = `${edge.from}>${edge.to}`; if (!seen.has(k)) { seen.add(k); e.push(edge) } }
    const r0 = rows[0]
    add({ id: 'id', col: 0, label: r0.display_name ?? email(r0) ?? r0.principal_id, sub: r0.identity_type, tone: rows.some((r) => r.privileged) ? 'critical' : 'accent',
      details: [['Type', r0.identity_type], ['E-mail / sign-in', email(r0) ?? ''], ['Principal ID', r0.principal_id], ['Status', r0.identity_status ?? 'Active'],
        ['Assignments', String(rows.length)], ['Privileged assignments', String(rows.filter((r) => r.privileged).length)]] })
    rows.forEach((r) => {
      const role = `role:${r.provider}:${r.access_details}`, acct = `acct:${r.provider}:${r.account_id}`, scope = `scope:${r.id}`
      add({ id: role, col: 1, label: r.access_details, sub: `${PROVIDER_LABEL[r.provider]}${r.privileged ? ' · privileged' : ''}`, tone: r.privileged ? 'critical' : null,
        details: [['Cloud', PROVIDER_LABEL[r.provider]], ['Privileged', r.privileged ? 'yes' : 'no'], ['Assignment type', r.access_type],
          ['Permissions', 'As defined by the provider for this role (not expanded by LV NEXUS)']] })
      add({ id: acct, col: 2, label: r.account_name || r.account_id, sub: r.account_id, details: [['Cloud', PROVIDER_LABEL[r.provider]], ['Account / subscription / project', r.account_name], ['ID', r.account_id]] })
      add({ id: scope, col: 3, label: scopeText(r), sub: r.scope_path.split('/').slice(-2).join('/'), tone: expiry(r) ? 'warning' : null,
        details: [['Scope level', r.scope_level.replace('_', ' ')], ['Path', r.scope_path], ['Access since (first seen)', day(r.first_seen_at)], ['Expires', expiry(r) ? day(expiry(r)) : 'No expiry'],
          ['PIM state', r.pim_state ?? ''], ['How granted', r.access_type]] })
      link({ from: 'id', to: role, label: r.access_type !== 'Direct' ? r.access_type.toLowerCase() : undefined, dashed: r.access_type !== 'Direct' })
      link({ from: role, to: acct }); link({ from: acct, to: scope })
    })
    return { nodes: [...n.values()], edges: e }
  }, [rows])
  return <RelationGraph columns={['Identity', 'Access level', 'Account', 'Scope']} nodes={nodes} edges={edges} height={Math.max(130, Math.min(680, Math.max(...[0, 1, 2, 3].map((c) => nodes.filter((n) => n.col === c).length)) * 52 + 50))} />
}

function ActivityDrawer({ kind, month, onClose }: { kind: string; month: string; onClose: () => void }) {
  const { data, error } = useApi<Activity>('/access/activity', { kind, month: month || undefined })
  const rows = (data?.events ?? []).map((e, i) => ({ ...e, id: i + 1 }))
  const cols: Col<(typeof rows)[number]>[] = [
    { key: 't', label: 'When', render: (e) => <span className="whitespace-nowrap text-xs">{fmtTime(e.time)}</span> },
    { key: 'who', label: 'User / identity', render: (e) => <span className="break-all text-[12.5px] font-medium">{e.target}</span> },
    { key: 'role', label: 'Role / policy', render: (e) => <span className="break-all text-xs">{e.role ?? '—'}</span> },
    { key: 'acct', label: 'Account', render: (e) => <span className="text-xs">{PROVIDER_LABEL[e.provider]} · {e.account_name}</span> },
    { key: 'by', label: 'Done by', render: (e) => <span className="break-all text-xs">{e.initiated_by ?? '—'}</span> },
    { key: 'out', label: 'Outcome', render: (e) => <Pill value={e.outcome === 'success' ? 'COMPLETED' : 'FAILED'} text={e.outcome} /> },
  ]
  return (
    <Drawer title={data?.kinds[kind] ?? 'Activity'} subtitle={data ? `${data.period.label}${data.period.complete ? '' : ' (so far)'} · ${data.total_events} event(s) from cloud audit logs` : undefined} onClose={onClose} width={980}>
      {error ? <ErrorNote message={error.message} /> : !data ? <PageSkeleton tiles={0} /> : <>
        <DataGrid label="Identity activity" cols={cols} rows={rows} empty="No matching events in the collected audit logs for this month." />
        <p className="mt-3 text-[11.5px] text-ink-3">{data.basis} Failed or denied attempts are shown with their outcome and are not counted. Raw events: Live audit → search the operation.</p>
        {rows.length > 0 && <div className="mt-2"><ExportButton name={`IAM activity ${data.period.label} ${kind}`} head={['Time', 'Cloud', 'Account', 'Account ID', 'Change', 'User / identity', 'Role / policy', 'Done by', 'Source IP', 'Operation', 'Outcome', 'Event ID']}
          rows={rows.map((e) => [e.time, e.provider, e.account_name, e.account_id, e.kind_label, e.target, e.role, e.initiated_by, e.source_ip, e.operation, e.outcome, e.event_id])} /></div>}
      </>}
    </Drawer>
  )
}

function MonthlyActivity({ month }: { month: string }) {
  const { data, error } = useApi<Activity>('/access/activity', { month: month || undefined })
  const [open, setOpen] = useState<string | null>(null)
  if (error) return <ErrorNote message={error.message} />
  if (!data) return <PageSkeleton tiles={2} />
  const gaps = data.coverage.filter((c) => !c.collected)
  const card = (kind: string, label: string, tone: string) => (
    <button type="button" onClick={() => setOpen(kind)} className="cn-card group px-5 py-4 text-left transition hover:-translate-y-0.5 hover:shadow-md focus-visible:outline-2">
      <div className="text-[12px] text-ink-3">{label} · {data.period.label}{data.period.complete ? '' : ' (so far)'}</div>
      <div className="tabular mt-1 text-[34px] font-semibold leading-none" style={{ color: tone }}>{fmtInt(data.counts[kind])}</div>
      <div className="mt-2 text-[11.5px] text-ink-3 group-hover:text-accent">See who, when and by whom →</div>
    </button>)
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-2">
        {card('user_created', 'Users added', 'var(--success, #0a7d32)')}
        {card('user_deleted', 'Users deleted', 'var(--critical)')}
      </div>
      <p className="text-[11.5px] text-ink-3">
        Counted from cloud audit logs. Role assignments are not new users: this month {fmtInt(data.counts.role_assigned)} access grant(s), {fmtInt(data.counts.role_removed)} removal(s)
        {' '}(<button type="button" className="text-accent hover:underline" onClick={() => setOpen('role_assigned')}>grants</button> · <button type="button" className="text-accent hover:underline" onClick={() => setOpen('role_removed')}>removals</button>) and {fmtInt(data.counts.service_identity_created)} service identit{data.counts.service_identity_created === 1 ? 'y' : 'ies'} created.
        {data.failed_attempts > 0 && ` ${data.failed_attempts} failed or denied attempt(s) not counted.`}
      </p>
      {gaps.length > 0 && <p className="rounded-lg border px-3 py-2 text-[12.5px]" style={{ borderColor: '#d9a40066', background: '#d9a40012' }}>
        No audit events collected this month for {gaps.map((g) => PROVIDER_LABEL[g.provider]).join(', ')}: additions and deletions there cannot be counted yet.</p>}
      {open && <ActivityDrawer kind={open} month={month} onClose={() => setOpen(null)} />}
    </>
  )
}

function PeopleTable() {
  const [f, setF] = useState({ provider: '', scope: '', q: '', who: 'people' })
  const [person, setPerson] = useState<string | null>(null)
  const { data, error, reload } = useApi<{ total: number; items: Row[] }>('/access/assignments', { provider: f.provider || undefined, scope: f.scope || undefined, q: f.q || undefined, size: 500 })
  const scopes = useApi<{ items: Scope[] }>('/inventory/scopes')
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton tiles={0} />
  const rows = data.items.filter((r) => f.who === 'all' || (f.who === 'people' ? HUMAN.has(r.identity_type) : !HUMAN.has(r.identity_type)))
  const accounts = (scopes.data?.items ?? []).filter((s) => !f.provider || s.provider === f.provider).map((s) => ({ value: s.external_id, label: `${PROVIDER_LABEL[s.provider]} · ${s.name}` }))
  const cols: Col<Row>[] = [
    { key: 'name', label: 'Name', render: (r) => <div className="min-w-[10rem]"><div className="truncate font-medium">{r.display_name ?? email(r) ?? r.principal_id}</div>{!HUMAN.has(r.identity_type) && <div className="text-[11px] text-ink-3">{TYPE_ICON[r.identity_type] ?? r.identity_type}</div>}</div> },
    { key: 'mail', label: 'E-mail', render: (r) => <span className="whitespace-nowrap text-[12.5px]">{email(r) ?? '—'}</span> },
    { key: 'cloud', label: 'Cloud', render: (r) => PROVIDER_LABEL[r.provider] },
    { key: 'acct', label: 'Account / subscription / project', render: (r) => <div><div className="truncate">{r.account_name}</div><div className="font-mono text-[10.5px] text-ink-3">{r.account_id}</div></div> },
    { key: 'role', label: 'Access level', render: (r) => <span><span className="font-medium">{r.access_details}</span>{r.privileged && <span className="ml-1.5 rounded-full px-1.5 py-px text-[10px] font-semibold text-white" style={{ background: 'var(--critical)' }}>privileged</span>}</span> },
    { key: 'scope', label: 'Scope', render: (r) => <span className="text-xs capitalize">{scopeText(r)}{r.access_type !== 'Direct' ? ` · ${r.access_type.toLowerCase()}` : ''}</span> },
    { key: 'status', label: 'Status', render: (r) => <Pill value={r.identity_status === 'Disabled' ? 'EXPIRED' : r.pim_state === 'eligible' ? 'PENDING' : 'COMPLETED'} text={r.identity_status === 'Disabled' ? 'disabled' : r.pim_state === 'eligible' ? 'eligible (PIM)' : 'active'} /> },
    { key: 'created', label: 'Access since', render: (r) => <span className="text-xs" title="First seen by LV NEXUS (providers do not report the grant date for every assignment)">{day(r.first_seen_at)}</span> },
    { key: 'exp', label: 'Expires', render: (r) => <span className="text-xs">{expiry(r) ? day(expiry(r)) : 'No expiry'}</span> },
  ]
  return (
    <section className="cn-card p-4" aria-label="User access">
      <FilterPanel onClear={() => setF({ provider: '', scope: '', q: '', who: 'people' })}>
        <Select label="Show" value={f.who} onChange={(v) => setF({ ...f, who: v || 'all' })} options={[{ value: 'people', label: 'People' }, { value: 'services', label: 'Service identities and groups' }]} all="Everyone" />
        <Select label="Cloud" value={f.provider} onChange={(v) => setF({ ...f, provider: v, scope: '' })} options={(['aws', 'azure', 'gcp'] as const).map((p) => ({ value: p, label: PROVIDER_LABEL[p] }))} />
        <Select label="Account" value={f.scope} onChange={(v) => setF({ ...f, scope: v })} options={accounts} />
        <TextFilter label="Search" value={f.q} onChange={(v) => setF({ ...f, q: v })} placeholder="Name, e-mail, role, account" />
      </FilterPanel>
      <div className="mb-2 flex items-center justify-between text-[12px] text-ink-3"><span>{fmtInt(rows.length)} access assignment(s){data.total > data.items.length ? ` (first ${data.items.length} of ${data.total}; narrow the filters)` : ''}</span>
        <ExportButton name="User access" head={['Name', 'E-mail', 'Cloud', 'Account', 'Account ID', 'Access level', 'Privileged', 'Scope', 'Status', 'Access since (first seen)', 'Expires']}
          rows={rows.map((r) => [r.display_name ?? email(r) ?? r.principal_id, email(r), r.provider, r.account_name, r.account_id, r.access_details, r.privileged ? 'yes' : 'no', scopeText(r), r.identity_status ?? 'Active', r.first_seen_at, expiry(r)])} /></div>
      <DataGrid label="User access" cols={cols} rows={rows} onOpen={(r) => setPerson(r.principal_id)} empty="No access assignments match these filters." />
      {person && (() => {
        const mine = data.items.filter((r) => r.principal_id === person)
        if (!mine.length) return null
        return <Drawer title={mine[0].display_name ?? email(mine[0]) ?? person} subtitle="Access relationships from the collected assignments" onClose={() => setPerson(null)} width={1040}>
          <IdentityGraph rows={mine} />
          <p className="mt-3 text-[11.5px] text-ink-3">Drawn only from collected role assignments{data.total > data.items.length ? ' (within the first 500 loaded; narrow the filters to see every assignment)' : ''}. Dashed links are inherited or group-based grants. MFA and individual permissions are not shown because they are not collected.</p>
        </Drawer>
      })()}
    </section>
  )
}

export default function AccessView() {
  const [view, setView] = useState<'people' | 'tree'>('people')
  const months = useMemo(() => { const out: { value: string; label: string }[] = []; const d = new Date(); d.setDate(1)
    for (let i = 1; i <= 6; i++) { d.setMonth(d.getMonth() - 1); out.push({ value: `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`, label: d.toLocaleDateString('en-IN', { month: 'long', year: 'numeric' }) }) }
    return out }, [])
  const [month, setMonth] = useState('')
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><p className="text-[11px] font-semibold uppercase tracking-[.14em] text-accent">Identity &amp; Access · read-only</p>
          <h1 className="mt-1 text-[28px] font-semibold tracking-tight">User access</h1>
          <p className="mt-1 text-sm text-ink-3">Who has access to which AWS account, Azure subscription and GCP project, at what level, and what changed this month.</p></div>
        <label className="flex items-center gap-2 text-[12px] text-ink-3">Month
          <select className="cn-input h-8 text-sm" value={month} onChange={(e) => setMonth(e.target.value)} aria-label="Month"><option value="">This month</option>{months.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}</select></label>
      </div>
      <MonthlyActivity month={month} />
      <Segmented label="View" value={view} onChange={setView} options={[{ value: 'people', label: 'People and access', icon: <Users size={13} aria-hidden /> }, { value: 'tree', label: 'By account', icon: <KeyRound size={13} aria-hidden /> }]} />
      {view === 'people' ? <PeopleTable /> : <AccessTree />}
    </div>
  )
}
