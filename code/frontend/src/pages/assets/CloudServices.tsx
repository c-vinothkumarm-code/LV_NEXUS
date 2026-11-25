import { Activity, Download, FileUp, Save, Server, SlidersHorizontal, Upload } from 'lucide-react'
import { useMemo, useState, type ReactNode } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useCan } from '../../auth/AuthContext'
import { ProviderBadge } from '../../components/hero'
import { DataGrid, Drawer, FilterPanel, KV, Pager, Section, Select, TextFilter, download, fileToBase64, type Col } from '../../components/secops'
import { useToast } from '../../components/Toast'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_LABEL, StatTile, fmtAgo, fmtTime, fmtUsd } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'

/* ---- types (mirror backend/app/services/assets/catalog.py) ---- */
export interface Asset {
  kind: 'server' | 'service'; provider: string; scope: string; scope_name: string; environment: string | null; resource_id: string; name: string
  hostname: string | null; ip_address: string | null; public_ip: string | null; region: string | null; resource_type: string; category: string
  size: string | null; server_status: string | null; guest_os: string | null; guest_os_source: string | null; cpus: number | null; memory_gb: number | null
  nic_count: number | null; provisioned_gb: number | null; used_gb: number | null; used_source: string | null
  native_backup_status: string | null; native_backup_last_at: string | null; native_backup_detail: string | null; commvault_backup_status: string | null
  backup_protected: boolean | null; create_date: string | null; first_seen_at: string | null; last_activity_at: string | null; last_login_at: string | null
  last_login_source: string | null; last_monitoring_at: string | null; cpu_avg: number | null; network_mb_per_day: number | null
  activity_status: string; activity_reason: string; recommended_action: string; stopped_since: string | null; estimated_monthly_cost_usd: number | null
  tag_owner: string | null; details_collected_at: string | null; gaps: Record<string, string>
  [manual: string]: unknown
}
interface ManualField { field: string; label: string; kind: 'text' | 'email' | 'choice' | 'date'; options: string[] }
interface Kpis {
  total: number; servers: number; services: number; by_activity: Record<string, number>; missing_spoc: number; servers_not_backed_up: number
  servers_backup_unknown: number; pii_assets: number; idle_monthly_cost_usd: number | null; idle_cost_assets_with_cost: number; details_missing: number
}
interface ListResp { total: number; page: number; size: number; kpis: Kpis; items: Asset[]; manual_fields: ManualField[]
  facets: { providers: string[]; scopes: [string, string, string][]; departments: string[]; spocs: string[]; environments: string[]; activity: string[] } }

const ACTIVITY_TONE: Record<string, string> = {
  Active: 'text-good', 'Low Activity': 'text-warning', Inactive: 'text-serious', Stopped: 'text-ink-3', 'Terminated / Deleted': 'text-ink-3', Unknown: 'text-ink-3',
}
const DOT: Record<string, string> = { Active: '●', 'Low Activity': '◐', Inactive: '○', Stopped: '■', 'Terminated / Deleted': '✕', Unknown: '?' }
export const CLOUD_SERVICES_TABS = [{ to: '/cloud-services', label: 'Asset inventory' }, { to: '/cloud-services/activity', label: 'Activity review' }]

export function ActivityBadge({ value }: { value: string }) {
  return <span className={`inline-flex items-center gap-1 whitespace-nowrap text-xs font-semibold ${ACTIVITY_TONE[value] ?? 'text-ink-3'}`}><span aria-hidden>{DOT[value] ?? '·'}</span>{value}</span>
}
const nc = (reason?: string) => <span className="text-ink-3" title={reason}>{reason ? (reason.startsWith('Not collected') ? reason : `Not collected – ${reason}`) : 'Not collected'}</span>
const val = (v: unknown, gap?: string, suffix = ''): ReactNode => (v === null || v === undefined || v === '' ? nc(gap) : `${v}${suffix}`)
const backupText = (a: Asset) => {
  const parts = [a.native_backup_status ? `Cloud: ${a.native_backup_status}` : null, a.commvault_backup_status ? `Commvault: ${a.commvault_backup_status}` : null].filter(Boolean)
  return parts.length ? parts.join(' · ') : 'Not recorded'
}
export const assetLink = (a: { provider: string; resource_id: string }) => `/cloud-services/asset?provider=${a.provider}&id=${encodeURIComponent(a.resource_id)}`

function useListParams() {
  const [sp, setSp] = useSearchParams()
  const get = (k: string) => sp.get(k) ?? ''
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); if (k !== 'page') n.delete('page'); setSp(n, { replace: true }) }
  return { get, set, clear: () => setSp(new URLSearchParams(), { replace: true }), sp }
}

/* ============================================================== inventory */
export default function CloudServicesInventory() {
  const p = useListParams()
  const navigate = useNavigate()
  const canImport = useCan('assets:import')
  const toast = useToast()
  const [bump, setBump] = useState(0)
  const [importing, setImporting] = useState(false)
  const filters = Object.fromEntries(['provider', 'scope', 'kind', 'department', 'spoc', 'activity', 'backup', 'environment', 'q', 'missing_spoc', 'sort', 'order']
    .map((k) => [k, p.get(k) || undefined]))
  const page = Number(p.get('page') || 1)
  const { data, error, reload } = useApi<ListResp>('/assets', { ...filters, page, size: 50 }, bump)
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton tiles={6} />
  const k = data.kpis
  const exportQs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v) as [string, string][]).toString()
  const exp = (fmt: string) => download(`/api/v1/assets/export?format=${fmt}${exportQs ? `&${exportQs}` : ''}`).catch((e) => toast({ kind: 'error', title: 'Export failed', text: e.message }))
  const rows = data.items.map((a, i) => ({ ...a, id: i }))
  const sort = { key: p.get('sort') || 'name', order: (p.get('order') || 'asc') as 'asc' | 'desc' }
  const cols: Col<Asset & { id: number }>[] = [
    { key: 'name', label: 'Server / resource', sortable: true, render: (a) => <div className="min-w-[12rem]"><Link to={assetLink(a)} className="font-medium text-ink hover:underline">{a.name}</Link>
      <div className="text-[11px] text-ink-3">{a.kind === 'server' ? `VM · ${a.size ?? ''}` : a.category}{a.hostname ? ` · ${a.hostname}` : ''}</div></div> },
    { key: 'provider', label: 'Cloud / scope', sortable: true, render: (a) => <div className="flex items-center gap-2"><ProviderBadge provider={a.provider} size={18} /><span className="text-xs">{a.scope_name}<br /><span className="text-ink-3">{a.region ?? ''}</span></span></div> },
    { key: 'ip', label: 'IP address', render: (a) => <span className="tabular text-xs">{a.ip_address ?? '—'}{a.public_ip ? <><br /><span className="text-ink-3">public {a.public_ip}</span></> : null}</span> },
    { key: 'server_status', label: 'Status', sortable: true, render: (a) => <span className="text-xs">{a.server_status ?? '—'}</span> },
    { key: 'activity_status', label: 'Activity', sortable: true, render: (a) => <span title={a.activity_reason}><ActivityBadge value={a.activity_status} /></span> },
    { key: 'last_activity_at', label: 'Last activity', sortable: true, render: (a) => <span className="text-xs" title={fmtTime(a.last_activity_at)}>{a.last_activity_at ? fmtAgo(a.last_activity_at) : 'Not recorded'}</span> },
    { key: 'server_spoc_email', label: 'SPOC', sortable: true, render: (a) => a.server_spoc_email ? <span className="text-xs">{(a.server_spoc_name as string) || (a.server_spoc_email as string)}</span> : <span className="text-xs font-semibold text-warning">Not assigned</span> },
    { key: 'department', label: 'Department', sortable: true, render: (a) => <span className="text-xs">{(a.department as string) ?? '—'}</span> },
    { key: 'backup', label: 'Backup', render: (a) => <span className={`text-xs ${a.backup_protected === false ? 'font-semibold text-serious' : ''}`}>{backupText(a)}</span> },
    { key: 'estimated_monthly_cost_usd', label: 'Est. cost / month', sortable: true, render: (a) => <span className="tabular text-xs">{a.estimated_monthly_cost_usd === null ? 'Not collected' : fmtUsd(a.estimated_monthly_cost_usd)}</span> },
  ]
  const onSort = (key: string) => { const n = new URLSearchParams(p.sp); n.set('sort', key); n.set('order', sort.key === key && sort.order === 'asc' ? 'desc' : 'asc'); n.delete('page'); navigate({ search: n.toString() }, { replace: true }) }
  return (
    <div className="space-y-5">
      <PageHeader eyebrow="Cloud Services Management" title="Cloud services and assets"
        description="Every server and cloud service across AWS, Azure and Google Cloud, with collected details, business owners, activity and backup status. Collected values come from read-only cloud APIs; business fields are maintained by your teams and never overwritten by a sync."
        action={<div className="flex flex-wrap gap-2">
          <button className="cn-btn cn-btn-ghost h-9" onClick={() => exp('xlsx')}><Download size={14} />Excel</button>
          <button className="cn-btn cn-btn-ghost h-9" onClick={() => exp('csv')}><Download size={14} />CSV</button>
          {canImport && <button className="cn-btn cn-btn-primary h-9" onClick={() => setImporting(true)}><Upload size={14} />Import metadata</button>}
        </div>} />
      <Tabs active="/cloud-services" />
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6">
        <StatTile label="Assets" num={k.total} note={`${k.servers} servers · ${k.services} services`} icon={<Server size={14} />} />
        <StatTile label="Active" num={k.by_activity.Active} tone="good" />
        <StatTile label="Low activity" num={k.by_activity['Low Activity']} tone="warning" />
        <StatTile label="Inactive" num={k.by_activity.Inactive} tone={k.by_activity.Inactive ? 'serious' : 'neutral'} note={k.idle_monthly_cost_usd !== null ? `${fmtUsd(k.idle_monthly_cost_usd)}/month on idle + stopped` : 'Idle cost not collected'} />
        <StatTile label="Stopped" num={k.by_activity.Stopped} note={`${k.by_activity.Unknown} unknown (no monitoring data)`} />
        <StatTile label="No Server SPOC" num={k.missing_spoc} tone={k.missing_spoc ? 'warning' : 'good'} note={`${k.servers_not_backed_up} servers without backup · ${k.servers_backup_unknown} unknown`} />
      </div>
      <FilterPanel onClear={p.clear}>
        <Select label="Cloud" value={p.get('provider')} onChange={(v) => p.set('provider', v)} options={data.facets.providers.map((x) => ({ value: x, label: PROVIDER_LABEL[x] ?? x }))} />
        <Select label="Account / subscription / project" value={p.get('scope')} onChange={(v) => p.set('scope', v)}
          options={data.facets.scopes.filter(([pr]) => !p.get('provider') || pr === p.get('provider')).map(([pr, id, name]) => ({ value: id, label: `${PROVIDER_LABEL[pr]} · ${name}` }))} />
        <Select label="Kind" value={p.get('kind')} onChange={(v) => p.set('kind', v)} options={[{ value: 'server', label: 'Servers (VMs)' }, { value: 'service', label: 'Other services' }]} />
        <Select label="Activity" value={p.get('activity')} onChange={(v) => p.set('activity', v)} options={data.facets.activity} />
        <Select label="Backup" value={p.get('backup')} onChange={(v) => p.set('backup', v)} options={[{ value: 'protected', label: 'Protected' }, { value: 'not_protected', label: 'Not protected' }, { value: 'unknown', label: 'Unknown' }]} />
        <Select label="Department" value={p.get('department')} onChange={(v) => p.set('department', v)} options={data.facets.departments} />
        <Select label="Environment" value={p.get('environment')} onChange={(v) => p.set('environment', v)} options={data.facets.environments} />
        <TextFilter label="SPOC" value={p.get('spoc')} onChange={(v) => p.set('spoc', v)} placeholder="name or e-mail" />
        <TextFilter label="Search" value={p.get('q')} onChange={(v) => p.set('q', v)} placeholder="name, IP, hostname, ID" />
        <label className="flex items-center gap-1.5 self-end pb-2 text-xs text-ink-2"><input type="checkbox" checked={p.get('missing_spoc') === 'true'} onChange={(e) => p.set('missing_spoc', e.target.checked ? 'true' : '')} />No SPOC only</label>
      </FilterPanel>
      <DataGrid label="Cloud assets" cols={cols} rows={rows} sort={sort} onSort={onSort} onOpen={(a) => navigate(assetLink(a))} empty="No assets match these filters." />
      <Pager page={page} pageSize={50} total={data.total} onPage={(n) => p.set('page', String(n))} />
      {importing && <ImportDrawer onClose={() => setImporting(false)} onDone={() => { setImporting(false); setBump((b) => b + 1) }} fields={data.manual_fields} />}
    </div>
  )
}

function Tabs({ active }: { active: string }) {
  return (
    <nav className="flex gap-1 border-b border-line" aria-label="Cloud Services Management">
      {CLOUD_SERVICES_TABS.map((t) => <Link key={t.to} to={t.to} aria-current={active === t.to ? 'page' : undefined}
        className={`-mb-px border-b-2 px-3 py-2 text-sm ${active === t.to ? 'border-accent font-semibold text-ink' : 'border-transparent text-ink-3 hover:text-ink'}`}>{t.label}</Link>)}
    </nav>
  )
}

interface ImportRow { row: number; provider: string; resource_id: string; status: 'ok' | 'unchanged' | 'error'; error: string | null; changes: Record<string, { old: string | null; new: string | null }> }
interface ImportResp { rows: ImportRow[]; valid: number; invalid: number; changes: number; ignored_columns: string[]; applied: boolean; fields_changed: number }

function ImportDrawer({ onClose, onDone, fields }: { onClose: () => void; onDone: () => void; fields: ManualField[] }) {
  const toast = useToast()
  const [file, setFile] = useState<File | null>(null)
  const [plan, setPlan] = useState<ImportResp | null>(null)
  const [busy, setBusy] = useState(false)
  const label = useMemo(() => Object.fromEntries(fields.map((f) => [f.field, f.label])), [fields])
  const send = async (apply: boolean) => {
    if (!file) return
    setBusy(true)
    try {
      const r = await api.post<ImportResp>('/assets/import', { filename: file.name, content_base64: await fileToBase64(file), apply })
      setPlan(r)
      if (apply) { toast({ kind: 'success', title: `Imported: ${r.fields_changed} field(s) updated` }); onDone() }
    } catch (e) { toast({ kind: 'error', title: 'Import failed', text: e instanceof Error ? e.message : '' }) }
    finally { setBusy(false) }
  }
  return (
    <Drawer title="Import business metadata" subtitle="CSV or Excel, matched on Cloud Provider + Resource ID" onClose={onClose}>
      <div className="space-y-4 text-sm">
        <ol className="list-decimal space-y-1 pl-5 text-ink-2">
          <li>Export the register (Excel), fill the light-blue business columns, save.</li>
          <li>Choose the file and run the check: nothing is written yet.</li>
          <li>Apply when there are no errors. Collected columns in the file are ignored.</li>
        </ol>
        <input type="file" accept=".csv,.xlsx" aria-label="Import file" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setPlan(null) }} />
        <div className="flex gap-2">
          <button className="cn-btn cn-btn-ghost" disabled={!file || busy} onClick={() => send(false)}><FileUp size={14} />Check file</button>
          <button className="cn-btn cn-btn-primary" disabled={!plan || plan.invalid > 0 || plan.changes === 0 || busy || plan.applied} onClick={() => send(true)}>Apply {plan?.changes ?? 0} change(s)</button>
        </div>
        {plan && (
          <div className="space-y-2">
            <p className="text-xs text-ink-2">{plan.valid} valid row(s), <b className={plan.invalid ? 'text-critical' : ''}>{plan.invalid} with errors</b>, {plan.changes} field change(s).
              {plan.ignored_columns.length > 0 && ` Ignored collected columns: ${plan.ignored_columns.join(', ')}.`}</p>
            <ul className="max-h-[50vh] space-y-1 overflow-auto rounded-lg bg-surface-2 p-2 text-xs">
              {plan.rows.filter((r) => r.status !== 'unchanged').map((r) => (
                <li key={r.row}><b>Row {r.row}</b> {r.provider} {r.resource_id.split('/').pop()}: {r.status === 'error' ? <span className="text-critical">{r.error}</span>
                  : Object.entries(r.changes).map(([f, c]) => `${label[f] ?? f}: ${c.old ?? '∅'} → ${c.new ?? '∅'}`).join('; ')}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Drawer>
  )
}

/* ============================================================== detail */
interface Detail extends Asset {
  can_edit: boolean; manual_fields: ManualField[]
  metadata_history: { field: string; label: string; old: string | null; new: string | null; source: string; by: string; at: string }[]
  activity_history: { day: string; classification: string; reason: string | null; state: string | null; cpu_avg: number | null; network_mb_per_day: number | null }[]
  inventory_changes: { field: string; old: string | null; new: string | null; at: string; source: string }[]
  access: { principal_id: string; principal_type: string; role: string; privileged: boolean; level: string; access_type: string; expires_at: string | null }[]
  access_total: number; access_visible: boolean
}

export function CloudServiceAsset() {
  const [sp] = useSearchParams()
  const provider = sp.get('provider') ?? '', id = sp.get('id') ?? ''
  const toast = useToast()
  const [bump, setBump] = useState(0)
  const { data, error, reload } = useApi<Detail>('/assets/item', { provider, resource_id: id }, bump)
  const [form, setForm] = useState<Record<string, string> | null>(null)
  const [busy, setBusy] = useState(false)
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton tiles={0} />
  const g = data.gaps ?? {}
  const edit = () => setForm(Object.fromEntries(data.manual_fields.map((f) => [f.field, (data[f.field] as string) ?? ''])))
  const save = async () => {
    if (!form) return
    setBusy(true)
    try {
      const r = await api.put<{ changed: string[] }>('/assets/metadata', { provider, resource_id: data.resource_id, fields: form })
      toast({ kind: 'success', title: r.changed.length ? `Saved ${r.changed.length} field(s)` : 'No changes' })
      setForm(null); setBump((b) => b + 1)
    } catch (e) { toast({ kind: 'error', title: 'Not saved', text: e instanceof Error ? e.message : '' }) }
    finally { setBusy(false) }
  }
  const server = data.kind === 'server'
  return (
    <div className="space-y-5">
      <div className="text-xs text-ink-3"><Link to="/cloud-services" className="hover:underline">Cloud services and assets</Link> / {data.name}</div>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <ProviderBadge provider={data.provider} size={36} />
          <div>
            <h1 className="cn-h-page">{data.name}</h1>
            <p className="text-sm text-ink-2">{data.kind === 'server' ? 'Virtual machine' : data.resource_type} · {data.scope_name} ({data.scope}) · {data.region ?? 'global'}</p>
            <p className="mt-0.5 break-all font-mono text-[11px] text-ink-3">{data.resource_id}</p>
          </div>
        </div>
        <div className="cn-card max-w-md px-4 py-3 text-sm">
          <ActivityBadge value={data.activity_status} />
          <p className="mt-1 text-xs text-ink-2">{data.activity_reason}</p>
          <p className="mt-2 text-xs"><b>Recommended:</b> {data.recommended_action}</p>
          <p className="mt-1 text-[11px] text-ink-3">No resource is changed automatically; any action needs business validation and approval.</p>
        </div>
      </div>
      <div className="grid gap-5 xl:grid-cols-2">
        <Section title="Collected details (read-only cloud APIs)">
          <KV items={[
            ['Server status', val(data.server_status)], ['IP address', val(data.ip_address)], ['Public IP', data.public_ip ?? 'None'],
            ...(server ? [
              ['Hostname', val(data.hostname, g.hostname)], ['Guest OS', data.guest_os ? `${data.guest_os}${data.guest_os_source ? ` (${data.guest_os_source})` : ''}` : nc(g.guest_os)],
              ['CPUs', val(data.cpus, g.cpus)], ['Memory', val(data.memory_gb, g.memory_gb, ' GB')], ['NICs', val(data.nic_count, g.nic_count)],
              ['Provisioned space', val(data.provisioned_gb, g.provisioned_gb, ' GB')], ['Used space', data.used_gb !== null ? `${data.used_gb} GB (${data.used_source})` : nc(g.used_space)],
            ] as [string, ReactNode][] : [['Type / SKU', `${data.resource_type}${data.size ? ` · ${data.size}` : ''}`], ['Owner tag', data.tag_owner ?? 'None']] as [string, ReactNode][]),
            ['Cloud-native backup', data.native_backup_status ? `${data.native_backup_status}${data.native_backup_last_at ? ` · last ${fmtTime(data.native_backup_last_at)}` : ''}` : nc(g.native_backup_status)],
            ['Create date', data.create_date ? fmtTime(data.create_date) : `Not reported (first seen by LV NEXUS ${fmtTime(data.first_seen_at)})`],
            ['Last activity', data.last_activity_at ? fmtTime(data.last_activity_at) : 'No management activity recorded'],
            ['Last login', data.last_login_at ? `${fmtTime(data.last_login_at)} (${data.last_login_source})` : nc(g.last_login)],
            ['Last monitoring', data.last_monitoring_at ? fmtTime(data.last_monitoring_at) : 'No metrics collected'],
            ['Avg CPU / network', data.cpu_avg !== null ? `${data.cpu_avg}% · ${data.network_mb_per_day ?? '—'} MB/day` : 'Not collected'],
            ['Est. monthly cost', data.estimated_monthly_cost_usd !== null ? fmtUsd(data.estimated_monthly_cost_usd) : nc(g.estimated_monthly_cost)],
            ['Details collected', data.details_collected_at ? fmtTime(data.details_collected_at) : (server ? nc(g.details) : 'Not applicable')],
          ]} />
        </Section>
        <Section title="Business metadata" action={data.can_edit && !form ? <button className="cn-btn cn-btn-ghost h-8 text-xs" onClick={edit}>Edit</button> : undefined}>
          {form ? (
            <div className="grid gap-3 sm:grid-cols-2">
              {data.manual_fields.map((f) => (
                <label key={f.field} className="flex flex-col gap-1 text-[11px] text-ink-3">{f.label}
                  {f.kind === 'choice' ? (
                    <select className="cn-input text-[12.5px] text-ink" value={form[f.field] ?? ''} onChange={(e) => setForm({ ...form, [f.field]: e.target.value })}>
                      <option value="">—</option>{f.options.map((o) => <option key={o}>{o}</option>)}
                    </select>
                  ) : <input className="cn-input text-[12.5px] text-ink" type={f.kind === 'date' ? 'date' : f.kind === 'email' ? 'email' : 'text'} value={form[f.field] ?? ''}
                    onChange={(e) => setForm({ ...form, [f.field]: e.target.value })} />}
                </label>
              ))}
              <div className="flex gap-2 sm:col-span-2">
                <button className="cn-btn cn-btn-primary" disabled={busy} onClick={save}><Save size={14} />Save</button>
                <button className="cn-btn cn-btn-ghost" onClick={() => setForm(null)}>Cancel</button>
              </div>
            </div>
          ) : <KV items={data.manual_fields.map((f) => [f.label, (data[f.field] as string) || <span className="text-ink-3">Not set</span>])} />}
        </Section>
      </div>
      <Section title="Activity history (daily review)">
        {data.activity_history.length ? (
          <table className="cn-table w-full text-left text-sm"><thead><tr className="text-[11px] uppercase text-ink-3"><th className="px-2 py-1">Day</th><th className="px-2 py-1">Activity</th><th className="px-2 py-1">State</th><th className="px-2 py-1">Avg CPU</th><th className="px-2 py-1">Network MB/day</th><th className="px-2 py-1">Reason</th></tr></thead>
            <tbody>{data.activity_history.map((h) => <tr key={h.day} className="border-t border-line/70"><td className="px-2 py-1 text-xs">{h.day}</td><td className="px-2 py-1"><ActivityBadge value={h.classification} /></td>
              <td className="px-2 py-1 text-xs">{h.state ?? '—'}</td><td className="tabular px-2 py-1 text-xs">{h.cpu_avg?.toFixed(1) ?? '—'}</td><td className="tabular px-2 py-1 text-xs">{h.network_mb_per_day?.toFixed(0) ?? '—'}</td><td className="px-2 py-1 text-xs text-ink-2">{h.reason}</td></tr>)}</tbody></table>
        ) : <p className="text-sm text-ink-3">No daily review yet (job asset_activity_review runs every morning).</p>}
      </Section>
      <div className="grid gap-5 xl:grid-cols-2">
        <Section title="Inventory changes (collected)">
          {data.inventory_changes.length ? <ul className="space-y-1 text-xs">{data.inventory_changes.map((c, i) => <li key={i}><b>{c.field}</b>: {c.old ?? '∅'} → {c.new ?? '∅'} <span className="text-ink-3">· {fmtTime(c.at)}</span></li>)}</ul>
            : <p className="text-sm text-ink-3">No changes observed.</p>}
        </Section>
        <Section title="Business metadata changes">
          {data.metadata_history.length ? <ul className="space-y-1 text-xs">{data.metadata_history.map((h, i) => <li key={i}><b>{h.label}</b>: {h.old ?? '∅'} → {h.new ?? '∅'} <span className="text-ink-3">· {h.by} · {h.source} · {fmtTime(h.at)}</span></li>)}</ul>
            : <p className="text-sm text-ink-3">Not edited yet.</p>}
        </Section>
      </div>
      {data.access_visible && (
        <Section title={`Who has access to this resource (${data.access_total})`}>
          {data.access.length ? (
            <table className="cn-table w-full text-left text-sm"><thead><tr className="text-[11px] uppercase text-ink-3"><th className="px-2 py-1">Principal</th><th className="px-2 py-1">Role</th><th className="px-2 py-1">Where granted</th><th className="px-2 py-1">Expires</th></tr></thead>
              <tbody>{data.access.map((a, i) => <tr key={i} className="border-t border-line/70"><td className="px-2 py-1 text-xs">{a.principal_id}<span className="text-ink-3"> · {a.principal_type}</span></td>
                <td className="px-2 py-1 text-xs">{a.role}{a.privileged ? <b className="text-serious"> · privileged</b> : null}</td><td className="px-2 py-1 text-xs">{a.level} · {a.access_type}</td><td className="px-2 py-1 text-xs">{a.expires_at ? fmtTime(a.expires_at) : 'No expiry'}</td></tr>)}</tbody></table>
          ) : <p className="text-sm text-ink-3">No access assignments collected for this resource or its parents.</p>}
        </Section>
      )}
    </div>
  )
}

/* ============================================================== activity review */
interface Policy { values: Record<string, number | boolean | string[]>; defaults: Record<string, unknown>; limits: Record<string, [number, number]> }
const POLICY_LABEL: Record<string, string> = {
  window_days: 'Utilisation window (days)', min_coverage_hours: 'Minimum monitoring data (hours)', low_cpu_percent: 'Low activity below CPU %',
  inactive_cpu_percent: 'Inactive below CPU %', inactive_network_mb_per_day: 'Inactive below network MB/day', inactive_days: 'Inactive after days without management activity',
  stopped_review_days: 'Review stopped servers after days', service_active_days: 'Services active if changed within days', activity_lookback_days: 'Audit look-back (days)',
  notify_every_days: 'Send a SPOC digest every N days',
}

export function CloudServicesActivity() {
  const p = useListParams()
  const canConfigure = useCan('assets:configure')
  const navigate = useNavigate()
  const toast = useToast()
  const [bump, setBump] = useState(0)
  const [editing, setEditing] = useState<Record<string, string> | null>(null)
  const activity = p.get('activity') || 'Inactive,Stopped,Low Activity'
  const { data, error, reload } = useApi<ListResp>('/assets', { activity, provider: p.get('provider') || undefined, sort: 'activity_status', size: 500 }, bump)
  const pol = useApi<Policy>('/assets/policy', undefined, bump)
  const kp = useApi<Kpis>('/assets/kpis', undefined, bump)
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data || !pol.data) return <PageSkeleton tiles={4} />
  const savePolicy = async () => {
    if (!editing) return
    try {
      await api.put('/assets/policy', { values: Object.fromEntries(Object.entries(editing).map(([k, v]) => [k, Number(v)])) })
      toast({ kind: 'success', title: 'Thresholds saved' }); setEditing(null); setBump((b) => b + 1)
    } catch (e) { toast({ kind: 'error', title: 'Not saved', text: e instanceof Error ? e.message : '' }) }
  }
  const order = ['Inactive', 'Stopped', 'Low Activity', 'Unknown', 'Active', 'Terminated / Deleted']
  const rows = [...data.items].sort((a, b) => order.indexOf(a.activity_status) - order.indexOf(b.activity_status)).map((a, i) => ({ ...a, id: i }))
  const cols: Col<Asset & { id: number }>[] = [
    { key: 'name', label: 'Asset', render: (a) => <div><Link to={assetLink(a)} className="font-medium hover:underline">{a.name}</Link><div className="text-[11px] text-ink-3">{PROVIDER_LABEL[a.provider]} · {a.scope_name}</div></div> },
    { key: 'a', label: 'Activity', render: (a) => <div className="max-w-xs"><ActivityBadge value={a.activity_status} /><div className="text-[11px] text-ink-3">{a.activity_reason}</div></div> },
    { key: 'l', label: 'Last activity / login / monitoring', render: (a) => <div className="text-[11px]">{a.last_activity_at ? fmtAgo(a.last_activity_at) : 'no activity recorded'}<br />{a.last_login_at ? `login ${fmtAgo(a.last_login_at)}` : 'login not collected'}<br />{a.last_monitoring_at ? `metrics ${fmtAgo(a.last_monitoring_at)}` : 'no metrics'}</div> },
    { key: 'c', label: 'Est. cost / month', render: (a) => <span className="tabular text-xs">{a.estimated_monthly_cost_usd === null ? 'Not collected' : fmtUsd(a.estimated_monthly_cost_usd)}</span> },
    { key: 's', label: 'SPOC', render: (a) => <span className="text-xs">{(a.server_spoc_name as string) || (a.server_spoc_email as string) || <b className="text-warning">Not assigned</b>}</span> },
    { key: 'r', label: 'Recommended action', render: (a) => <span className="text-xs">{a.recommended_action}</span> },
  ]
  const v = pol.data.values
  return (
    <div className="space-y-5">
      <PageHeader eyebrow="Cloud Services Management" title="Activity review"
        description="Assets classified from collected metrics, audit logs and power state. Inactive and long-stopped assets are sent to their Server SPOC (copy to the Reporting Manager) in one digest. Nothing is stopped or deleted automatically." />
      <Tabs active="/cloud-services/activity" />
      <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {['Inactive', 'Stopped', 'Low Activity', 'Unknown', 'Active', 'Terminated / Deleted'].map((c) => (
          <button key={c} className={`cn-card cn-lift px-4 py-3 text-left ${activity === c ? 'ring-2 ring-[var(--accent)]' : ''}`} onClick={() => p.set('activity', activity === c ? '' : c)}>
            <ActivityBadge value={c} /><div className="tabular mt-1 text-2xl font-semibold">{kp.data?.by_activity[c] ?? '—'}</div>
          </button>
        ))}
      </div>
      <FilterPanel onClear={p.clear}>
        <Select label="Cloud" value={p.get('provider')} onChange={(x) => p.set('provider', x)} options={data.facets.providers.map((x) => ({ value: x, label: PROVIDER_LABEL[x] ?? x }))} />
        <Select label="Activity" value={p.get('activity')} onChange={(x) => p.set('activity', x)} all="Needs review (inactive, stopped, low)" options={data.facets.activity} />
      </FilterPanel>
      <DataGrid label="Assets needing review" cols={cols} rows={rows} onOpen={(a) => navigate(assetLink(a))} empty="Nothing needs review with the current thresholds." />
      <Section title="Thresholds and notifications" action={canConfigure && !editing ? <button className="cn-btn cn-btn-ghost h-8 text-xs" onClick={() => setEditing(Object.fromEntries(Object.keys(POLICY_LABEL).map((k) => [k, String(v[k])])))}><SlidersHorizontal size={13} />Edit</button> : undefined}>
        {editing ? (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Object.keys(POLICY_LABEL).map((k) => (
              <label key={k} className="flex flex-col gap-1 text-[11px] text-ink-3">{POLICY_LABEL[k]}
                <input className="cn-input text-[12.5px] text-ink" type="number" step="any" min={pol.data!.limits[k]?.[0]} max={pol.data!.limits[k]?.[1]} value={editing[k]} onChange={(e) => setEditing({ ...editing, [k]: e.target.value })} /></label>
            ))}
            <div className="flex gap-2 sm:col-span-2 lg:col-span-3"><button className="cn-btn cn-btn-primary" onClick={savePolicy}><Save size={14} />Save</button><button className="cn-btn cn-btn-ghost" onClick={() => setEditing(null)}>Cancel</button></div>
          </div>
        ) : <KV items={[...Object.keys(POLICY_LABEL).map((k) => [POLICY_LABEL[k], String(v[k])] as [string, ReactNode]),
          ['SPOC digests', v.notify_enabled ? `On · ${(v.notify_classifications as string[]).join(', ')}` : 'Off']]} />}
        <p className="mt-2 flex items-center gap-1 text-[11px] text-ink-3"><Activity size={12} />Servers are Inactive only when CPU and network are both below the thresholds and there was no management activity; with too little monitoring data they are Unknown, never Inactive.</p>
      </Section>
    </div>
  )
}
