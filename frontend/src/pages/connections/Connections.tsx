import { Cable } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Panel } from '../../components/hero'
import { DataGrid, Drawer, FilterPanel, KV, Pill, Section, Select, TextFilter, type Col } from '../../components/secops'
import { ErrorNote, ExportButton, PageHeader, PageSkeleton, PROVIDER_LABEL, fmtAgo, fmtTime } from '../../components/ui'
import { useApi } from '../../hooks/useApi'

interface Source { api: string | null; state: string; last_success: string | null; last_failure: string | null; failure_reason: string | null; gate_check: string; gate_status: string }
interface Conn {
  provider: string; external_id: string; name: string; parent: string | null; environment: string | null; organization: string | null; billing_account: string | null
  is_management: boolean; provider_state: string; onboarding_status: string; monitoring_enabled: boolean; authentication: string; permissions: string
  permission_detail: string | null; checks: Record<string, string>; last_seen_at: string | null; last_validated_at: string | null; sources: Record<string, Source>; health: string
  coverage: { resources: number; activity_events_24h: number; last_cost_day: string | null; access_assignments: number; security_findings: number }
}
const STATE_TONE: Record<string, string> = { OK: 'APPROVED', FAILING: 'Critical', NOT_PERMITTED: 'High', NEVER_SYNCHRONIZED: 'NOT_CONFIGURED' }
const HEALTH_TONE: Record<string, string> = { Healthy: 'APPROVED', Degraded: 'High', 'Not connected': 'Critical' }
const SRC_LABEL: Record<string, string> = { discovery: 'Discovery', inventory: 'Inventory', activity: 'Activity logs', cost: 'Billing', cost_detail: 'Cost detail', iam: 'IAM',
  security: 'Security findings', metrics: 'Metrics' }

/** One row per account / subscription / project with authentication, permissions and per-API synchronization state. */
export default function Connections() {
  const [f, setF] = useState({ provider: '', health: '', q: '' })
  const [open, setOpen] = useState<Conn | null>(null)
  const { data, error, reload } = useApi<{ items: Conn[]; totals: Record<string, Record<string, number>>; sources: Record<string, string>; tenants: string[] }>(
    '/connections/registry', { provider: f.provider || undefined })
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return <PageSkeleton tiles={3} />
  const rows = data.items.filter((c) => (!f.health || c.health === f.health) && (!f.q || `${c.name} ${c.external_id}`.toLowerCase().includes(f.q.toLowerCase())))
    .map((c, i) => ({ ...c, id: i }))
  const cols: Col<Conn & { id: number }>[] = [
    { key: 'n', label: 'Account / subscription / project', render: (c) => <div className="max-w-[260px]"><div className="truncate font-medium">{c.name || c.external_id}{c.is_management && <span className="ml-1 text-[10px] text-ink-3">management</span>}</div>
      <div className="truncate font-mono text-[11px] text-ink-3">{PROVIDER_LABEL[c.provider]} · {c.external_id}</div></div> },
    { key: 'h', label: 'Health', render: (c) => <Pill value={HEALTH_TONE[c.health]} text={c.health} /> },
    { key: 'a', label: 'Auth / permissions', render: (c) => <div className="text-xs">{c.authentication} / {c.permissions}</div> },
    { key: 's', label: 'Data sources', render: (c) => <div className="flex flex-wrap gap-1">{Object.entries(c.sources).map(([k, v]) => <span key={k} title={`${SRC_LABEL[k]}: ${v.state}${v.failure_reason ? ` — ${v.failure_reason}` : ''}`}
      className="rounded px-1 text-[10px]" style={{ background: `color-mix(in srgb, ${v.state === 'OK' ? 'var(--good)' : v.state === 'FAILING' ? 'var(--critical)' : v.state === 'NOT_PERMITTED' ? '#e0a100' : 'var(--ink-3)'} 18%, transparent)` }}>{SRC_LABEL[k]}</span>)}</div> },
    { key: 'c', label: 'Coverage', render: (c) => <div className="text-[11px] text-ink-3">{c.coverage.resources} resources · {c.coverage.activity_events_24h} events/24h · {c.coverage.access_assignments} assignments · cost to {c.coverage.last_cost_day ?? '—'}</div> },
    { key: 'v', label: 'Validated', render: (c) => fmtAgo(c.last_validated_at) },
  ]
  return (
    <>
      <PageHeader eyebrow="Integrations" title="Cloud connections" description="Every discovered AWS account, Azure subscription and GCP project with its authentication, permission validation and the state of each data source (last success, last failure and reason). Counts come from discovery, never from configuration."
        action={<Link className="cn-btn cn-btn-primary" to="/connections/onboard">Onboard a cloud</Link>} />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">{['aws', 'azure', 'gcp'].map((p) => { const t = data.totals[p] ?? {}; return (
        <button key={p} className={`cn-card cn-lift px-4 py-3 text-left ${f.provider === p ? 'ring-2 ring-[var(--accent)]' : ''}`} onClick={() => setF({ ...f, provider: f.provider === p ? '' : p })}>
          <div className="text-sm font-semibold">{PROVIDER_LABEL[p]}</div><div className="tabular mt-1 text-[22px] font-semibold">{t.scopes ?? 0}<span className="ml-1 text-xs font-normal text-ink-3">{p === 'aws' ? 'accounts' : p === 'azure' ? 'subscriptions' : 'projects'} discovered</span></div>
          <div className="text-[11px] text-ink-3">{t.Healthy ?? 0} healthy · {t.Degraded ?? 0} degraded · {t['Not connected'] ?? 0} not connected</div></button>) })}</div>
      <Panel icon={<Cable size={15} />} title={`Connections (${rows.length})`} subtitle={data.tenants.length ? `Entra tenant(s): ${data.tenants.join(', ')}` : undefined}
        action={<ExportButton name="Cloud connections" head={['Cloud', 'ID', 'Name', 'Health', 'Authentication', 'Permissions', ...Object.keys(data.sources).map((k) => SRC_LABEL[k])]}
          rows={rows.map((c) => [c.provider, c.external_id, c.name, c.health, c.authentication, c.permissions, ...Object.keys(data.sources).map((k) => c.sources[k]?.state)])} />}>
        <FilterPanel onClear={() => setF({ provider: '', health: '', q: '' })}>
          <Select label="Health" value={f.health} onChange={(v) => setF({ ...f, health: v })} options={['Healthy', 'Degraded', 'Not connected']} />
          <TextFilter label="Search" value={f.q} onChange={(v) => setF({ ...f, q: v })} placeholder="name or ID" />
        </FilterPanel>
        <div className="mb-2 flex flex-wrap items-center gap-3 text-[11px] text-ink-3" aria-label="Data source legend">
          {[['OK', 'var(--good)', 'synchronising'], ['FAILING', 'var(--critical)', 'last sync failed (open the row for the reason)'],
            ['NOT_PERMITTED', '#e0a100', 'permission missing'], ['NEVER', 'var(--ink-3)', 'never synchronised / not applicable']].map(([k, c, t]) => (
            <span key={k} className="inline-flex items-center gap-1"><span className="inline-block h-2.5 w-4 rounded" style={{ background: `color-mix(in srgb, ${c} 35%, transparent)` }} />{t}</span>))}
          <span className="ml-auto">Live check from a terminal: <code>python -m app.validate_cloud aws|gcp|azure</code></span>
        </div>
        <DataGrid label="Cloud connections" cols={cols} rows={rows} onOpen={setOpen} empty="Nothing discovered yet. Configure a cloud under Integrations and run account discovery." />
      </Panel>
      {open && <Drawer title={open.name || open.external_id} subtitle={<Pill value={HEALTH_TONE[open.health]} text={open.health} />} onClose={() => setOpen(null)} width={860}>
        <Section title="Connection"><KV items={[['Cloud', PROVIDER_LABEL[open.provider]], ['ID', <span className="font-mono text-xs">{open.external_id}</span>], ['Organization / tenant / parent', open.organization ?? open.parent],
          ['Billing account', open.billing_account], ['Provider state', open.provider_state], ['Onboarding', open.onboarding_status], ['Environment', open.environment],
          ['Last discovered', fmtTime(open.last_seen_at)], ['Last validated', fmtTime(open.last_validated_at)], ['Permission detail', open.permission_detail]]} /></Section>
        <Section title="Checks"><div className="flex flex-wrap gap-2">{Object.entries(open.checks).map(([k, v]) => <Pill key={k} value={v === 'pass' ? 'APPROVED' : v === 'fail' ? 'Critical' : 'NOT_CONFIGURED'} text={`${k.replace('_', ' ')}: ${v}`} />)}</div></Section>
        <Section title="Data sources">
          <table className="w-full text-left text-xs"><thead><tr className="border-b border-line text-ink-3">{['Source', 'API', 'State', 'Last success', 'Last failure / reason'].map((h) => <th key={h} className="px-1 py-1">{h}</th>)}</tr></thead>
            <tbody>{Object.entries(open.sources).map(([k, v]) => <tr key={k} className="border-b border-line/60"><td className="px-1 py-1 font-medium">{SRC_LABEL[k]}</td><td className="px-1">{v.api}</td>
              <td className="px-1"><Pill value={STATE_TONE[v.state]} text={v.state.replace(/_/g, ' ').toLowerCase()} /></td><td className="px-1">{fmtTime(v.last_success)}</td>
              <td className="px-1">{v.last_failure ? <>{fmtTime(v.last_failure)}<div className="text-ink-3">{v.failure_reason}</div></> : v.state === 'NOT_PERMITTED' ? `${v.gate_check} check failed` : '—'}</td></tr>)}</tbody></table>
        </Section>
      </Drawer>}
    </>
  )
}
