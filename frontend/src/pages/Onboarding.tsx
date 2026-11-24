import { useState } from 'react'
import CloudConnections from '../components/CloudConnections'
import { Boxes, CheckCircle2, CircleDashed, KeyRound, ListChecks, PieChart as PieIcon, Plug } from 'lucide-react'
import { ArcDonut, CARD_ORDER, ComparisonChart, HeroLayout, KpiCard, Panel, ProviderCard } from '../components/hero'
import { Card, EmptyState, ErrorNote, Meter, PageHeader, PageSkeleton, PROVIDER_COLOR, PROVIDER_LABEL, PROVIDER_NAME, ProviderTag, SCOPE_NOUN, StatusBadge, Table, fmtInt, fmtTime } from '../components/ui'
import { useCan } from '../auth/AuthContext'
import { useApi } from '../hooks/useApi'
import { useFilters } from '../hooks/useFilters'
import { api, type OnboardingRecord, type OnboardingSummary, type Provider, type Scope, type Task } from '../services/api'

const CHECKS = ['authentication', 'permissions', 'configuration', 'audit_logs', 'billing', 'monitoring']
const CHECK_LABEL: Record<string, string> = { authentication: 'Auth', permissions: 'Permissions', configuration: 'APIs', audit_logs: 'Audit logs', billing: 'Billing', monitoring: 'Monitoring' }
const MISSING: [string, string][] = [['permissions', 'Missing permissions'], ['audit_logs', 'Missing log integrations'], ['billing', 'Missing billing integrations'], ['monitoring', 'Missing monitoring integrations']]
const ORDER: Provider[] = ['aws', 'gcp', 'azure']

export default function Onboarding() {
  const { filters, set, refreshKey } = useFilters()
  const [status, setStatus] = useState('')
  const [bump, setBump] = useState(0)
  const key = refreshKey + bump
  const summary = useApi<OnboardingSummary>('/onboarding/summary', undefined, key)
  const scopes = useApi<{ total: number; items: Scope[] }>('/inventory/scopes', { provider: filters.provider, search: filters.search, status }, key)
  const tasks = useApi<{ items: Task[] }>('/onboarding/tasks', { provider: filters.provider }, key)
  const records = useApi<{ items: OnboardingRecord[] }>('/onboarding/records', { provider: filters.provider, limit: 15 }, key)
  const canApprove = useCan('onboarding:approve')
  const [busy, setBusy] = useState<number | null>(null)
  const [actionError, setActionError] = useState('')

  const decide = async (id: number, decision: 'approved' | 'rejected') => {
    setBusy(id); setActionError('')
    try { await api.post(`/onboarding/tasks/${id}/decision`, { decision }); setBump((b) => b + 1) }
    catch (e) { setActionError(e instanceof Error ? e.message : 'Decision failed') }
    finally { setBusy(null) }
  }

  if (summary.error) return <ErrorNote message={summary.error.message} />
  if (!summary.data) return <PageSkeleton tiles={5} />
  const s = summary.data
  const chart = ORDER.map((p) => {
    const b = s.by_provider[p]
    const total = Object.values(b).reduce((a, n) => a + n, 0)
    const inactive = b['Inactive'] + b['Monitoring Disabled']
    return { provider: PROVIDER_LABEL[p], onboarded: b['Fully Onboarded'], attention: total - b['Fully Onboarded'] - inactive, inactive }
  })

  const gaps = Object.values(s.missing).reduce((x, v) => x + v.length, 0)
  const active = s.total - (s.by_status['Inactive'] ?? 0)
  return (
    <>
      <PageHeader eyebrow="Cloud Accounts" title="Cloud inventory and onboarding" description="Scopes are discovered automatically. Access or configuration gaps become tasks for human approval; nothing is changed in any cloud." />

      <HeroLayout
        kpis={<>
          <KpiCard icon={<Boxes size={15} />} label="Scopes in inventory" num={s.total} note="accounts, projects, subscriptions" />
          <KpiCard icon={<CheckCircle2 size={15} />} label="Fully onboarded" num={s.by_status['Fully Onboarded']} note={s.total ? `${((100 * s.by_status['Fully Onboarded']) / s.total).toFixed(0)}% of inventory` : undefined} />
          <KpiCard icon={<CircleDashed size={15} />} label="Partially onboarded" num={s.by_status['Partially Onboarded'] + s.by_status['Pending Configuration']} note="includes pending configuration" />
          <KpiCard icon={<KeyRound size={15} />} label="Access failed or pending" num={s.by_status['Access Failed'] + s.by_status['Pending Access']} note="needs a permission fix" />
          <KpiCard icon={<Plug size={15} />} label="Integration gaps" num={gaps} note="failed checks on active scopes" />
          <KpiCard icon={<ListChecks size={15} />} label="Awaiting approval" num={s.open_tasks} note="human decision required" />
        </>}
        main={
          <Panel icon={<Boxes size={15} />} title="Onboarding status by cloud" subtitle="Every discovered scope; nothing is created or changed in any cloud" bodyClass="px-5 pb-4 pt-3 xl:pr-16">
            <ComparisonChart stacked data={chart} x="provider"
              series={[{ key: 'onboarded', label: 'Fully onboarded', color: 'var(--compare-current)' }, { key: 'attention', label: 'Needs attention', color: 'var(--compare-previous)' }, { key: 'inactive', label: 'Inactive or disabled', color: 'var(--neutral-mark)' }]}
              empty={<EmptyState title="No scopes discovered yet">Connect a cloud below, then choose Run discovery now.</EmptyState>} />
          </Panel>
        }
        trend={
          <Panel float icon={<Plug size={15} />} title="Integration gaps" subtitle="Active scopes where a check did not pass">
            <ul className="space-y-2.5 text-sm">
              {[...MISSING, ['authentication', 'Authentication failures'] as [string, string]].map(([k, label]) => (
                <li key={k}>
                  <div className="mb-1 flex justify-between text-xs"><span className="font-medium text-ink">{label}</span><span className="tabular font-semibold">{fmtInt(s.missing[k]?.length ?? 0)}</span></div>
                  <Meter value={active ? (100 * (s.missing[k]?.length ?? 0)) / active : null} tone="var(--compare-current)" label={`${label} share`} />
                </li>
              ))}
            </ul>
          </Panel>
        }
        donut={
          <Panel float icon={<PieIcon size={15} />} title="Inventory by cloud" subtitle="Share of discovered scopes">
            <ArcDonut centre={fmtInt(s.total)} centreNote="scopes" emptyText="No scopes discovered yet."
              items={(['azure', 'aws', 'gcp'] as const).map((p) => ({ key: p, label: PROVIDER_NAME[p], value: Object.values(s.by_provider[p] ?? {}).reduce((x, y) => x + y, 0), color: PROVIDER_COLOR[p] }))} />
          </Panel>
        }
        bottom={CARD_ORDER.filter((p) => !filters.provider || p === filters.provider).map((p) => {
          const b = s.by_provider[p] ?? {}
          const total = Object.values(b).reduce((x, y) => x + y, 0)
          const full = b['Fully Onboarded'] ?? 0
          return (
            <ProviderCard key={p} provider={p} to="/inventory" action="Show this cloud" onAction={() => set({ provider: p })}
              value={fmtInt(total)} valueLabel={`${SCOPE_NOUN[p]} discovered`} side={{ value: total ? `${((100 * full) / total).toFixed(0)}%` : '—', label: 'Fully onboarded' }}
              split={total ? { left: { label: 'Onboarded', value: fmtInt(full) }, right: { label: 'Needs attention', value: fmtInt(total - full) }, ratio: full / total } : null}
              note={total ? `${fmtInt(b['Access Failed'] ?? 0)} access failed · ${fmtInt(b['Pending Access'] ?? 0)} pending access` : 'Not connected or nothing discovered yet'} />
          )
        })}
      />

      <CloudConnections onDiscovered={() => setBump((b) => b + 1)} />

      <Card icon={<Boxes size={15} />} title="Tasks awaiting human approval" subtitle="Approving records the decision and authorises a person to make the change. The platform never applies it.">
        {actionError && <div className="mb-2"><ErrorNote message={actionError} /></div>}
        <Table empty="No onboarding tasks" head={['Cloud', 'Task', 'Proposed action', 'Status', 'Raised', '']} rows={(tasks.data?.items ?? []).map((t) => [
          <ProviderTag provider={t.provider} />,
          <div><div className="font-medium">{t.title}</div><div className="text-xs text-ink-3">{t.description}</div></div>,
          <span className="text-xs text-ink-2">{t.proposed_action}</span>,
          <div><StatusBadge status={t.status} />{t.decided_by && <div className="text-xs text-ink-3">{t.decided_by}</div>}</div>,
          <span className="whitespace-nowrap text-xs">{fmtTime(t.created_at)}</span>,
          t.status === 'pending_approval' && canApprove ? (
            <div className="flex gap-1.5">
              <button disabled={busy === t.id} onClick={() => decide(t.id, 'approved')} className="rounded-md bg-accent-btn px-2 py-1 text-xs font-medium text-white disabled:opacity-50">Approve</button>
              <button disabled={busy === t.id} onClick={() => decide(t.id, 'rejected')} className="rounded-md border border-line px-2 py-1 text-xs disabled:opacity-50">Reject</button>
            </div>
          ) : null,
        ])} />
      </Card>

      <Card icon={<Boxes size={15} />} title="Cloud scopes" subtitle={`${fmtInt(scopes.data?.total ?? 0)} matching the current filters`} action={
        <select className="h-8 rounded-md border border-line bg-surface px-2 text-sm" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Onboarding status">
          <option value="">All statuses</option>
          {Object.keys(s.by_status).map((k) => <option key={k} value={k}>{k}</option>)}
        </select>}>
        <Table empty="No scopes match the current filters" head={['Cloud', 'Name', 'ID', 'Status', ...CHECKS.map((c) => CHECK_LABEL[c]), 'First discovered']} rows={(scopes.data?.items ?? []).map((r) => [
          <ProviderTag provider={r.provider} />,
          <span className="font-medium">{r.name}</span>,
          <code className="text-xs text-ink-2">{r.external_id}</code>,
          <StatusBadge status={r.onboarding_status} />,
          ...CHECKS.map((c) => r.checks[c]
            ? <span title={r.checks[c].detail}><StatusBadge status={r.checks[c].status} label={r.checks[c].status === 'pass' ? 'Pass' : r.checks[c].status === 'fail' ? 'Fail' : 'Unknown'} /></span>
            : <span className="text-xs text-ink-3">n/a</span>),
          <span className="whitespace-nowrap text-xs">{fmtTime(r.first_discovered_at)}</span>,
        ])} />
      </Card>

      <Card icon={<Boxes size={15} />} title="Onboarding history" subtitle="Append-only audit evidence of status changes">
        <Table empty="No onboarding history yet" head={['When', 'Cloud', 'Scope', 'Event', 'From', 'To']} rows={(records.data?.items ?? []).map((r) => [
          <span className="whitespace-nowrap text-xs">{fmtTime(r.created_at)}</span>, <ProviderTag provider={r.provider} />,
          <div><span className="font-medium">{r.scope_name}</span> <code className="text-xs text-ink-3">{r.scope_external_id}</code></div>,
          <span className="text-xs">{r.event_type.replace(/_/g, ' ')}</span>,
          r.previous_status ? <StatusBadge status={r.previous_status} /> : <span className="text-xs text-ink-3">new</span>,
          <StatusBadge status={r.new_status} />,
        ])} />
      </Card>
    </>
  )
}
