import { ClipboardCheck, FileWarning, KeyRound, Landmark, ListChecks, PieChart as PieIcon, ShieldCheck, UserCheck, Users } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useCan } from '../auth/AuthContext'
import { ArcDonut, CARD_ORDER, ComparisonChart, HeroLayout, KpiCard, Panel, ProviderCard } from '../components/hero'
import { EmptyState, ErrorNote, Meter, PageHeader, PageSkeleton, ProviderTag, SCOPE_NOUN, StatusBadge, Table, fmtAgo, fmtInt, fmtPct, fmtTime } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useFilters } from '../hooks/useFilters'
import type { AdminUser, OnboardingSummary, Scope, Soc, Task } from '../services/api'
import { ScopeName } from '../hooks/useScopeNames'

/** The onboarding checks the discovery job records for every scope (see backend services/connector.py). */
export const CHECKS: { key: string; label: string }[] = [
  { key: 'authentication', label: 'Authentication' }, { key: 'permissions', label: 'Read-only permissions' }, { key: 'configuration', label: 'Configuration' },
  { key: 'audit_logs', label: 'Audit logging' }, { key: 'billing', label: 'Billing access' }, { key: 'monitoring', label: 'Monitoring' },
]
const STATUS_COLOR: Record<string, string> = {
  'Fully Onboarded': 'var(--series-azure)', 'Partially Onboarded': 'var(--series-aws)', 'Pending Configuration': 'var(--series-gcp)',
  'Pending Access': 'var(--compare-previous)', 'Access Failed': 'var(--critical)', Discovered: 'var(--neutral-mark)', 'Monitoring Disabled': 'var(--neutral-mark)', Inactive: 'var(--surface-3)',
}
const RESOLVED = ['Closed', 'Confirmed Legitimate']
const STALE_DAYS = 30

function checkStats(scopes: Scope[]) {
  return CHECKS.map((c) => {
    let pass = 0, fail = 0, unknown = 0
    for (const s of scopes) {
      const st = s.checks?.[c.key]?.status
      if (st === 'pass') pass++
      else if (st === 'fail') fail++
      else if (st !== 'not_applicable') unknown++
    }
    return { ...c, pass, fail, unknown }
  })
}

export default function Governance() {
  const { filters: f, refreshKey } = useFilters()
  const canSoc = useCan('soc:read'), canAdmin = useCan('admin:users')
  const scopes = useApi<{ items: Scope[] }>('/inventory/scopes', { provider: f.provider }, refreshKey)
  const summary = useApi<OnboardingSummary>('/onboarding/summary', undefined, refreshKey)
  const tasks = useApi<{ items: Task[] }>('/onboarding/tasks', { provider: f.provider }, refreshKey)
  const soc = useApi<Soc>(canSoc ? '/dashboard/soc' : null, { provider: f.provider }, refreshKey)
  const users = useApi<{ items: AdminUser[] }>(canAdmin ? '/admin/users' : null, undefined, refreshKey)

  if (scopes.error) return <ErrorNote message={scopes.error.message} onRetry={scopes.reload} />
  if (!scopes.data) return <PageSkeleton tiles={6} />
  const active = scopes.data.items.filter((s) => s.onboarding_status !== 'Inactive')
  const stats = checkStats(active)
  const evaluated = stats.reduce((a, s) => a + s.pass + s.fail, 0)
  const passed = stats.reduce((a, s) => a + s.pass, 0)
  const compliance = evaluated ? (100 * passed) / evaluated : null
  const failing = stats.reduce((a, s) => a + s.fail, 0)
  const pendingTasks = (tasks.data?.items ?? []).filter((t) => t.status === 'pending_approval')
  const review = soc.data?.by_review_status ?? {}
  const totalFindings = Object.values(review).reduce((a, b) => a + b, 0)
  const reviewed = totalFindings ? (100 * (totalFindings - (review['Pending Review'] ?? 0))) / totalFindings : null
  const now = Date.now()
  const stale = (users.data?.items ?? []).filter((u) => u.is_active && (!u.last_login_at || now - new Date(u.last_login_at).getTime() > STALE_DAYS * 864e5))
  const admins = (users.data?.items ?? []).filter((u) => u.is_active && u.roles.includes('admin'))
  const providerScopes = (p: string) => active.filter((s) => s.provider === p)
  const byStatus = summary.data?.by_status ?? {}

  return (
    <>
      <PageHeader eyebrow="Governance & Compliance" title="Governance and compliance"
        description="Configuration compliance of every connected account, project and subscription, security review coverage, open exceptions and access review. Read-only: nothing here changes a cloud." />
      <HeroLayout
        kpis={<>
          <KpiCard icon={<ShieldCheck size={15} />} label="Configuration compliance" num={compliance} fmt={(n) => fmtPct(n)} note={evaluated ? `${fmtInt(passed)} of ${fmtInt(evaluated)} checks pass` : 'No checks evaluated yet'} />
          <KpiCard icon={<FileWarning size={15} />} label="Failing checks" num={evaluated ? failing : null} note={evaluated ? `across ${active.length} active scopes` : 'Run discovery first'} to="/inventory" />
          <KpiCard icon={<ClipboardCheck size={15} />} label="Findings reviewed" num={canSoc ? reviewed : null} fmt={(n) => fmtPct(n)} note={canSoc ? (totalFindings ? `${fmtInt(review['Pending Review'] ?? 0)} awaiting review` : 'No findings recorded') : 'Requires SOC access'} to={canSoc ? '/audit' : undefined} />
          <KpiCard icon={<ListChecks size={15} />} label="Open exceptions" num={tasks.data ? pendingTasks.length : null} note="tasks awaiting approval" to="/inventory" />
          <KpiCard icon={<Users size={15} />} label="Active administrators" num={canAdmin && users.data ? admins.length : null} note={canAdmin ? 'holders of the admin role' : 'Visible to administrators'} />
          <KpiCard icon={<UserCheck size={15} />} label={`No sign-in for ${STALE_DAYS}+ days`} num={canAdmin && users.data ? stale.length : null} note={canAdmin ? 'active accounts to review' : 'Visible to administrators'} />
        </>}
        main={
          <Panel icon={<ListChecks size={15} />} title="Control status by check" subtitle="Scopes passing and failing each onboarding control (unknown = not yet evaluated)" bodyClass="px-5 pb-4 pt-3 xl:pr-16">
            <ComparisonChart data={stats.map((s) => ({ check: s.label, pass: s.pass, fail: s.fail, unknown: s.unknown }))} x="check"
              series={[{ key: 'pass', label: 'Pass', color: 'var(--compare-current)' }, { key: 'fail', label: 'Fail', color: 'var(--critical)' }, { key: 'unknown', label: 'Not evaluated', color: 'var(--compare-previous)' }]}
              empty={<EmptyState title="No scopes discovered yet">Connect a cloud on Cloud Inventory and run discovery.</EmptyState>} />
          </Panel>
        }
        trend={
          <Panel float icon={<ClipboardCheck size={15} />} title="Security control status" subtitle="Findings by review status">
            {!canSoc ? <EmptyState title="Requires SOC access" /> : totalFindings === 0 ? <EmptyState title="No findings recorded" /> : (
              <ul className="space-y-2.5 text-xs">
                {Object.entries(review).sort((a, b) => b[1] - a[1]).map(([k, n]) => (
                  <li key={k}>
                    <div className="mb-1 flex justify-between"><StatusBadge status={k} /><span className="tabular font-semibold">{fmtInt(n)}</span></div>
                    <Meter value={(100 * n) / totalFindings} tone={RESOLVED.includes(k) ? 'var(--compare-current)' : 'var(--compare-previous)'} label={`${k} share`} />
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        }
        donut={
          <Panel float icon={<PieIcon size={15} />} title="Subscription governance" subtitle="Scopes by onboarding status">
            <ArcDonut centre={fmtInt(summary.data?.total ?? null)} centreNote="scopes in inventory"
              items={Object.entries(byStatus).filter(([, n]) => n > 0).map(([k, n]) => ({ key: k, label: k, value: n, color: STATUS_COLOR[k] ?? 'var(--neutral-mark)' }))}
              emptyText="No scopes discovered yet." />
          </Panel>
        }
        bottom={CARD_ORDER.filter((p) => !f.provider || p === f.provider).map((p) => {
          const ps = providerScopes(p), st = checkStats(ps)
          const ev = st.reduce((a, s) => a + s.pass + s.fail, 0), ok = st.reduce((a, s) => a + s.pass, 0)
          const full = ps.filter((s) => s.onboarding_status === 'Fully Onboarded').length
          return (
            <ProviderCard key={p} provider={p} to="/inventory" value={fmtInt(ps.length)} valueLabel={`active ${SCOPE_NOUN[p]}`}
              side={{ value: ev ? fmtPct((100 * ok) / ev, 0) : '—', label: 'Controls passing' }}
              split={ps.length ? { left: { label: 'Fully onboarded', value: fmtInt(full) }, right: { label: 'Needs attention', value: fmtInt(ps.length - full) }, ratio: full / ps.length } : null}
              note={ps.length ? `${st.reduce((a, s) => a + s.fail, 0)} failing checks · ${pendingTasks.filter((t) => t.provider === p).length} open exceptions` : 'Not connected or nothing discovered'} />
          )
        })}
      />

      <Panel icon={<Landmark size={15} />} title="Policy compliance" subtitle="Cloud-native policy engines (Azure Policy, AWS Config, GCP Organization Policy)">
        <EmptyState title="Not collected">
          Policy compliance states are not collected by this version, so no compliance score is shown here. Adding it needs a read-only collector for each cloud's policy service and explicit approval.
          The configuration controls above are what the platform verifies today.
        </EmptyState>
      </Panel>

      <Panel icon={<ShieldCheck size={15} />} title="Configuration compliance" subtitle="Latest result of each control for every active scope">
        <Table label="Configuration compliance by scope" maxHeight={420} empty="No active scopes"
          head={['Cloud', 'Scope', 'Status', ...CHECKS.map((c) => c.label), 'Last validated']}
          rows={active.map((s) => [
            <ProviderTag provider={s.provider} />, <span className="font-medium">{s.name || s.external_id}</span>, <StatusBadge status={s.onboarding_status} />,
            ...CHECKS.map((c) => { const ch = s.checks?.[c.key]; return ch ? <span title={ch.detail ?? ''}><StatusBadge status={ch.status} /></span> : <span className="text-xs text-ink-3">—</span> }),
            <span className="text-xs text-ink-3">{fmtAgo(s.last_validated_at)}</span>,
          ])} />
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel icon={<FileWarning size={15} />} title="Exception tracking" subtitle="Gaps raised for human approval. Approving authorises a person to act; the platform never applies changes.">
          <Table label="Exceptions" maxHeight={360} empty="No exceptions recorded"
            head={['Cloud', 'Scope', 'Exception', 'Status', 'Decided by', 'Raised']}
            rows={(tasks.data?.items ?? []).map((t) => [<ProviderTag provider={t.provider} />, <ScopeName className="text-xs" provider={t.provider} id={t.scope_external_id} />, t.title,
              <StatusBadge status={t.status} />, <span className="text-xs">{t.decided_by ?? '—'}</span>, <span className="text-xs text-ink-3">{fmtTime(t.created_at)}</span>])} />
          <Link to="/inventory" className="mt-3 inline-block text-xs font-medium text-accent hover:underline">Decide exceptions on Cloud Inventory</Link>
        </Panel>
        <Panel icon={<KeyRound size={15} />} title="Access review" subtitle={`Accounts with platform access; flagged when not used for ${STALE_DAYS} days`}>
          {!canAdmin ? <EmptyState title="Visible to administrators">User and role lists are restricted to the admin role.</EmptyState> : (
            <>
              <Table label="Access review" maxHeight={360} empty="No users"
                head={['User', 'Role', 'Active', 'Last sign-in', 'Review']}
                rows={(users.data?.items ?? []).map((u) => [<span className="text-xs font-medium">{u.email}</span>, <span className="text-xs capitalize">{u.roles.join(', ').replace(/_/g, ' ')}</span>,
                  <StatusBadge status={u.is_active ? 'active' : 'stopped'} label={u.is_active ? 'Active' : 'Disabled'} />, <span className="text-xs text-ink-3">{fmtAgo(u.last_login_at)}</span>,
                  stale.includes(u) ? <StatusBadge status="warning" label="Review access" /> : <span className="text-xs text-ink-3">—</span>])} />
              <Link to="/admin/access" className="mt-3 inline-block text-xs font-medium text-accent hover:underline">Change roles in Access control</Link>
            </>
          )}
        </Panel>
      </div>
    </>
  )
}
