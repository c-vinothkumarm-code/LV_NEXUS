import { KeyRound, ShieldAlert, UserCog, UserPlus } from 'lucide-react'
import { useState } from 'react'
import { useMe } from '../auth/AuthContext'
import { useToast } from '../components/Toast'
import { Card, ErrorNote, ExportButton, PageHeader, PageSkeleton, PROVIDER_LABEL, StatusBadge, Table, fmtTime } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { api, type AccessEvent, type AdminUser, type AuditEntry, type Scope } from '../services/api'
import { ScopeName } from '../hooks/useScopeNames'

type Patch = { role?: string; is_active?: boolean; access_status?: string; access_expires_at?: string; clear_expiry?: boolean }
const STATUS_TONE: Record<string, 'pass' | 'warn' | 'fail' | 'muted'> = { ACTIVE: 'pass', SUSPENDED: 'warn', REVOKED: 'fail' }
const nice = (s: string) => s.replace(/_/g, ' ')

/** Access registry: admin-controlled provisioning. A successful Google Workspace sign-in grants nothing on its own;
 *  the person must be listed here (or be in a mapped Google group). Suspension, revocation and role changes end the
 *  person's open sessions immediately. Every change lands in the append-only audit log. */
export default function Access() {
  const me = useMe()
  const toast = useToast()
  const [bump, setBump] = useState(0)
  const [form, setForm] = useState({ email: '', display_name: '', role: 'viewer', access_expires_at: '' })
  const users = useApi<{ items: AdminUser[]; roles: { name: string; label: string; description: string }[] }>('/admin/users', undefined, bump)
  const audit = useApi<{ items: AuditEntry[] }>('/admin/audit', { limit: 100 }, bump)
  const allScopes = useApi<{ items: Scope[] }>('/inventory/scopes')
  const setScopes = (u: AdminUser, scopes: { provider: string; scope_external_id: string }[], what: string) =>
    run(() => api.put(`/admin/users/${u.id}/scopes`, { scopes }), 'Scopes updated', `${u.email}: ${what}`)
  const access = useApi<{ items: AccessEvent[]; failures_24h: { total: number; by_reason: Record<string, number> } }>('/admin/access-log', { limit: 200 }, bump)

  const run = async (fn: () => Promise<unknown>, title: string, text: string) => {
    try { await fn(); toast({ kind: 'success', title, text }); setBump((b) => b + 1) }
    catch (e) { toast({ kind: 'error', title: 'Change refused', text: e instanceof Error ? e.message : 'Unknown error' }) }
  }
  const update = (u: AdminUser, body: Patch, what: string) => run(() => api.patch(`/admin/users/${u.id}`, body), 'Access updated', `${u.email}: ${what}`)
  const provision = () => run(() => api.post('/admin/users', {
    email: form.email, display_name: form.display_name || null, role: form.role,
    access_expires_at: form.access_expires_at ? new Date(`${form.access_expires_at}T23:59:59Z`).toISOString() : null,
  }).then(() => setForm({ email: '', display_name: '', role: 'viewer', access_expires_at: '' })), 'Access provisioned', form.email)

  if (users.error) return <ErrorNote message={users.error.message} onRetry={users.reload} />
  if (!users.data) return <PageSkeleton tiles={0} />
  const roles = users.data.roles
  return (
    <>
      <PageHeader eyebrow="Administration" title="Access registry"
        description="Who may use the Command Center, with which role and until when. Sign-in is limited to verified LatentView Google Workspace accounts; this registry decides who is authorized." />

      <Card icon={<UserPlus size={15} />} title="Provision access" subtitle="The person still has to pass every Google Workspace check (verified e-mail, LatentView Workspace domain) at sign-in">
        <form className="grid gap-2 sm:grid-cols-[2fr_1.4fr_1.2fr_1fr_auto]" onSubmit={(e) => { e.preventDefault(); provision() }}>
          <input className="cn-input" required type="email" placeholder="name@latentview.com" aria-label="Corporate e-mail" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <input className="cn-input" placeholder="Display name (optional)" aria-label="Display name" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
          <select className="cn-input" aria-label="Role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            {roles.map((r) => <option key={r.name} value={r.name} title={r.description}>{r.label}</option>)}
          </select>
          <input className="cn-input" type="date" aria-label="Access expiry (optional)" title="Access expiry (optional)" value={form.access_expires_at} onChange={(e) => setForm({ ...form, access_expires_at: e.target.value })} />
          <button className="cn-btn cn-btn-primary h-9 px-4 text-sm" type="submit">Provision</button>
        </form>
      </Card>

      <Card icon={<UserCog size={15} />} title="Authorized users" subtitle="Roles grant a fixed set of permissions, enforced by the API on every request"
        action={<ExportButton name="Access registry" head={['Email', 'Name', 'Role', 'Status', 'Role source', 'Authorized (UTC)', 'Access expiry (UTC)', 'Last sign-in (UTC)', 'Created by', 'Modified by', 'Google identity bound']}
          rows={users.data.items.map((u) => [u.email, u.display_name, u.roles.join(';'), u.access_status, u.role_source, u.authorized_at, u.access_expires_at, u.last_login_at, u.created_by, u.modified_by, u.google_sub_bound ? 'yes' : 'no'])} />}>
        <Table empty="No users yet" head={['User', 'Role', 'Status', 'Access expiry', 'Last sign-in', 'Sessions', '']} rows={users.data.items.map((u) => {
          const self = u.email === me?.email
          return [
            <div><div className="font-medium">{u.display_name ?? u.email}</div><div className="text-xs text-ink-3">{u.email}{self ? ' (you)' : ''}</div>
              <div className="text-[11px] text-ink-3">{u.role_source.startsWith('google_group') ? `via ${u.role_source.slice(13)}` : `added by ${u.created_by ?? 'unknown'}`}{u.google_sub_bound ? ' · Google identity bound' : ''}</div>
              {u.roles.includes('project_owner') && (
                <div className="mt-1.5">
                  <div className="flex flex-wrap gap-1">
                    {u.scopes.length === 0 && <span className="text-[11px]" style={{ color: 'var(--critical)' }}>No scopes assigned: sees nothing</span>}
                    {u.scopes.map((sc) => (
                      <span key={`${sc.provider}:${sc.scope_external_id}`} className="inline-flex items-center gap-1 rounded-full border border-line px-2 py-0.5 text-[11px]">
                        {PROVIDER_LABEL[sc.provider]} <ScopeName provider={sc.provider} id={sc.scope_external_id} />
                        <button aria-label={`Remove ${sc.scope_external_id}`} className="text-ink-3 hover:text-ink" onClick={() => setScopes(u, u.scopes.filter((x) => x !== sc), `removed ${sc.scope_external_id}`)}>×</button>
                      </span>
                    ))}
                  </div>
                  <select className="cn-input mt-1 h-7 text-xs" aria-label={`Assign a scope to ${u.email}`} value="" onChange={(e) => {
                    const [provider, ...rest] = e.target.value.split(':'); const id = rest.join(':')
                    if (provider) setScopes(u, [...u.scopes, { provider, scope_external_id: id }], `added ${id}`)
                  }}>
                    <option value="">Assign account / subscription / project…</option>
                    {(allScopes.data?.items ?? []).filter((x) => !u.scopes.some((y) => y.provider === x.provider && y.scope_external_id === x.external_id))
                      .map((x) => <option key={`${x.provider}:${x.external_id}`} value={`${x.provider}:${x.external_id}`}>{PROVIDER_LABEL[x.provider]} · {x.name || x.external_id}</option>)}
                  </select>
                </div>
              )}</div>,
            <select className="cn-input" value={u.roles[0] ?? ''} disabled={self} onChange={(e) => update(u, { role: e.target.value }, `role ${nice(e.target.value)}`)} aria-label={`Role for ${u.email}`}>
              {roles.map((r) => <option key={r.name} value={r.name} title={r.description}>{r.label}</option>)}
            </select>,
            <StatusBadge status={STATUS_TONE[u.access_status] ?? 'muted'} label={nice(u.access_status.toLowerCase())} />,
            <input className="cn-input h-8 text-xs" type="date" disabled={self} aria-label={`Access expiry for ${u.email}`} value={u.access_expires_at?.slice(0, 10) ?? ''}
              onChange={(e) => update(u, e.target.value ? { access_expires_at: new Date(`${e.target.value}T23:59:59Z`).toISOString() } : { clear_expiry: true }, e.target.value ? `expires ${e.target.value}` : 'no expiry')} />,
            <span className="whitespace-nowrap text-xs">{fmtTime(u.last_login_at)}</span>,
            <span className="text-xs">{u.open_sessions}</span>,
            self ? <span className="text-xs text-ink-3">You cannot change your own access</span> :
              <div className="flex flex-wrap gap-1">
                {u.access_status === 'ACTIVE'
                  ? <><button className="cn-btn cn-btn-ghost h-7 px-2.5 text-xs" onClick={() => update(u, { access_status: 'SUSPENDED' }, 'suspended, sessions ended')}>Suspend</button>
                    <button className="cn-btn cn-btn-ghost h-7 px-2.5 text-xs" onClick={() => update(u, { access_status: 'REVOKED' }, 'revoked, sessions ended')}>Revoke</button></>
                  : <button className="cn-btn cn-btn-ghost h-7 px-2.5 text-xs" onClick={() => update(u, { access_status: 'ACTIVE' }, 'reactivated')}>Reactivate</button>}
                {u.open_sessions > 0 && <button className="cn-btn cn-btn-ghost h-7 px-2.5 text-xs" onClick={() => run(() => api.post(`/admin/users/${u.id}/revoke-sessions`, {}), 'Sessions ended', u.email)}>End sessions</button>}
              </div>,
          ]
        })} />
        <ul className="mt-3 grid gap-1 text-xs text-ink-3 sm:grid-cols-2">{roles.map((r) => <li key={r.name}><span className="font-medium text-ink-2">{r.label}</span>: {r.description}</li>)}</ul>
      </Card>

      <Card icon={<ShieldAlert size={15} />} title="Sign-in activity"
        subtitle={access.data ? `${access.data.failures_24h.total} denied sign-ins in the last 24 hours${Object.keys(access.data.failures_24h.by_reason).length ? ': ' + Object.entries(access.data.failures_24h.by_reason).map(([k, v]) => `${nice(k)} ${v}`).join(', ') : ''}` : 'Loading'}
        action={<ExportButton name="Sign-in activity" head={['Time (UTC)', 'Event', 'Reason', 'Account', 'IP address']} rows={(access.data?.items ?? []).map((a) => [a.created_at, a.event, a.reason, a.email, a.ip_address])} />}>
        <Table dense maxHeight={360} empty="No sign-in activity recorded" head={['Time', 'Event', 'Reason', 'Account', 'IP address']} rows={(access.data?.items ?? []).map((a) => [
          <span className="whitespace-nowrap text-xs">{fmtTime(a.created_at)}</span>,
          <StatusBadge status={a.event === 'login_success' ? 'pass' : a.event === 'login_denied' || a.event === 'throttled' ? 'fail' : 'muted'} label={nice(a.event)} />,
          <span className="text-xs">{a.reason ? nice(a.reason) : '—'}</span>, <span className="text-xs">{a.email ?? '—'}</span>, <span className="text-xs">{a.ip_address ?? '—'}</span>])} />
      </Card>

      <Card icon={<KeyRound size={15} />} title="Administrative audit log" subtitle="Append-only: the database refuses changes or deletions to these records"
        action={<ExportButton name="Admin audit log" head={['ID', 'Time (UTC)', 'Actor', 'Action', 'Target', 'Detail']} rows={(audit.data?.items ?? []).map((a) => [a.id, a.created_at, a.actor, a.action, a.target, JSON.stringify(a.detail)])} />}>
        <Table dense maxHeight={420} empty="No administrative actions recorded" head={['Time', 'Actor', 'Action', 'Target', 'Detail']} rows={(audit.data?.items ?? []).map((a) => [
          <span className="whitespace-nowrap text-xs">{fmtTime(a.created_at)}</span>, <span className="text-xs">{a.actor}</span>, <code className="text-xs">{a.action}</code>,
          <span className="text-xs">{a.target ?? '—'}</span>, <code className="block max-w-md truncate text-[11px] text-ink-3" title={JSON.stringify(a.detail)}>{JSON.stringify(a.detail)}</code>])} />
      </Card>
    </>
  )
}
