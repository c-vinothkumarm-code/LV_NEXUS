import {
  Bell, Boxes, ChevronDown, ChevronLeft, ChevronRight, CircleDollarSign, FileBarChart2, HeartPulse, KeyRound, LayoutGrid, LogOut, Menu, Monitor, Moon, PanelLeftClose,
  PanelLeftOpen, Plug, Radar, RefreshCw, Scale, Search, Server, Settings, ShieldCheck, Sun, UserCog, X,
} from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useAuth, useCan } from '../auth/AuthContext'
import { ProductLogo } from '../components/brand/Brand'
import { PROVIDER_LABEL, StatusBadge } from '../components/ui'
import { AssistantButton } from '../components/assistant'
import { useApi } from '../hooks/useApi'
import { useFilters, type Filters } from '../hooks/useFilters'
import { api, type Overview, type Scope, type SearchHit } from '../services/api'
import { BRAND } from '../theme/brand'
import { getThemePref, setThemePref, type ThemePref } from '../theme/theme'

/** The 12 sections of LV NEXUS. A section and its pages are listed only when the signed-in role may use them (the API
 *  enforces the same rules). Every existing page stays reachable; no placeholder pages. */
export interface NavItem { to: string; label: string; perm: string }
export interface NavSection { key: string; label: string; icon: typeof LayoutGrid; items: NavItem[] }
export const SECTIONS: NavSection[] = [
  { key: 'exec', label: 'Executive Overview', icon: LayoutGrid, items: [
    { to: '/', label: 'Overview', perm: 'inventory:read|inventory:read_assigned' },
    { to: '/executive', label: 'Executive review', perm: 'exec:read|inventory:read' },
  ] },
  { key: 'accounts', label: 'Cloud Accounts', icon: Boxes, items: [
    { to: '/accounts', label: 'Account hierarchy', perm: 'inventory:read|inventory:read_assigned' },
    { to: '/inventory', label: 'Onboarding status', perm: 'onboarding:read' },
  ] },
  { key: 'security', label: 'Security Center', icon: ShieldCheck, items: [
    { to: '/vulnerabilities', label: 'Security findings', perm: 'vuln:read|vuln:read_assigned' },
  ] },
  { key: 'activity', label: 'Live Cloud Activity', icon: Radar, items: [
    { to: '/activity', label: 'Live activity', perm: 'audit:read' },
    { to: '/audit', label: 'SOC review and cases', perm: 'audit:read' },
  ] },
  { key: 'iam', label: 'Identity & Access', icon: KeyRound, items: [
    { to: '/access', label: 'Identities and access', perm: 'access:read' },
  ] },
  { key: 'resources', label: 'Cloud Resources', icon: Server, items: [
    { to: '/inventory/explorer', label: 'Resource explorer', perm: 'inventory:read|inventory:read_assigned' },
  ] },
  { key: 'infra', label: 'Infrastructure Health', icon: HeartPulse, items: [
    { to: '/monitoring', label: 'Resources and VM health', perm: 'infra:read|inventory:read_assigned' },
  ] },
  { key: 'finops', label: 'FinOps', icon: CircleDollarSign, items: [
    { to: '/cost/overview', label: 'Cost overview', perm: 'finops:read' },
    { to: '/cost/analysis', label: 'Cost analysis', perm: 'finops:read' },
    { to: '/cost/optimization', label: 'Optimisation', perm: 'finops:read' },
    { to: '/budgets', label: 'Budgets and approvals', perm: 'budget:read' },
    { to: '/budgets/alerts', label: 'Budget alerts', perm: 'budget:read' },
    { to: '/budgets/settings', label: 'Thresholds and approval chains', perm: 'budget:read' },
  ] },
  { key: 'gov', label: 'Governance & Compliance', icon: Scale, items: [
    { to: '/compliance', label: 'Compliance overview', perm: 'onboarding:read|reports:export' },
    { to: '/compliance/policies', label: 'Policy library', perm: 'onboarding:read|reports:export' },
    { to: '/governance', label: 'Governance checks', perm: 'onboarding:read' },
  ] },
  { key: 'reports', label: 'Reports & Alerts', icon: FileBarChart2, items: [
    { to: '/reports/library', label: 'Report library', perm: 'reports:export' },
    { to: '/reports', label: 'Scheduled reports', perm: 'automation:read' },
    { to: '/notifications', label: 'Notifications', perm: 'inventory:read' },
  ] },
  { key: 'integrations', label: 'Integrations', icon: Plug, items: [
    { to: '/connections/onboard', label: 'Onboard a cloud', perm: 'onboarding:read' },
    { to: '/connections', label: 'Cloud connections', perm: 'sync:read|onboarding:read|inventory:read' },
    { to: '/integrations', label: 'Collection and sync', perm: 'sync:read' },
    { to: '/system-health', label: 'System health', perm: 'automation:read|inventory:read' },
  ] },
  { key: 'admin', label: 'Administration', icon: UserCog, items: [
    { to: '/admin/access', label: 'Users and roles', perm: 'admin:users' },
    { to: '/audit/trail', label: 'Application audit trail', perm: 'audit:read|admin:users' },
    { to: '/automation', label: 'Jobs and collection', perm: 'automation:read' },
    { to: '/ai', label: 'AI assistant and agents', perm: 'ai:use' },
  ] },
]
export const NAV = SECTIONS.flatMap((s) => s.items.map((i) => ({ ...i, icon: s.icon })))

// Which filters each page honours (matches the query parameters its API endpoint accepts).
const PAGE_FILTERS: Record<string, (keyof Filters)[]> = {
  '/executive': ['provider', 'scope', 'dateFrom', 'dateTo'],
  '/monitoring': ['provider', 'scope', 'region', 'environment'],
  '/inventory': ['provider', 'search'],
  '/governance': ['provider'],
  '/automation': ['dateFrom', 'dateTo'],
  '/reports': ['dateFrom', 'dateTo'],
}
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Informational']
const REVIEW = ['Pending Review', 'Under Investigation', 'Confirmed Legitimate', 'Confirmed Suspicious', 'Remediation Required', 'Escalated', 'Closed']

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className="flex w-full items-center gap-1.5 text-xs text-ink-3 sm:w-auto"><span className="w-20 shrink-0 sm:w-auto">{label}</span>{children}</label>
}

function FilterBar() {
  const { filters: f, set, reset, refresh } = useFilters()
  const active = PAGE_FILTERS[useLocation().pathname] ?? []
  const scopes = useApi<{ items: Scope[] }>(active.includes('scope') ? '/inventory/scopes' : null)
  const has = (k: keyof Filters) => active.includes(k)
  const [open, setOpen] = useState(false)
  if (!active.length) return null
  const scopeOptions = (scopes.data?.items ?? []).filter((s) => !f.provider || s.provider === f.provider)
  const dirty = active.some((k) => f[k])
  const count = active.filter((k) => f[k]).length
  return (
    <div className="rounded-2xl border border-line bg-surface px-3 py-1.5">
      <div className="flex items-center justify-between sm:hidden">
        <button className="cn-btn cn-btn-ghost" onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-controls="cn-filters">Filters{count ? ` (${count})` : ''}</button>
        <button className="cn-btn cn-btn-ghost" onClick={refresh}><RefreshCw size={13} aria-hidden />Refresh</button>
      </div>
      <div id="cn-filters" className={`${open ? 'mt-2 flex' : 'hidden'} flex-wrap items-center gap-x-3 gap-y-2 sm:mt-0 sm:flex`} role="search" aria-label="Filters">
        {has('provider') && (
          <Field label="Cloud">
            <select className="cn-input" value={f.provider} onChange={(e) => set({ provider: e.target.value, scope: '' })} aria-label="Cloud provider">
              <option value="">All clouds</option>{['aws', 'azure', 'gcp'].map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p]}</option>)}
            </select>
          </Field>
        )}
        {has('scope') && (
          <Field label="Account / subscription">
            <select className="cn-input max-w-[16rem]" value={f.scope} onChange={(e) => set({ scope: e.target.value })} aria-label="Account, project or subscription">
              <option value="">All</option>
              {scopeOptions.map((s) => <option key={`${s.provider}:${s.external_id}`} value={s.external_id}>{PROVIDER_LABEL[s.provider]} · {s.name || s.external_id}</option>)}
            </select>
          </Field>
        )}
        {has('region') && <Field label="Region"><input className="cn-input w-32" value={f.region} placeholder="any" onChange={(e) => set({ region: e.target.value })} aria-label="Region" /></Field>}
        {has('environment') && <Field label="Environment"><input className="cn-input w-28" value={f.environment} placeholder="any" onChange={(e) => set({ environment: e.target.value })} aria-label="Environment" /></Field>}
        {has('severity') && (
          <Field label="Severity">
            <select className="cn-input" value={f.severity} onChange={(e) => set({ severity: e.target.value })} aria-label="Severity">
              <option value="">All</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}
            </select>
          </Field>
        )}
        {has('reviewStatus') && (
          <Field label="Review">
            <select className="cn-input" value={f.reviewStatus} onChange={(e) => set({ reviewStatus: e.target.value })} aria-label="Review status">
              <option value="">All</option>{REVIEW.map((s) => <option key={s}>{s}</option>)}
            </select>
          </Field>
        )}
        {has('dateFrom') && (
          <Field label="Dates">
            <input type="date" className="cn-input" value={f.dateFrom} onChange={(e) => set({ dateFrom: e.target.value })} aria-label="From date" />
            <span aria-hidden>–</span>
            <input type="date" className="cn-input" value={f.dateTo} onChange={(e) => set({ dateTo: e.target.value })} aria-label="To date" />
          </Field>
        )}
        {has('search') && (
          <label className="relative">
            <Search size={14} className="absolute left-3 top-2.5 text-ink-3" aria-hidden />
            <input className="cn-input w-56 pl-8" value={f.search} placeholder="Search name or ID" onChange={(e) => set({ search: e.target.value })} aria-label="Search" />
          </label>
        )}
        <div className="ml-auto flex items-center gap-2">
          {dirty && <button className="text-xs font-medium text-accent hover:underline" onClick={reset}>Clear filters</button>}
          <button className="cn-btn cn-btn-ghost hidden sm:inline-flex" onClick={refresh}><RefreshCw size={13} aria-hidden />Refresh</button>
        </div>
      </div>
    </div>
  )
}

/** Close a popover on outside click or Escape. */
function usePopover() {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false) }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDown); document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey) }
  }, [open])
  return { open, setOpen, ref }
}

/** Alerts derived by the API from current state (failed collections, budget levels, critical findings, stale scheduler). */
function NotificationBell() {
  const can = useCan('inventory:read')
  const { refreshKey } = useFilters()
  const ov = useApi<Overview>(can ? '/dashboard/overview' : null, undefined, refreshKey)
  const { open, setOpen, ref } = usePopover()
  const loc = useLocation()
  useEffect(() => setOpen(false), [loc.pathname, setOpen])
  if (!can) return null
  const alerts = ov.data?.alerts ?? []
  return (
    <div className="relative" ref={ref}>
      <button className="relative grid h-9 w-9 place-items-center rounded-full border border-line text-ink-2 transition-colors hover:bg-surface-2"
        onClick={() => setOpen((o) => !o)} aria-haspopup="dialog" aria-expanded={open} aria-label={`Notifications: ${alerts.length} active`}>
        <Bell size={16} aria-hidden />
        {alerts.length > 0 && (
          <span key={alerts.length} className="cn-pop absolute -right-1 -top-1 grid h-[18px] min-w-[18px] place-items-center rounded-full px-1 text-[10px] font-bold text-white" style={{ background: 'var(--critical)' }} aria-hidden>
            {alerts.length > 9 ? '9+' : alerts.length}
          </span>
        )}
      </button>
      {open && (
        <div role="dialog" aria-label="Notifications" className="cn-card cn-float-in absolute right-0 z-40 mt-2 w-[min(92vw,380px)] text-ink" style={{ boxShadow: 'var(--shadow-2)' }}>
          <div className="flex items-center justify-between px-4 pt-3.5 pb-2">
            <div className="text-sm font-semibold">Notifications</div>
            <Link to="/notifications" className="text-xs font-medium text-accent hover:underline">View all</Link>
          </div>
          <div className="max-h-80 overflow-auto px-2 pb-2">
            {ov.loading && !ov.data ? <div className="px-2 py-4 text-xs text-ink-3">Loading…</div>
              : alerts.length === 0 ? <div className="px-2 py-4 text-xs text-ink-3">No active alerts. Alerts appear here when a collection fails, a budget level is reached or a critical finding is open.</div>
              : alerts.slice(0, 8).map((a, i) => (
                <div key={i} className="cn-toast flex items-start gap-2 rounded-xl px-2 py-2 hover:bg-surface-2" style={{ animationDelay: `${i * 30}ms` }}>
                  <StatusBadge status={a.level} label="" />
                  <div className="min-w-0 text-xs"><div className="font-semibold text-ink">{a.area}</div><div className="text-ink-2">{a.text}</div></div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  )
}

function UserMenu() {
  const auth = useAuth()
  const canAdmin = useCan('admin:users')
  const { open, setOpen, ref } = usePopover()
  if (!auth) return null
  const { me, signOut } = auth
  const initials = (me.display_name || me.email).split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((p) => p[0]?.toUpperCase()).join('')
  return (
    <div className="relative" ref={ref}>
      <button className="flex items-center gap-2 rounded-full py-1 pl-1 pr-2 text-left transition-colors hover:bg-surface-2" onClick={() => setOpen((o) => !o)} aria-haspopup="menu" aria-expanded={open}>
        <span className="grid h-8 w-8 place-items-center rounded-full text-xs font-semibold text-white" style={{ background: 'var(--brand-gradient)' }} aria-hidden>{initials}</span>
        <span className="hidden leading-tight 2xl:block">
          <span className="block max-w-40 truncate text-[12.5px] font-semibold text-ink">{me.display_name ?? me.email}</span>
          <span className="block text-[11px] text-ink-3">{(me.role_labels ?? me.roles).join(', ')}</span>
        </span>
        <span className="sr-only">Account menu</span>
      </button>
      {open && (
        <div role="menu" className="cn-card cn-float-in absolute right-0 z-40 mt-2 w-72 p-1.5 text-ink" style={{ boxShadow: 'var(--shadow-2)' }}>
          <div className="px-2.5 py-2 text-xs text-ink-3">
            <div className="text-sm font-semibold text-ink">{me.display_name ?? me.email}</div>
            <div>{me.email}</div>
            <div className="mt-1">Role: {(me.role_labels ?? me.roles).join(', ') || 'none'}</div>
            {me.auth_mode === 'dev' && <div className="mt-1 inline-flex items-center gap-1 font-medium text-ink"><span className="h-2 w-2 rounded-full bg-warning" aria-hidden />Development sign-in</div>}
            {me.session_expires_at && <div className="mt-1">Session ends {new Date(me.session_expires_at).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}</div>}
          </div>
          {canAdmin && (
            <Link role="menuitem" to="/admin/access" onClick={() => setOpen(false)} className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-sm hover:bg-surface-2"><UserCog size={15} aria-hidden />Users and roles</Link>
          )}
          <button role="menuitem" className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-sm hover:bg-surface-2" onClick={() => void signOut()}>
            <LogOut size={15} aria-hidden />Sign out
          </button>
        </div>
      )}
    </div>
  )
}

function useSections() {
  const perms = useAuth()?.me.permissions ?? []
  const can = (p: string) => p.split('|').some((x) => perms.includes(x))
  return SECTIONS.map((sec) => ({ ...sec, items: sec.items.filter((i) => can(i.perm)) })).filter((sec) => sec.items.length > 0)
}

function isActive(pathname: string, to: string) {
  return to === '/' ? pathname === '/' : pathname === to || pathname.startsWith(`${to}/`)
}

/** The single page the URL belongs to: the longest matching navigation entry (so /inventory/explorer is not also /inventory). */
// pages reached from tabs that belong to a navigation entry with a different path
const NAV_ALIAS: Record<string, string> = { '/cost/billing-periods': '/cost/analysis', '/cost': '/cost/overview' }

function bestMatch(pathname: string, items: NavItem[]) {
  const path = Object.entries(NAV_ALIAS).find(([from]) => isActive(pathname, from))?.[1] ?? pathname
  return items.filter((i) => isActive(path, i.to)).sort((a, b) => b.to.length - a.to.length)[0]?.to
}

const OPEN_KEY = 'cn-nav-open'

function Sidebar({ onNavigate, collapsed }: { onNavigate?: () => void; collapsed?: boolean }) {
  const sections = useSections()
  const { pathname } = useLocation()
  const current = bestMatch(pathname, sections.flatMap((s) => s.items))
  const activeKey = sections.find((s) => s.items.some((i) => i.to === current))?.key
  const [open, setOpen] = useState<Record<string, boolean>>(() => { try { return JSON.parse(sessionStorage.getItem(OPEN_KEY) ?? '{}') } catch { return {} } })
  const toggle = (key: string, value?: boolean) => setOpen((o) => {
    const next = { ...o, [key]: value ?? !(o[key] ?? key === activeKey) }
    try { sessionStorage.setItem(OPEN_KEY, JSON.stringify(next)) } catch { /* storage blocked */ }
    return next
  })
  return (
    <nav aria-label="Main" className="flex flex-col gap-0.5">
      {sections.map((sec) => {
        const Icon = sec.icon
        const active = sec.key === activeKey
        if (sec.items.length === 1 || collapsed) {
          const item = sec.items[0]
          return (
            <Link key={sec.key} to={item.to} onClick={onNavigate} title={collapsed ? sec.label : undefined}
              aria-current={active ? 'page' : undefined} className={`cn-side-link ${active ? 'is-active' : ''}`}>
              <Icon size={17} aria-hidden className="shrink-0" />{!collapsed && <span className="truncate">{sec.label}</span>}
            </Link>
          )
        }
        const expanded = open[sec.key] ?? active
        return (
          <div key={sec.key}>
            <button className={`cn-side-link ${active ? 'has-active-child' : ''}`} onClick={() => toggle(sec.key)} aria-expanded={expanded}
              aria-controls={`nav-${sec.key}`}>
              <Icon size={17} aria-hidden className="shrink-0" /><span className="flex-1 truncate text-left">{sec.label}</span>
              <ChevronDown size={14} aria-hidden className={`shrink-0 opacity-60 transition-transform ${expanded ? 'rotate-180' : ''}`} />
            </button>
            {expanded && (
              <div id={`nav-${sec.key}`} className="cn-side-tree mb-1 ml-[18px] mt-0.5 flex flex-col gap-0.5 pl-2">
                {sec.items.map((i) => (
                  <Link key={i.to} to={i.to} onClick={onNavigate} aria-current={current === i.to ? 'page' : undefined}
                    className={`cn-side-sub ${current === i.to ? 'is-active' : ''}`}>{i.label}</Link>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </nav>
  )
}

/** Light / dark / system theme (system follows the operating system). Only the preference name is stored. */
function ThemeMenu() {
  const [pref, setPref] = useState<ThemePref>(getThemePref())
  const { open, setOpen, ref } = usePopover()
  const choose = (p: ThemePref) => { setThemePref(p); setPref(p); setOpen(false) }
  const opts: [ThemePref, string, typeof Sun][] = [['light', 'Light', Sun], ['dark', 'Dark', Moon], ['system', 'System', Monitor]]
  const Current = opts.find((o) => o[0] === pref)![2]
  return (
    <div className="relative" ref={ref}>
      <button className="grid h-9 w-9 place-items-center rounded-full border border-line text-ink-2 transition-colors hover:bg-surface-2"
        onClick={() => setOpen((o) => !o)} aria-haspopup="menu" aria-expanded={open} aria-label={`Theme: ${pref}`}><Current size={15} aria-hidden /></button>
      {open && (
        <div role="menu" aria-label="Theme" className="cn-card cn-float-in absolute right-0 z-40 mt-2 w-40 p-1.5 text-ink" style={{ boxShadow: 'var(--shadow-2)' }}>
          {opts.map(([p, label, Icon]) => (
            <button key={p} role="menuitemradio" aria-checked={pref === p} onClick={() => choose(p)}
              className={`flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm hover:bg-surface-2 ${pref === p ? 'font-semibold text-accent' : ''}`}>
              <Icon size={14} aria-hidden />{label}</button>
          ))}
        </div>
      )}
    </div>
  )
}

interface SyncStatus { running: boolean; integrations: { provider: string; enabled: boolean; health: string; last_success_at: string | null }[] }

/** Data freshness: the oldest "last successful collection" of the enabled clouds. Stale or failing collection is shown, never hidden. */
function Freshness() {
  const can = useCan('sync:read')
  const { refreshKey } = useFilters()
  const st = useApi<SyncStatus>(can ? '/sync/status' : null, undefined, refreshKey)
  if (!can || !st.data) return null
  const enabled = st.data.integrations.filter((i) => i.enabled)
  if (!enabled.length) return <Link to="/connections/onboard" className="cn-chip hidden md:inline-flex">No cloud connected</Link>
  const times = enabled.map((i) => i.last_success_at)
  const never = times.some((t) => !t)
  const oldest = never ? null : times.map((t) => new Date(t!).getTime()).reduce((a, b) => Math.min(a, b))
  const hours = oldest ? (Date.now() - oldest) / 3_600_000 : null
  const failing = enabled.some((i) => i.health !== 'OK')
  const tone = never || (hours !== null && hours > 24) ? 'var(--critical)' : failing || (hours !== null && hours > 6) ? 'var(--warning)' : 'var(--good)'
  const text = never ? 'Not yet collected' : hours! < 1 ? `Data ${Math.max(1, Math.round(hours! * 60))} min old` : `Data ${Math.round(hours!)} h old`
  const title = enabled.map((i) => `${PROVIDER_LABEL[i.provider]}: ${i.health.replace(/_/g, ' ').toLowerCase()}, last success ${i.last_success_at ? new Date(i.last_success_at).toLocaleString('en-IN') : 'never'}`).join('\n')
  return (
    <Link to="/integrations" className="cn-chip hidden md:inline-flex" title={title} aria-label={`Data freshness: ${text}${failing ? ', some collections need attention' : ''}`}>
      <span className={`h-2 w-2 rounded-full ${st.data.running ? 'cn-live' : ''}`} style={{ background: tone }} aria-hidden />{st.data.running ? 'Collecting…' : text}
    </Link>
  )
}

/** Global search over accounts, resources, VMs and findings (results already filtered by the server for this role). */
function GlobalSearch() {
  const [q, setQ] = useState('')
  const [hits, setHits] = useState<SearchHit[] | null>(null)
  const { open, setOpen, ref } = usePopover()
  const navigate = useNavigate()
  const canAll = useCan('inventory:read'), canAssigned = useCan('inventory:read_assigned')
  const canSearch = canAll || canAssigned
  useEffect(() => {
    if (q.trim().length < 2) { setHits(null); return }
    const t = setTimeout(() => { api.get<{ items: SearchHit[] }>('/search', { q: q.trim() }).then((r) => { setHits(r.items); setOpen(true) }).catch(() => setHits([])) }, 250)
    return () => clearTimeout(t)
  }, [q, setOpen])
  if (!canSearch) return null
  const label: Record<string, string> = { scope: 'Account', resource: 'Resource', vm: 'VM', finding: 'Finding' }
  return (
    <div className="relative w-full max-w-sm" ref={ref}>
      <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-3" aria-hidden />
      <input className="cn-input h-9 w-full pl-8" placeholder="Search accounts, resources, VMs, findings" aria-label="Search" value={q}
        onChange={(e) => setQ(e.target.value)} onFocus={() => hits && setOpen(true)} />
      {open && hits && (
        <div role="listbox" aria-label="Search results" className="cn-card cn-float-in absolute left-0 right-0 z-40 mt-1.5 max-h-96 overflow-auto p-1.5" style={{ boxShadow: 'var(--shadow-2)' }}>
          {hits.length === 0 ? <div className="px-2 py-3 text-xs text-ink-3">No matches you have access to.</div> : hits.map((h, i) => (
            <button key={i} role="option" aria-selected={false} className="flex w-full items-start gap-2 rounded-lg px-2 py-1.5 text-left hover:bg-surface-2"
              onClick={() => { setOpen(false); setQ(''); navigate(h.link) }}>
              <span className="mt-0.5 w-16 shrink-0 text-[10.5px] font-semibold uppercase tracking-wide text-ink-3">{label[h.type]}</span>
              <span className="min-w-0"><span className="block truncate text-sm text-ink">{h.title}</span><span className="block truncate text-[11px] text-ink-3">{PROVIDER_LABEL[h.provider]} · {h.subtitle}</span></span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

const COLLAPSE_KEY = 'cn-sidebar-collapsed'

/** Page labels for breadcrumbs: from the navigation, plus the sub-pages reached from tabs. */
const EXTRA_LABELS: Record<string, string> = {
  '/cost/billing-periods': 'Billing periods', '/compliance/policies': 'Policy library', '/vulnerabilities/findings': 'All findings', '/vulnerabilities/overview': 'Posture analytics', '/vulnerabilities/aws': 'AWS Security Hub',
  '/vulnerabilities/azure': 'Microsoft Defender / Advisor', '/vulnerabilities/gcp': 'Google SCC', '/vulnerabilities/remediation': 'Remediation',
  '/vulnerabilities/exceptions': 'Exceptions', '/vulnerabilities/sla': 'SLA', '/vulnerabilities/history': 'History', '/audit/activities': 'Activities',
  '/audit/aws': 'AWS CloudTrail', '/audit/azure': 'Azure Activity Log', '/audit/gcp': 'GCP Audit Logs', '/audit/queue': 'Review queue',
  '/audit/authorized': 'Authorized', '/audit/suspicious': 'Suspicious', '/audit/closed': 'Closed', '/audit/cases': 'Cases', '/audit/rules': 'Rules',
  '/integrations/regions': 'Regions', '/integrations/sync': 'Synchronization', '/integrations/history': 'History', '/integrations/failed': 'Failed',
  '/integrations/permissions': 'Permissions', '/integrations/schedule': 'Schedule', '/cost': 'Cost', 
  '/budgets/alerts': 'Budget alerts', '/connections/onboard/aws': 'AWS', '/connections/onboard/azure': 'Azure', '/connections/onboard/gcp': 'Google Cloud',
  '/budgets/settings': 'Thresholds and approval chains', '/inventory/explorer': 'Inventory explorer', '/admin': 'Administration', '/reports/library': 'Report library',
}
function pageLabel(path: string): string {
  const hit = NAV.find((i) => i.to === path)
  if (hit) return hit.label
  if (EXTRA_LABELS[path]) return EXTRA_LABELS[path]
  const seg = path.split('/').pop() ?? ''
  return seg.charAt(0).toUpperCase() + seg.slice(1).replace(/-/g, ' ')
}

/** Back and breadcrumbs on every page except Home. Back returns to the previous page (keeping its filters, which live in
 *  the address), or to the parent page when the page was opened directly. */
function PageNav() {
  const { pathname } = useLocation()
  const nav = useNavigate()
  const loc = useLocation()
  if (pathname === '/') return null
  const parts = pathname.split('/').filter(Boolean)
  const trail = parts.map((_, i) => '/' + parts.slice(0, i + 1).join('/'))
  const parent = trail.length > 1 ? trail[trail.length - 2] : '/'
  const back = () => (loc.key !== 'default' && window.history.length > 1 ? nav(-1) : nav(parent))
  return (
    <nav aria-label="Breadcrumb" className="flex flex-wrap items-center gap-2 text-[12.5px]">
      <button type="button" onClick={back} className="inline-flex items-center gap-1 rounded-full border border-line bg-surface px-2.5 py-1 font-medium text-ink-2 hover:border-accent hover:text-accent" aria-label="Go back">
        <ChevronLeft size={14} aria-hidden />Back</button>
      <ol className="flex min-w-0 flex-wrap items-center gap-1 text-ink-3">
        <li><Link to="/" className="hover:text-accent">Home</Link></li>
        {trail.map((p, i) => <li key={p} className="flex items-center gap-1"><ChevronRight size={12} aria-hidden />
          {i === trail.length - 1 ? <span aria-current="page" className="font-medium text-ink">{pageLabel(p)}</span> : <Link to={p} className="hover:text-accent">{pageLabel(p)}</Link>}</li>)}
      </ol>
    </nav>
  )
}

export default function AppLayout({ children }: { children?: ReactNode }) {
  const location = useLocation()
  const [drawer, setDrawer] = useState(false)
  const demo = useAuth()?.me.demo_mode ?? false
  const canAutomation = useCan('automation:read'), canInventory = useCan('inventory:read')
  const canSettings = canAutomation || canInventory
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem(COLLAPSE_KEY) === '1' } catch { return false } })
  useEffect(() => setDrawer(false), [location.pathname])
  const toggleCollapsed = () => setCollapsed((c) => { try { localStorage.setItem(COLLAPSE_KEY, c ? '0' : '1') } catch { /* blocked */ } return !c })
  const brand = (small = false) => (
    <Link to="/" className="flex min-w-0 items-center gap-2.5" aria-label={`${BRAND.product} home`}>
      <ProductLogo compact={small} />
    </Link>
  )
  return (
    <div className="min-h-screen lg:flex">
      <a href="#content" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2">Skip to content</a>
      <aside className={`cn-sidebar sticky top-0 hidden h-screen shrink-0 flex-col p-3 lg:flex ${collapsed ? 'w-[68px]' : 'w-[276px]'}`}>
        <div className="mb-4 flex items-center justify-between px-1.5 pt-1">{brand(collapsed)}</div>
        <div className="min-h-0 flex-1 overflow-y-auto pr-0.5"><Sidebar collapsed={collapsed} /></div>
        {!collapsed && <div className="cn-side-brand-sub mt-2 border-t px-2 pt-2 text-[10.5px]" style={{ borderColor: 'var(--side-line)' }}>{BRAND.poweredBy}</div>}
        <button className="cn-side-link mt-1" onClick={toggleCollapsed} aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}>
          {collapsed ? <PanelLeftOpen size={16} aria-hidden /> : <><PanelLeftClose size={16} aria-hidden /><span>Collapse</span></>}
        </button>
      </aside>
      {drawer && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/50" onClick={() => setDrawer(false)} aria-hidden />
          <div className="cn-sidebar cn-toast absolute inset-y-0 left-0 flex w-[280px] flex-col p-3" style={{ animationName: 'cn-fade-up' }}>
            <div className="mb-4 flex items-center justify-between px-1">{brand()}
              <button className="rounded-full p-1.5 text-ink-2 hover:bg-surface-2" onClick={() => setDrawer(false)} aria-label="Close menu"><X size={18} /></button>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto"><Sidebar onNavigate={() => setDrawer(false)} /></div>
          </div>
        </div>
      )}
      <div className="min-w-0 flex-1">
        <header className="cn-topbar sticky top-0 z-30 border-b border-line px-3 py-2 sm:px-5">
          <div className="mx-auto flex max-w-[1560px] items-center gap-2">
            <button className="grid h-9 w-9 shrink-0 place-items-center rounded-full text-ink-2 hover:bg-surface-2 lg:hidden" onClick={() => setDrawer(true)} aria-label="Open menu"><Menu size={18} /></button>
            <GlobalSearch />
            <div className="ml-auto flex items-center gap-2">
              <Freshness />
              <AssistantButton />
              <NotificationBell />
              <ThemeMenu />
              {canSettings && <Link to="/system-health" className="hidden h-9 w-9 place-items-center rounded-full border border-line text-ink-2 transition-colors hover:bg-surface-2 sm:grid"
                aria-label="Settings and system health" title="Settings and system health"><Settings size={15} aria-hidden /></Link>}
              <UserMenu />
            </div>
          </div>
          <div className="mx-auto mt-2 max-w-[1560px] empty:hidden"><FilterBar /></div>
        </header>
        {demo && <div role="status" className="border-b px-4 py-1.5 text-center text-[12.5px] font-medium"
          style={{ background: 'color-mix(in srgb, var(--warning) 16%, var(--surface-1))', borderColor: 'color-mix(in srgb, var(--warning) 45%, var(--line))', color: 'var(--text-primary)' }}>
          Demo mode – fictional sample data on a separate demo database. No cloud is connected and no e-mail or chat message is sent.</div>}
        <main id="content" key={location.pathname} className="cn-page mx-auto w-full max-w-[1560px] space-y-5 px-3 pb-10 pt-5 sm:px-5">
          <PageNav />
          {children ?? <Outlet />}
        </main>
      </div>
    </div>
  )
}
