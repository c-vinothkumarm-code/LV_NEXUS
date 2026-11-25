import { BellRing, ClipboardCheck, FilePlus2, Landmark, Plus, Settings2, Wallet } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useLocation, useSearchParams } from 'react-router-dom'
import { useCan, useMe } from '../../auth/AuthContext'
import { Panel, SubTabs } from '../../components/hero'
import { DataGrid, Drawer, FilterPanel, KV, Pill, Section, Select, TextFilter, Timeline, useAction, type Col } from '../../components/secops'
import { ErrorNote, ExportButton, PageHeader, PageSkeleton, PROVIDER_LABEL, fmtUsd } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { api, type Scope } from '../../services/api'
import { ScopeName } from '../../hooks/useScopeNames'

/* ---------------------------------------------------------------- types */
interface Step { key: string; label: string; status: string; by: string | null; at: string | null }
interface Position {
  period_start: string; approved_monthly_usd: number; actual_mtd_usd: number | null; actual_is_provisional: boolean; forecast_month_usd: number | null
  forecast_method: string; remaining_usd: number | null; utilisation_percent: number | null; level: string | null
}
interface Budget {
  id: number; budget_key: string; name: string; level: string; parent_id: number | null; environment: string | null; provider: string | null
  account_name: string | null; scope_external_id: string | null; project_application: string | null; business_entity: string | null; service: string | null
  currency: string; original_monthly_amount: number; original_annual_amount: number | null; fx_rate_to_usd: number | null
  original_monthly_usd: number; approved_monthly_usd: number; approved_annual_usd: number | null; start_date: string; end_date: string
  email_subject: string | null; native_alert_name: string | null; owner: string | null; status: string; thresholds: number[]; created_by: string
  created_at: string | null; updated_at: string | null; approvals: { request_id: number | null; request_status?: string; steps: Step[] }; position: Position | null
}
interface BudgetDetail extends Budget {
  revisions: { id: number; change_monthly_usd: number; previous_monthly_usd: number; revised_monthly_usd: number; effective_date: string; reason: string; approvers: { step: string; by: string }[]; email_reference: string | null; recorded_by: string; created_at: string }[]
  requests: Req[]; alerts: Alert[]; allocations: { id: number; budget_key: string; name: string; approved_monthly_usd: number; status: string }[]
  history: { action: string; actor: string; at: string }[]; monthly_actuals: { month: string; actual_usd: number | null; provisional: boolean }[]
}
interface Req {
  id: number; request_key: string; request_type: string; budget_id: number | null; status: string; steps: { key: string; label: string; permission: string }[]
  current_step: number; current_step_label: string | null; current_step_permission: string | null; existing_monthly_usd: number | null
  actual_mtd_usd: number | null; forecast_month_usd: number | null; amount_monthly_usd: number; proposed_monthly_usd: number | null; justification: string
  requester: string; requesting_team: string | null; email_subject: string | null; outcome_note: string | null; created_at: string | null; budget?: [string, string] | null
  service_details: Record<string, unknown> | null
}
interface Alert {
  id: number; budget_id: number; budget_key: string | null; budget_name: string | null; scope: string | null; period_start: string; level: string; threshold: number
  approved_usd: number; actual_usd: number; forecast_usd: number | null; remaining_usd: number; utilisation_percent: number; owner: string | null
  required_action: string; source: string; native_alert_name: string | null; notified: { channel: string; at: string }[]; acknowledged_by: string | null; created_at: string
}
interface Summary {
  approved_monthly_usd: number; approved_annual_usd: number; actual_mtd_usd: number | null; actual_covers_budgets: number; root_budgets: number
  remaining_usd: number | null; utilisation_percent: number | null; forecast_month_usd: number | null; over_budget: { id: number; budget_key: string; name: string; utilisation_percent: number }[]
  approaching: { id: number; budget_key: string; name: string; utilisation_percent: number }[]; pending_requests: number; awaiting_finance: number
  expired: number; draft: number; open_alerts: number; billing_last_collected: string | null; note: string
}

export const BUDGET_TABS = [{ to: '/budgets', label: 'Budget tracker' },
  { to: '/budgets/alerts', label: 'Budget alerts' }, { to: '/budgets/settings', label: 'Thresholds and approval chains' }]
const TYPE_LABEL: Record<string, string> = { new_budget: 'New budget', additional_budget: 'Additional budget', budget_decrease: 'Budget decrease', new_service: 'New cloud service' }
const STATUS_TONE: Record<string, string> = { DRAFT: 'NOT_CONFIGURED', PENDING: 'PENDING', APPROVED: 'APPROVED', ACTIVE: 'COMPLETED', EXPIRED: 'EXPIRED', REJECTED: 'REJECTED' }
const usd = (v: number | null | undefined) => (v === null || v === undefined ? 'not collected' : fmtUsd(v))
const dash = (v: number | null | undefined) => (v === null || v === undefined ? '—' : fmtUsd(v))
const day = (v: string | null | undefined) => (v ? new Date(v.length === 10 ? `${v}T00:00:00` : v).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }) : '—')

function Utilisation({ p }: { p: Position | null }) {
  if (!p) return <span className="text-xs text-ink-3">not active</span>
  if (p.utilisation_percent === null) return <span className="text-xs text-ink-3">no billing data yet</span>
  const u = p.utilisation_percent
  const tone = u > 100 ? 'var(--critical)' : u >= 90 ? '#ec835a' : u >= 75 ? '#d99100' : 'var(--good)'
  return (
    <div className="min-w-[120px]">
      <div className="flex justify-between text-xs"><span className="tabular font-semibold">{u.toFixed(1)}%</span><span className="text-ink-3">{p.level}</span></div>
      <div className="mt-1 h-1.5 rounded-full bg-surface-2"><div className="h-1.5 rounded-full" style={{ width: `${Math.min(100, u)}%`, background: tone }} /></div>
    </div>
  )
}

/* ---------------------------------------------------------------- register */
const EMPTY = { name: '', level: 'account', environment: 'Production', provider: 'azure', scope_external_id: '', project_application: '', business_entity: '', service: '',
  monthly_amount: '', annual_amount: '', currency: 'USD', fx_rate_to_usd: '', fx_rate_date: '', start_date: '', end_date: '', email_subject: '', native_alert_name: '', owner: '', parent_id: '' }

function BudgetForm({ onDone, onCancel, budgets }: { onDone: () => void; onCancel: () => void; budgets: Budget[] }) {
  const [f, setF] = useState(EMPTY)
  const scopes = useApi<{ items: Scope[] }>('/inventory/scopes')
  const { run, busy } = useAction(onDone)
  const inp = (k: keyof typeof EMPTY, label: string, type = 'text', req = false) => (
    <label className="text-xs text-ink-3">{label}{req && ' *'}<input className="cn-input mt-1 w-full" type={type} required={req} value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} /></label>
  )
  const submit = () => run(() => api.post('/budgets', {
    ...f, monthly_amount: Number(f.monthly_amount), annual_amount: f.annual_amount ? Number(f.annual_amount) : null,
    fx_rate_to_usd: f.fx_rate_to_usd ? Number(f.fx_rate_to_usd) : null, fx_rate_date: f.fx_rate_date || null, parent_id: f.parent_id ? Number(f.parent_id) : null,
    provider: f.level === 'organization' || f.level === 'business_entity' ? null : f.provider, scope_external_id: f.level === 'account' ? f.scope_external_id : null,
    ...Object.fromEntries(['project_application', 'business_entity', 'service', 'email_subject', 'native_alert_name', 'owner'].map((k) => [k, f[k as keyof typeof EMPTY] || null])),
  }), 'Budget registered as draft')
  return (
    <Drawer title="Register a budget" subtitle="Saved as a draft; submit it for approval from the register." onClose={onCancel}>
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); submit() }}>
        {inp('name', 'Budget name', 'text', true)}
        <label className="text-xs text-ink-3">Level *<select className="cn-input mt-1 w-full" value={f.level} onChange={(e) => setF({ ...f, level: e.target.value })}>
          {['organization', 'provider', 'environment', 'account', 'business_entity', 'project', 'service'].map((l) => <option key={l} value={l}>{l.replace('_', ' ')}</option>)}</select></label>
        <label className="text-xs text-ink-3">ENV<select className="cn-input mt-1 w-full" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })}>
          {['', 'Production', 'UAT', 'Development', 'POC', 'Sandbox'].map((l) => <option key={l} value={l}>{l || '—'}</option>)}</select></label>
        <label className="text-xs text-ink-3">Cloud provider<select className="cn-input mt-1 w-full" value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value, scope_external_id: '' })}>
          {['aws', 'azure', 'gcp'].map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p]}</option>)}</select></label>
        {f.level === 'account' && (
          <label className="text-xs text-ink-3 sm:col-span-2">Account / subscription / project *<select className="cn-input mt-1 w-full" required value={f.scope_external_id} onChange={(e) => setF({ ...f, scope_external_id: e.target.value })}>
            <option value="">Select from the discovered inventory…</option>
            {(scopes.data?.items ?? []).filter((s) => s.provider === f.provider).map((s) => <option key={s.external_id} value={s.external_id}>{s.name || s.external_id} ({s.external_id})</option>)}</select></label>
        )}
        {inp('project_application', 'Project / application')}{inp('business_entity', 'Business entity')}
        {inp('service', 'Service (only for service-level budgets)')}
        <label className="text-xs text-ink-3">Allocation of (parent budget)<select className="cn-input mt-1 w-full" value={f.parent_id} onChange={(e) => setF({ ...f, parent_id: e.target.value })}>
          <option value="">None (top-level budget)</option>{budgets.map((b) => <option key={b.id} value={b.id}>{b.budget_key} {b.name}</option>)}</select></label>
        {inp('monthly_amount', 'Approved monthly amount', 'number', true)}{inp('annual_amount', 'Approved annual amount (blank = 12 x monthly)', 'number')}
        <label className="text-xs text-ink-3">Currency *<select className="cn-input mt-1 w-full" value={f.currency} onChange={(e) => setF({ ...f, currency: e.target.value })}>
          {['USD', 'INR', 'EUR', 'GBP'].map((c) => <option key={c}>{c}</option>)}</select></label>
        {f.currency !== 'USD' && <>{inp('fx_rate_to_usd', `USD per 1 ${f.currency} used for approval`, 'number', true)}{inp('fx_rate_date', 'Exchange-rate date', 'date', true)}</>}
        {inp('start_date', 'Start date', 'date', true)}{inp('end_date', 'End date', 'date', true)}
        {inp('owner', 'Budget owner (person or team)')}{inp('native_alert_name', 'Native cloud budget alert name')}
        <div className="sm:col-span-2">{inp('email_subject', 'Approval e-mail subject (reference only; approvals are recorded in the workflow)')}</div>
        <div className="flex gap-2 sm:col-span-2"><button className="cn-btn cn-btn-primary h-9 text-sm" disabled={busy}>Save draft</button><button type="button" className="cn-btn cn-btn-ghost h-9 text-sm" onClick={onCancel}>Cancel</button></div>
      </form>
    </Drawer>
  )
}

function RequestForm({ budget, onDone, onCancel }: { budget: Budget | null; onDone: () => void; onCancel: () => void }) {
  const isService = budget === null
  const [f, setF] = useState({ type: isService ? 'new_service' : 'additional_budget', amount: '', justification: '', team: '', email_subject: '', email_reference: '', effective: '', docs: '',
    purpose: '', provider: 'azure', scope: '', service: '', requirements: '', est_month: '', est_year: '' })
  const { run, busy } = useAction(onDone)
  const t = (k: keyof typeof f, label: string, type = 'text', req = false, area = false) => (
    <label className={`text-xs text-ink-3 ${area ? 'sm:col-span-2' : ''}`}>{label}{req && ' *'}{area
      ? <textarea className="cn-input mt-1 min-h-16 w-full" required={req} value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} />
      : <input className="cn-input mt-1 w-full" type={type} required={req} value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} />}</label>
  )
  const submit = () => {
    const amt = Number(f.amount || f.est_month || 0) * (f.type === 'budget_decrease' ? -1 : 1)
    return run(() => api.post('/budget-requests', {
      request_type: f.type, budget_id: budget?.id ?? null, amount_monthly_usd: amt, justification: f.justification, requesting_team: f.team || null,
      email_subject: f.email_subject || null, email_reference: f.email_reference || null, effective_date: f.effective || null,
      supporting_documents: f.docs.split('\n').map((d) => d.trim()).filter(Boolean),
      service_details: f.type === 'new_service' ? { business_purpose: f.purpose, provider: f.provider, scope: f.scope || null, service: f.service, technical_requirements: f.requirements,
        estimated_monthly_cost_usd: Number(f.est_month), estimated_annual_cost_usd: f.est_year ? Number(f.est_year) : Number(f.est_month) * 12 } : null,
    }), 'Request submitted for approval')
  }
  return (
    <Drawer title={isService ? 'Request a new cloud service' : `Change budget ${budget?.budget_key}`} subtitle={budget ? `${budget.name}: approved ${fmtUsd(budget.approved_monthly_usd)} per month` : 'Approval is recorded here; provisioning is done separately by an authorized administrator.'} onClose={onCancel}>
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); submit() }}>
        {!isService && <label className="text-xs text-ink-3">Request type<select className="cn-input mt-1 w-full" value={f.type} onChange={(e) => setF({ ...f, type: e.target.value })}>
          <option value="additional_budget">Additional budget</option><option value="budget_decrease">Budget decrease</option></select></label>}
        {!isService && t('amount', f.type === 'budget_decrease' ? 'Decrease per month (USD)' : 'Additional amount per month (USD)', 'number', true)}
        {!isService && budget?.position && <div className="rounded-lg bg-surface-2 p-2 text-xs sm:col-span-2">Month to date {usd(budget.position.actual_mtd_usd)} · forecast {usd(budget.position.forecast_month_usd)} (estimate). These are recorded with the request.</div>}
        {isService && <>{t('purpose', 'Business purpose', 'text', true)}
          <label className="text-xs text-ink-3">Cloud provider *<select className="cn-input mt-1 w-full" value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value })}>{['aws', 'azure', 'gcp'].map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p]}</option>)}</select></label>
          {t('scope', 'Account / subscription / project')}{t('service', 'Requested service', 'text', true)}
          {t('est_month', 'Estimated monthly cost (USD)', 'number', true)}{t('est_year', 'Estimated annual cost (USD)', 'number')}
          {t('requirements', 'Technical requirements', 'text', false, true)}</>}
        {t('justification', 'Business justification', 'text', true, true)}{t('team', 'Requesting team')}{t('effective', 'Requested effective date', 'date')}
        {t('email_subject', 'E-mail subject')}{t('email_reference', 'E-mail message reference')}
        {t('docs', 'Supporting documents (one link per line)', 'text', false, true)}
        <div className="flex gap-2 sm:col-span-2"><button className="cn-btn cn-btn-primary h-9 text-sm" disabled={busy}>Submit for approval</button><button type="button" className="cn-btn cn-btn-ghost h-9 text-sm" onClick={onCancel}>Cancel</button></div>
      </form>
    </Drawer>
  )
}

function BudgetPanel({ id, onClose, onChanged }: { id: number; onClose: () => void; onChanged: () => void }) {
  const canManage = useCan('budget:manage')
  const [bump, setBump] = useState(0)
  const { data } = useApi<BudgetDetail>(`/budgets/${id}`, undefined, bump)
  const done = useCallback(() => { setBump((b) => b + 1); onChanged() }, [onChanged])
  const { run, busy } = useAction(done)
  const [req, setReq] = useState(false)
  if (!data) return <Drawer title="Loading budget" onClose={onClose}><div className="text-sm text-ink-3">Loading…</div></Drawer>
  const p = data.position
  return (
    <Drawer title={`${data.budget_key} · ${data.name}`} subtitle={<span className="flex items-center gap-2"><Pill value={STATUS_TONE[data.status]} text={data.status.toLowerCase()} />{data.level.replace('_', ' ')} budget</span>} onClose={onClose} width={860}>
      <Section title="This month" action={canManage && ['ACTIVE', 'APPROVED'].includes(data.status) ? <button className="cn-btn cn-btn-ghost h-7 text-xs" onClick={() => setReq(true)}><FilePlus2 size={12} aria-hidden />Request change</button> : undefined}>
        {p ? <KV items={[['Approved monthly (USD)', fmtUsd(p.approved_monthly_usd)], ['Actual month to date', <span>{usd(p.actual_mtd_usd)}{p.actual_is_provisional && <span className="text-ink-3"> (provisional)</span>}</span>],
          ['Forecast for the month', <span>{usd(p.forecast_month_usd)} <span className="text-ink-3">({p.forecast_method})</span></span>], ['Remaining', usd(p.remaining_usd)],
          ['Utilisation', <Utilisation p={p} />], ['Thresholds', data.thresholds.map((t) => `${t}%`).join(', ')]]} />
          : <p className="text-sm text-ink-3">Spend is tracked once the budget is approved and its start date is reached.</p>}
      </Section>
      <Section title="Register">
        <KV items={[['ENV', data.environment], ['Cloud provider', data.provider ? PROVIDER_LABEL[data.provider] : 'All'], ['Account name', data.account_name], ['Account ID', data.scope_external_id],
          ['Project / application', data.project_application], ['Business entity', data.business_entity], ['Service', data.service],
          ['Original approved monthly', `${data.original_monthly_amount.toLocaleString('en-IN')} ${data.currency}${data.currency !== 'USD' ? ` (rate ${data.fx_rate_to_usd} → ${fmtUsd(data.original_monthly_usd)})` : ''}`],
          ['Current approved monthly (USD)', fmtUsd(data.approved_monthly_usd)], ['Approved annual (USD)', usd(data.approved_annual_usd)], ['Time line', `${day(data.start_date)} to ${day(data.end_date)}`],
          ['Budget owner', data.owner], ['Native budget alert', data.native_alert_name ?? 'none recorded'], ['E-mail subject', data.email_subject], ['Created', `${day(data.created_at)} by ${data.created_by}`], ['Last updated', day(data.updated_at)]]} />
      </Section>
      <Section title="Approvals">
        {data.approvals.steps.length ? <ul className="space-y-1 text-sm">{data.approvals.steps.map((s) => (
          <li key={s.key} className="flex items-center justify-between"><span>{s.label}</span><span className="flex items-center gap-2 text-xs text-ink-3">{s.by && `${s.by} · ${day(s.at)}`}<Pill value={s.status === 'APPROVED' ? 'APPROVED' : s.status === 'REJECTED' ? 'REJECTED' : 'PENDING'} text={s.status.toLowerCase()} /></span></li>))}</ul>
          : <p className="text-xs text-ink-3">Not yet submitted for approval.</p>}
        {canManage && ['DRAFT', 'REJECTED'].includes(data.status) && <button className="cn-btn cn-btn-primary mt-2 h-8 text-xs" disabled={busy} onClick={() => run(() => api.post(`/budgets/${id}/submit`, {}), 'Submitted for approval')}>Submit for approval</button>}
      </Section>
      <Section title={`Revisions (${data.revisions.length})`}>
        {data.revisions.length ? <ul className="space-y-2 text-sm">{data.revisions.map((r) => (
          <li key={r.id} className="rounded-lg border border-line p-2"><div className="font-medium">{r.change_monthly_usd > 0 ? '+' : ''}{fmtUsd(r.change_monthly_usd)} / month: {fmtUsd(r.previous_monthly_usd)} → {fmtUsd(r.revised_monthly_usd)} from {day(r.effective_date)}</div>
            <div className="text-xs text-ink-3">{r.reason}</div><div className="text-xs text-ink-3">Approved by {r.approvers.map((a) => `${a.step}: ${a.by}`).join(' · ')}{r.email_reference ? ` · e-mail ${r.email_reference}` : ''}</div></li>))}</ul>
          : <p className="text-xs text-ink-3">No revisions. The original approved amount is unchanged.</p>}
      </Section>
      <Section title="Monthly actuals (USD)">
        <ul className="grid grid-cols-3 gap-2 text-xs sm:grid-cols-6">{data.monthly_actuals.map((m) => <li key={m.month} className="rounded-lg bg-surface-2 p-2"><div className="text-ink-3">{m.month}</div><div className="tabular font-semibold">{usd(m.actual_usd)}</div>{m.provisional && <div className="text-ink-3">provisional</div>}</li>)}</ul>
      </Section>
      {data.allocations.length > 0 && <Section title="Allocations"><ul className="text-sm">{data.allocations.map((a) => <li key={a.id}>{a.budget_key} {a.name}: {fmtUsd(a.approved_monthly_usd)} ({a.status.toLowerCase()})</li>)}</ul></Section>}
      <Section title={`Alerts (${data.alerts.length})`}>{data.alerts.length ? <ul className="text-sm">{data.alerts.map((a) => <li key={a.id} className="flex justify-between"><span>{a.period_start.slice(0, 7)} · {a.level}</span><span className="tabular">{a.utilisation_percent.toFixed(1)}%</span></li>)}</ul> : <p className="text-xs text-ink-3">No alerts.</p>}</Section>
      <Section title="History"><Timeline items={data.history.map((h) => ({ at: h.at, title: h.action.replace(/[._]/g, ' '), body: h.actor }))} /></Section>
      {req && <RequestForm budget={data} onCancel={() => setReq(false)} onDone={() => { setReq(false); done() }} />}
    </Drawer>
  )
}

export function BudgetRegister() {
  const canManage = useCan('budget:manage')
  const [params, setParams] = useSearchParams()
  const [f, setF] = useState({ status: '', provider: '', environment: '', q: '' })
  const [bump, setBump] = useState(0)
  const [creating, setCreating] = useState(false)
  const [service, setService] = useState(false)
  const list = useApi<{ items: Budget[]; statuses: string[]; environments: string[] }>('/budgets', f, bump)
  const sum = useApi<Summary>('/budgets/summary', undefined, bump)
  const refresh = useCallback(() => setBump((b) => b + 1), [])
  if (list.error) return <ErrorNote message={list.error.message} onRetry={list.reload} />
  if (!list.data || !sum.data) return <PageSkeleton tiles={6} />
  const s = sum.data
  const open = Number(params.get('budget')) || null
  const cols: Col<Budget>[] = [
    { key: 'key', label: 'ID', render: (b) => <span className="font-mono text-xs">{b.budget_key}</span> },
    { key: 'name', label: 'Budget', render: (b) => <div className="max-w-xs"><div className="truncate font-medium">{b.name}</div><div className="truncate text-[11px] text-ink-3">{b.project_application ?? b.level.replace('_', ' ')}{b.parent_id ? ' · allocation' : ''}</div></div> },
    { key: 'env', label: 'ENV', render: (b) => b.environment ?? '—' },
    { key: 'acct', label: 'Account', render: (b) => (b.scope_external_id ? <span>{b.provider && PROVIDER_LABEL[b.provider]} · {b.account_name ?? b.scope_external_id}</span> : (b.provider ? PROVIDER_LABEL[b.provider] : 'All clouds')) },
    { key: 'amt', label: 'Approved / month', render: (b) => <span className="tabular">{fmtUsd(b.approved_monthly_usd)}</span> },
    { key: 'act', label: 'Actual MTD', render: (b) => <span className="tabular">{b.position ? usd(b.position.actual_mtd_usd) : '—'}</span> },
    { key: 'util', label: 'Utilisation', render: (b) => <Utilisation p={b.position} /> },
    { key: 'appr', label: 'Approvals', render: (b) => <span className="text-xs">{b.approvals.steps.length ? b.approvals.steps.map((x) => `${x.label.split(' ')[0]} ${x.status === 'APPROVED' ? '✓' : x.status === 'REJECTED' ? '✗' : '…'}`).join(' · ') : 'not submitted'}</span> },
    { key: 'owner', label: 'Owner', render: (b) => b.owner ?? '—' },
    { key: 'status', label: 'Status', render: (b) => <Pill value={STATUS_TONE[b.status]} text={b.status.toLowerCase()} /> },
  ]
  const kpis: [string, string, string?][] = [
    ['Approved per month', fmtUsd(s.approved_monthly_usd), `${s.root_budgets} top-level active budgets`], ['Approved per year', fmtUsd(s.approved_annual_usd)],
    ['Actual month to date', usd(s.actual_mtd_usd), s.actual_mtd_usd !== null ? `${s.actual_covers_budgets} of ${s.root_budgets} budgets have billing data` : 'billing not collected'],
    ['Utilisation', s.utilisation_percent === null ? '—' : `${s.utilisation_percent.toFixed(1)}%`, `remaining ${usd(s.remaining_usd)}`],
    ['Forecast for the month', usd(s.forecast_month_usd), 'run-rate estimate'], ['Over budget', String(s.over_budget.length), `${s.approaching.length} approaching (75%+)`],
    ['Pending requests', String(s.pending_requests), `${s.awaiting_finance} awaiting Finance`], ['Open alerts', String(s.open_alerts), `${s.expired} expired · ${s.draft} draft`],
  ]
  return (
    <>
      <PageHeader eyebrow="FinOps" title="Budget tracker"
        description="The authoritative record of Finance-approved cloud budgets, compared with collected spend. Original approvals are never overwritten; changes are approved revisions."
        action={canManage ? <div className="flex gap-2"><button className="cn-btn cn-btn-ghost h-9 text-sm" onClick={() => setService(true)}><FilePlus2 size={14} aria-hidden />New service request</button>
          <button className="cn-btn cn-btn-primary h-9 text-sm" onClick={() => setCreating(true)}><Plus size={14} aria-hidden />Register budget</button></div> : undefined} />
      <SubTabs items={BUDGET_TABS} />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {kpis.map(([l, v, n]) => <div key={l} className="cn-card px-4 py-3"><div className="text-[11.5px] text-ink-3">{l}</div><div className="tabular mt-1 text-[20px] font-semibold">{v}</div>{n && <div className="text-[11px] text-ink-3">{n}</div>}</div>)}
      </div>
      <Panel icon={<Wallet size={15} />} title={`Budgets (${list.data.items.length})`} subtitle={s.note}
        action={<ExportButton name="Budget register" head={['ID', 'ENV', 'Cloud Provider', 'Account Name', 'Account ID', 'Project / Application', 'Approved Monthly Budget (USD)', 'Approved Annual Budget (USD)', 'Currency', 'Original monthly (currency)', 'Start', 'End', 'Project Team Approval', 'Finance Approval', 'Internal Approval', 'Email Subject', 'Budget Alert Name', 'Budget Owner', 'Status', 'Actual MTD (USD)', 'Utilisation %', 'Created', 'Last Updated']}
          rows={list.data.items.map((b) => { const st = (k: string) => { const x = b.approvals.steps.find((y) => y.key === k); return x ? `${x.status}${x.by ? ` (${x.by})` : ''}` : '' }
            return [b.budget_key, b.environment, b.provider, b.account_name, b.scope_external_id, b.project_application, b.approved_monthly_usd, b.approved_annual_usd, b.currency, b.original_monthly_amount, b.start_date, b.end_date, st('project_team'), st('finance'), st('internal'), b.email_subject, b.native_alert_name, b.owner, b.status, b.position?.actual_mtd_usd, b.position?.utilisation_percent, b.created_at, b.updated_at] })} />}>
        <FilterPanel onClear={() => setF({ status: '', provider: '', environment: '', q: '' })}>
          <Select label="Status" value={f.status} onChange={(v) => setF({ ...f, status: v })} options={list.data.statuses} />
          <Select label="Cloud" value={f.provider} onChange={(v) => setF({ ...f, provider: v })} options={[{ value: 'aws', label: 'AWS' }, { value: 'azure', label: 'Azure' }, { value: 'gcp', label: 'GCP' }]} />
          <Select label="ENV" value={f.environment} onChange={(v) => setF({ ...f, environment: v })} options={list.data.environments} />
          <TextFilter label="Search" value={f.q} onChange={(v) => setF({ ...f, q: v })} placeholder="Name, ID, account, project" />
        </FilterPanel>
        <DataGrid label="Budget register" cols={cols} rows={list.data.items} onOpen={(b) => setParams({ budget: String(b.id) })} empty="No budgets registered yet." />
      </Panel>
      <BudgetApprovals refreshKey={bump} />
      {open && <BudgetPanel id={open} onClose={() => setParams({})} onChanged={refresh} />}
      {creating && <BudgetForm budgets={list.data.items} onCancel={() => setCreating(false)} onDone={() => { setCreating(false); refresh() }} />}
      {service && <RequestForm budget={null} onCancel={() => setService(false)} onDone={() => { setService(false); refresh() }} />}
    </>
  )
}

/* ---------------------------------------------------------------- requests */
function RequestPanel({ id, onClose, onChanged }: { id: number; onClose: () => void; onChanged: () => void }) {
  const me = useMe()
  const [bump, setBump] = useState(0)
  const { data } = useApi<Req & { history: { step: string; decision: string; actor: string; notes: string | null; email_reference: string | null; at: string }[]; budget: { id: number; budget_key: string; name: string } | null }>(`/budget-requests/${id}`, undefined, bump)
  const done = useCallback(() => { setBump((b) => b + 1); onChanged() }, [onChanged])
  const { run, busy } = useAction(done)
  const [notes, setNotes] = useState('')
  const [ref, setRef] = useState('')
  if (!data) return <Drawer title="Loading request" onClose={onClose}><div className="text-sm text-ink-3">Loading…</div></Drawer>
  const mine = data.requester === me?.email
  const canAct = data.status === 'PENDING' && !mine && !!data.current_step_permission && !!me?.permissions.includes(data.current_step_permission)
  const decide = (decision: string) => run(() => api.post(`/budget-requests/${id}/decision`, { decision, notes: notes || null, email_reference: ref || null }), 'Decision recorded')
  return (
    <Drawer title={`${data.request_key} · ${TYPE_LABEL[data.request_type]}`} subtitle={<span className="flex items-center gap-2"><Pill value={data.status} />{data.current_step_label ? `Waiting for: ${data.current_step_label}` : data.outcome_note}</span>} onClose={onClose}>
      <Section title="Request">
        <KV items={[['Budget', data.budget ? `${data.budget.budget_key} ${data.budget.name}` : '—'], ['Requested by', `${data.requester}${data.requesting_team ? ` (${data.requesting_team})` : ''}`],
          ['Existing approved / month', dash(data.existing_monthly_usd)], ['Actual MTD at request', dash(data.actual_mtd_usd)], ['Forecast at request', dash(data.forecast_month_usd)],
          ['Amount / month', fmtUsd(data.amount_monthly_usd)], ['Proposed / month', usd(data.proposed_monthly_usd)], ['E-mail subject', data.email_subject]]} />
        <p className="mt-2 text-sm">{data.justification}</p>
        {data.service_details && <pre className="mt-2 rounded-lg bg-surface-2 p-2 text-[11px]">{JSON.stringify(data.service_details, null, 2)}</pre>}
      </Section>
      <Section title="Approval chain">
        <ol className="space-y-1 text-sm">{data.steps.map((s, i) => (
          <li key={s.key} className="flex justify-between"><span>{i + 1}. {s.label}</span><span className="text-xs text-ink-3">{i < data.current_step || data.status === 'APPROVED' ? 'approved' : i === data.current_step && data.status === 'PENDING' ? 'waiting' : data.status === 'REJECTED' && i === data.current_step ? 'rejected' : 'not started'}</span></li>))}</ol>
      </Section>
      {canAct && (
        <Section title={`Decide: ${data.current_step_label}`}>
          <textarea className="cn-input min-h-16 w-full text-sm" placeholder="Notes (required to reject or ask for information)" aria-label="Decision notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
          <input className="cn-input mt-2 w-full text-sm" placeholder="Approval e-mail message reference (optional evidence)" aria-label="E-mail reference" value={ref} onChange={(e) => setRef(e.target.value)} />
          <div className="mt-2 flex flex-wrap gap-2">
            <button className="cn-btn cn-btn-primary h-8 text-xs" disabled={busy} onClick={() => decide('APPROVED')}>Approve</button>
            <button className="cn-btn cn-btn-ghost h-8 text-xs" disabled={busy} onClick={() => decide('REJECTED')}>Reject</button>
            <button className="cn-btn cn-btn-ghost h-8 text-xs" disabled={busy} onClick={() => decide('MORE_INFO')}>Request more information</button>
          </div>
        </Section>
      )}
      {mine && data.status === 'MORE_INFO' && (
        <Section title="Provide the requested information">
          <textarea className="cn-input min-h-16 w-full text-sm" aria-label="Information" value={notes} onChange={(e) => setNotes(e.target.value)} />
          <button className="cn-btn cn-btn-primary mt-2 h-8 text-xs" disabled={busy || !notes} onClick={() => run(() => api.post(`/budget-requests/${id}/respond`, { decision: 'x', notes }), 'Information sent')}>Send</button>
        </Section>
      )}
      {mine && ['PENDING', 'MORE_INFO'].includes(data.status) && <button className="cn-btn cn-btn-ghost mb-4 h-8 text-xs" disabled={busy} onClick={() => run(() => api.post(`/budget-requests/${id}/withdraw`, {}), 'Request withdrawn')}>Withdraw request</button>}
      <Section title="History"><Timeline items={data.history.slice().reverse().map((h) => ({ at: h.at, title: `${h.step}: ${h.decision.toLowerCase().replace('_', ' ')} · ${h.actor}`, body: [h.notes, h.email_reference && `e-mail ${h.email_reference}`].filter(Boolean).join(' · ') || undefined, tone: h.decision }))} /></Section>
    </Drawer>
  )
}

/** Budget requests and approvals, shown inside the Budget tracker (no separate page). */
function BudgetApprovals({ refreshKey }: { refreshKey: number }) {
  const [params, setParams] = useSearchParams()
  const loc = useLocation()
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => { if (loc.hash === '#approvals') ref.current?.scrollIntoView({ block: 'start' }) }, [loc.hash])
  const [f, setF] = useState({ status: '', request_type: '', awaiting_me: '' })
  const [bump, setBump] = useState(0)
  const list = useApi<{ items: Req[] }>('/budget-requests', f, bump + refreshKey * 1000)
  const refresh = useCallback(() => setBump((b) => b + 1), [])
  if (list.error) return <ErrorNote message={list.error.message} onRetry={list.reload} />
  if (!list.data) return <PageSkeleton tiles={0} />
  const open = Number(params.get('request')) || null
  const pending = list.data.items.filter((r) => ['PENDING', 'MORE_INFO'].includes(r.status)).length
  const cols: Col<Req>[] = [
    { key: 'key', label: 'ID', render: (r) => <span className="font-mono text-xs">{r.request_key}</span> },
    { key: 'type', label: 'Type', render: (r) => TYPE_LABEL[r.request_type] },
    { key: 'budget', label: 'Budget', render: (r) => (r.budget ? `${r.budget[0]} ${r.budget[1]}` : (r.service_details?.service as string) ?? '—') },
    { key: 'amt', label: 'Amount / month', render: (r) => <span className="tabular">{fmtUsd(r.amount_monthly_usd)}</span> },
    { key: 'req', label: 'Requested by', render: (r) => r.requester },
    { key: 'step', label: 'Waiting for', render: (r) => r.current_step_label ?? '—' },
    { key: 'status', label: 'Status', render: (r) => <Pill value={r.status} /> },
    { key: 'at', label: 'Created', render: (r) => day(r.created_at) },
  ]
  return (
    <div id="approvals" ref={ref} className="scroll-mt-20">
      <Panel icon={<ClipboardCheck size={15} />} title={`Budget requests and approvals (${pending} open)`}
        subtitle="New budgets, additional budget, decreases and new services. Each step needs its own approver; a requester cannot approve their own request. The approved amount changes only after the final approval is recorded." 
        action={<ExportButton name="Budget requests" head={['ID', 'Type', 'Budget', 'Amount per month (USD)', 'Proposed per month', 'Requester', 'Status', 'Waiting for', 'Outcome', 'Created']}
          rows={list.data.items.map((r) => [r.request_key, TYPE_LABEL[r.request_type], r.budget?.[0], r.amount_monthly_usd, r.proposed_monthly_usd, r.requester, r.status, r.current_step_label, r.outcome_note, r.created_at])} />}>
        <FilterPanel onClear={() => setF({ status: '', request_type: '', awaiting_me: '' })}>
          <Select label="Show" value={f.awaiting_me} onChange={(v) => setF({ ...f, awaiting_me: v })} options={[{ value: 'true', label: 'Awaiting my approval' }]} all="All requests" />
          <Select label="Status" value={f.status} onChange={(v) => setF({ ...f, status: v })} options={['PENDING', 'MORE_INFO', 'APPROVED', 'REJECTED', 'WITHDRAWN']} />
          <Select label="Type" value={f.request_type} onChange={(v) => setF({ ...f, request_type: v })} options={Object.entries(TYPE_LABEL).map(([value, label]) => ({ value, label }))} />
        </FilterPanel>
        <DataGrid label="Budget requests" cols={cols} rows={list.data.items} onOpen={(r) => setParams({ request: String(r.id) })} empty="No requests in this view." />
      </Panel>
      {open && <RequestPanel id={open} onClose={() => setParams({})} onChanged={refresh} />}
    </div>
  )
}

/* ---------------------------------------------------------------- alerts */
export function BudgetAlerts() {
  const canManage = useCan('budget:manage')
  const canConfigure = useCan('budget:configure')
  const [openOnly, setOpenOnly] = useState('true')
  const [bump, setBump] = useState(0)
  const list = useApi<{ items: Alert[] }>('/budget-alerts', { open_only: openOnly || undefined }, bump)
  const { run, busy } = useAction(() => setBump((b) => b + 1))
  if (list.error) return <ErrorNote message={list.error.message} onRetry={list.reload} />
  if (!list.data) return <PageSkeleton tiles={0} />
  const cols: Col<Alert>[] = [
    { key: 'level', label: 'Level', render: (a) => <Pill value={a.threshold > 100 ? 'Critical' : a.threshold >= 90 ? 'High' : a.threshold >= 75 ? 'Medium' : 'Low'} text={a.level} /> },
    { key: 'budget', label: 'Budget', render: (a) => <div><div className="font-medium">{a.budget_key} {a.budget_name}</div><div className="text-[11px] text-ink-3"><ScopeName id={a.scope} /></div></div> },
    { key: 'amt', label: 'Approved / actual', render: (a) => <span className="tabular text-xs">{fmtUsd(a.approved_usd)} / {fmtUsd(a.actual_usd)}</span> },
    { key: 'fc', label: 'Forecast', render: (a) => usd(a.forecast_usd) },
    { key: 'util', label: 'Utilisation', render: (a) => `${a.utilisation_percent.toFixed(1)}%` },
    { key: 'owner', label: 'Owner', render: (a) => a.owner ?? '—' },
    { key: 'src', label: 'Source', render: (a) => <span className="text-xs">LV NEXUS alert{a.native_alert_name ? ` · native: ${a.native_alert_name}` : ''}</span> },
    { key: 'at', label: 'Alert date', render: (a) => day(a.created_at) },
    { key: 'ack', label: '', render: (a) => (a.acknowledged_by ? <span className="text-xs text-ink-3">acknowledged by {a.acknowledged_by}</span>
      : canManage ? <button className="cn-btn cn-btn-ghost h-7 text-xs" disabled={busy} onClick={() => run(() => api.post(`/budget-alerts/${a.id}/acknowledge`, {}), 'Alert acknowledged')}>Acknowledge</button> : null) },
  ]
  return (
    <>
      <PageHeader eyebrow="FinOps" title="Budget alerts"
        description="Internal LV NEXUS alerts raised the first time a budget crosses each threshold in a month. They are separate from the provider's own budget alerts, and never stop or change any workload."
        action={canConfigure ? <button className="cn-btn cn-btn-ghost h-9 text-sm" disabled={busy} onClick={() => run(() => api.post('/budget-alerts/evaluate', {}), 'Budgets evaluated')}><BellRing size={14} aria-hidden />Evaluate now</button> : undefined} />
      <SubTabs items={BUDGET_TABS} />
      <Panel icon={<BellRing size={15} />} title={`Alerts (${list.data.items.length})`}
        action={<div className="flex items-center gap-2"><Select label="Show" value={openOnly} onChange={setOpenOnly} options={[{ value: 'true', label: 'Not acknowledged' }]} all="All alerts" />
          <ExportButton name="Budget alerts" head={['Budget', 'Scope', 'Month', 'Level', 'Approved', 'Actual', 'Forecast', 'Remaining', 'Utilisation %', 'Owner', 'Required action', 'Notified', 'Alert date']}
            rows={list.data.items.map((a) => [a.budget_key, a.scope, a.period_start, a.level, a.approved_usd, a.actual_usd, a.forecast_usd, a.remaining_usd, a.utilisation_percent, a.owner, a.required_action, a.notified.map((n) => n.channel).join(';'), a.created_at])} /></div>}>
        <DataGrid label="Budget alerts" cols={cols} rows={list.data.items} empty="No budget alerts." />
      </Panel>
    </>
  )
}

/* ---------------------------------------------------------------- settings */
export function BudgetSettings() {
  const canConfigure = useCan('budget:configure')
  const [bump, setBump] = useState(0)
  const data = useApi<{ thresholds: number[]; workflows: { id: number; request_type: string; min_amount_usd: number; steps: { key: string; label: string; permission: string }[]; enabled: boolean; updated_by: string | null }[]; step_catalogue: { key: string; label: string; permission: string }[]; request_types: string[] }>('/budget-settings', undefined, bump)
  const { run, busy } = useAction(() => setBump((b) => b + 1))
  const [ths, setThs] = useState('')
  const [wf, setWf] = useState({ request_type: 'additional_budget', min_amount_usd: '0', steps: '' })
  if (data.error) return <ErrorNote message={data.error.message} onRetry={data.reload} />
  if (!data.data) return <PageSkeleton tiles={0} />
  const d = data.data
  return (
    <>
      <PageHeader eyebrow="FinOps" title="Thresholds and approval chains"
        description="Alert thresholds apply to every budget unless a budget sets its own. Approval chains are chosen by request type and amount: the chain with the highest minimum amount not above the request applies." />
      <SubTabs items={BUDGET_TABS} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel icon={<Settings2 size={15} />} title="Alert thresholds" subtitle="Above 100% is always 'Budget exceeded'">
          <div className="flex flex-wrap gap-1.5">{d.thresholds.map((t) => <span key={t} className="rounded-full border border-line px-2.5 py-0.5 text-sm tabular">{t}%</span>)}</div>
          {canConfigure && <form className="mt-3 flex gap-2" onSubmit={(e) => { e.preventDefault(); run(() => api.put('/budget-settings/thresholds', { thresholds: ths.split(',').map((x) => Number(x.trim())).filter(Boolean) }), 'Thresholds saved') }}>
            <input className="cn-input flex-1" placeholder="e.g. 50, 75, 90, 100" aria-label="Thresholds" value={ths} onChange={(e) => setThs(e.target.value)} /><button className="cn-btn cn-btn-primary h-9 text-sm" disabled={busy}>Save</button></form>}
        </Panel>
        <Panel icon={<Landmark size={15} />} title="Approval steps available" subtitle="Each step requires the listed permission">
          <ul className="space-y-1 text-sm">{d.step_catalogue.map((s) => <li key={s.key} className="flex justify-between"><span>{s.label} <code className="text-[11px] text-ink-3">{s.key}</code></span><code className="text-xs">{s.permission}</code></li>)}</ul>
        </Panel>
      </div>
      <Panel icon={<ClipboardCheck size={15} />} title="Approval chains">
        <ul className="divide-y divide-line">{d.workflows.map((w) => (
          <li key={w.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
            <span><b>{TYPE_LABEL[w.request_type]}</b> from {fmtUsd(w.min_amount_usd)} per month{!w.enabled && ' (disabled)'}</span>
            <span className="text-xs">{w.steps.map((s) => s.label).join(' → ')}</span><span className="text-[11px] text-ink-3">updated by {w.updated_by}</span>
          </li>))}</ul>
        {canConfigure && (
          <form className="mt-3 grid gap-2 sm:grid-cols-[1fr_140px_2fr_auto]" onSubmit={(e) => { e.preventDefault(); run(() => api.put('/budget-settings/workflows', { request_type: wf.request_type, min_amount_usd: Number(wf.min_amount_usd || 0), steps: wf.steps.split(',').map((k) => ({ key: k.trim() })).filter((s) => s.key) }), 'Approval chain saved') }}>
            <select className="cn-input" aria-label="Request type" value={wf.request_type} onChange={(e) => setWf({ ...wf, request_type: e.target.value })}>{d.request_types.map((t) => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}</select>
            <input className="cn-input" type="number" min={0} aria-label="From amount per month (USD)" placeholder="From USD / month" value={wf.min_amount_usd} onChange={(e) => setWf({ ...wf, min_amount_usd: e.target.value })} />
            <input className="cn-input" aria-label="Steps" placeholder={`Steps in order, e.g. ${d.step_catalogue.map((s) => s.key).slice(0, 3).join(', ')}`} value={wf.steps} onChange={(e) => setWf({ ...wf, steps: e.target.value })} />
            <button className="cn-btn cn-btn-primary h-9 text-sm" disabled={busy}>Save chain</button>
          </form>
        )}
      </Panel>
    </>
  )
}
