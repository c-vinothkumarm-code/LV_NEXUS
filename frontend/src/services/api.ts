export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

type Params = Record<string, string | number | undefined | null>

function qs(params?: Params): string {
  if (!params) return ''
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

async function request<T>(method: string, path: string, params?: Params, body?: unknown): Promise<T> {
  const res = await fetch(`/api/v1${path}${qs(params)}`, {
    method,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'mcp-dashboard' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.status === 401 && !path.startsWith('/auth/')) {
    // The session expired or was revoked: tell the app shell to show the sign-in page (no token is kept in the browser).
    window.dispatchEvent(new CustomEvent('cloudnexus:unauthorized'))
  }
  if (!res.ok) {
    let detail = res.statusText
    try {
      detail = (await res.json()).detail ?? detail
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  return res.json() as Promise<T>
}

export const api = {
  get: <T,>(path: string, params?: Params) => request<T>('GET', path, params),
  post: <T,>(path: string, body?: unknown) => request<T>('POST', path, undefined, body),
  put: <T,>(path: string, body?: unknown) => request<T>('PUT', path, undefined, body),
  patch: <T,>(path: string, body?: unknown) => request<T>('PATCH', path, undefined, body),
  delete: <T,>(path: string) => request<T>('DELETE', path),
}

/* ---- response types (mirror backend/app/api) ---- */
export type Provider = 'aws' | 'gcp' | 'azure'
export interface Collection { job: string; state: 'collected' | 'not_collected' | 'failed'; last_run_at: string | null; last_status: string | null }
export interface Check { status: 'pass' | 'fail' | 'unknown' | 'not_applicable'; detail?: string; remediation?: string }
export interface Scope {
  provider: Provider; scope_type: string; external_id: string; name: string; provider_state: string; parent: string | null
  environment: string | null; onboarding_status: string; checks: Record<string, Check>; monitoring_enabled: boolean
  first_discovered_at: string; last_seen_at: string | null; last_validated_at: string | null
}
export interface AutomationStats { success_rate_percent: number | null; counts: Record<string, number>; window_days: number }
export interface Overview {
  scopes: Record<Provider, { total: number; fully_onboarded: number }>
  total_resources: number
  vms: { total: number; healthy: number; unhealthy: number; unknown: number; stopped: number }
  findings: { critical: number; high: number; pending_investigations: number }
  cost: { period_start: string; currency: string; by_provider: Record<string, number>; total: number | null; is_final: boolean }
  budget: { approved: number | null; utilisation_percent: number | null }
  automation: AutomationStats
  collection: Record<'inventory' | 'soc' | 'finops' | 'infrastructure', Collection>
  filters: { provider: string | null; scope: string | null; from: string; to: string }
  findings_open_by_severity: Record<string, number>
  provider_health: Record<Provider, ProviderHealth>
  freshness: Record<string, Freshness>
  scheduler: Scheduler
  jobs: JobBrief[]
  cost_daily: CostPoint[]
  cost_monthly: Record<string, number | string>[]
  cost_weekly: Weekly
  recent_events: CloudEvent[]
  alerts: { level: string; area: string; text: string }[]
  vm_utilisation: Utilisation
  resources_by_type: Record<string, number>
  generated_at: string
}
export interface ProviderHealth {
  state: 'healthy' | 'degraded' | 'failing' | 'pending' | 'not_connected'; enabled: boolean; scopes_active: number; fully_onboarded: number
  access_failed: number; failures: { job: string; scope: string; reason: string }[]; failure_count: number
  last_connection_test: { at: string; ok: boolean; detail: string } | null
}
export interface Freshness { last_run_at: string | null; last_status: string | null; last_success_at: string | null }
export interface Scheduler { state: 'active' | 'stale' | 'never_run'; last_scheduled_run_at: string | null; minutes_since?: number }
export interface JobBrief { name: string; description: string; last_status: string | null; last_finished_at: string | null; next_run_at: string | null; implemented: boolean; enabled: boolean; running: boolean }
export type CostPoint = { date: string } & Record<string, number | string>
export interface Weekly { current_week: number; previous_week: number; variation_percent: number | null; top_increasing_services: { service: string; increase_usd: number; new: boolean }[] }
export interface CloudEvent {
  id: number; provider: Provider; scope: string; time: string; event_name: string; principal: string | null; source_ip: string | null
  resource_id: string | null; severity: string | null; outcome: string | null; flagged: boolean; source: string
}
export interface MetricStat { average: number | null; max: number | null; reporting: number; missing: number }
export interface Utilisation { running_with_samples: number; cpu: MetricStat; memory: MetricStat; disk: MetricStat }
export interface AdminUser {
  id: number; email: string; display_name: string | null; roles: string[]; role_labels: string[]; is_active: boolean; last_login_at: string | null; created_at: string
  access_status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED'; google_sub_bound: boolean; authorized_at: string | null; access_expires_at: string | null
  role_source: string; created_by: string | null; modified_by: string | null; open_sessions: number; scopes: { provider: Provider; scope_external_id: string }[]
}
export interface AccessEvent { id: number; event: string; reason: string | null; email: string | null; ip_address: string | null; created_at: string }
export interface SearchHit { type: 'scope' | 'resource' | 'vm' | 'finding'; provider: Provider; title: string; subtitle: string; link: string }
export interface AuditEntry { id: number; actor: string; action: string; target: string | null; detail: Record<string, unknown>; created_at: string }
export interface MissingItem { provider: Provider; external_id: string; name: string; status: string; detail?: string }
export interface OnboardingSummary {
  total: number; by_status: Record<string, number>; by_provider: Record<Provider, Record<string, number>>
  missing: Record<string, MissingItem[]>; recently_discovered: Scope[]; open_tasks: number
}
export interface Task {
  id: number; provider: Provider; scope_external_id: string; title: string; description: string | null
  proposed_action: string | null; status: string; decided_by: string | null; decided_at: string | null; created_at: string
}
export interface OnboardingRecord {
  id: number; provider: Provider; scope_external_id: string; scope_name: string | null; event_type: string
  previous_status: string | null; new_status: string; detail: string | null; created_at: string
}
export interface Execution {
  id: number; job_name: string; trigger: string; triggered_by: string | null; status: string; started_at: string
  finished_at: string | null; scopes_total: number; scopes_failed: number
  failures: { provider: string; scope: string; name?: string; reason: string }[]; error: string | null
}
export interface Job {
  name: string; description: string; schedule: string; timezone: string; enabled: boolean; implemented: boolean
  last_status: string | null; last_started_at: string | null; last_finished_at: string | null; running: boolean
}
export interface Automation { jobs: Job[]; executions: Execution[]; stats: AutomationStats; notifications: Record<string, number>; scheduler: Scheduler; freshness: Record<string, Freshness>; next_runs: Record<string, string | null> }
export interface Finding {
  id: number; provider: string; scope: string; title: string; severity: string; review_status: string; principal: string | null
  rule_id: string; risk_score: number; occurrences: number; recommended_action: string | null; ai_analysis: string | null; last_seen_at: string
  resource_id: string | null; first_seen_at: string; updated_at: string; source: string
}
export interface FindingDetail extends Omit<Finding, 'scope' | 'occurrences'> {
  scope: string; occurrence_count: number; evidence: Record<string, unknown>
  reviews: { id: number; previous_status: string | null; new_status: string; reviewer: string; notes: string | null; evidence_reference: string | null; created_at: string }[]
}
export interface Soc {
  collection: Collection; events_collected: number; by_cloud: Record<string, number>; by_severity: Record<string, number>
  by_review_status: Record<string, number>; by_scope: Record<string, number>; by_principal: Record<string, number>
  trend: { date: string; findings: number }[]; remediation: Record<string, number>
  recent_findings: Finding[]
  incidents: Record<string, number>
  posture: Record<string, Record<string, number>>
  recent_events: CloudEvent[]
  affected_resources: { resource: string; findings: number }[]
  generated_at: string
}
export interface FinOps {
  collection: Collection; range: { from: string; to: string }; month_to_date: Overview['cost']
  daily: { date: string; provider: string; cost_usd: number }[]
  by_service: { name: string; cost_usd: number }[]; by_scope: { name: string; cost_usd: number }[]; budgets: number
  budget_status: BudgetStatus[]; anomalies: { provider: string; scope: string; date: string; cost_usd: number; baseline_mean_usd: number; increase_percent: number | null }[]
  weekly: { current_week: number; previous_week: number; variation_percent: number | null; top_increasing_services: { service: string; increase_usd: number; new: boolean }[] }
  forecast_total: number | null; fx_configured: boolean
  monthly: Record<string, number | string>[]
  previous_month: { month: string; total_actual: number; is_final: boolean; previous_month: number; mom_variation_percent: number | null; approved_budget: number | null; budget_variance: number | null }
  metadata: { last_collected_at: string | null; original_currencies: Record<string, number>; reporting_currency: string; fx_usd_inr_rate: number | null
    provisional_records: number; total_records: number; periods: Record<string, string>; azure_period_starts: { scope: string; period_start: string }[] }
  by_provider_range: Record<string, number>
  generated_at: string
}
export interface BudgetStatus {
  id: number; provider: string; scope: string; service: string; currency: string; period_start: string; period_end: string; approved: number
  actual: number; utilisation_percent: number | null; remaining: number; level: string | null; level_label: string; forecast: number | null
}
export interface Infra {
  collection: Collection; by_health: Record<string, number>; by_power_state: Record<string, number>; by_provider: Record<string, number>
  public_ip_count: number; exposed_count: number
  by_region: Record<string, number>; by_scope: Record<string, number>; utilisation: Utilisation; resources_by_type: Record<string, number>; generated_at: string
  vms: { provider: string; scope: string; name: string | null; region: string | null; instance_type: string | null; power_state: string | null; public_ip: string | null; private_ip: string | null; health_status: string; exposed_ports: string[]
    cpu_percent: number | null; memory_percent: number | null; disk_percent: number | null; missing_metrics: string[] | null
    network_in_bytes: number | null; network_out_bytes: number | null }[]
  open_alerts: { vm_id: number; vm: string | null; provider: string | null; type: string; severity: string; message: string | null; created_at: string }[]
}
export interface Me { email: string; display_name: string | null; roles: string[]; role_labels?: string[]; permissions: string[]; auth_mode: string; app_name?: string; session_minutes?: number; session_idle_minutes?: number; session_expires_at?: string | null; access_expires_at?: string | null; demo_mode?: boolean }
export interface AuthProviders { mode: string; environment: string; app_name: string; demo_mode?: boolean; session_minutes: number; messages?: Record<string, string>; providers: { id: string; label: string; url: string }[]; problem: string | null }
export interface Prereq { providers: { provider: Provider; enabled: boolean; items: { name: string; configured: boolean; note: string }[] }[] }
export interface ConnectionField { key: string; label: string; help: string; required: boolean; kind: 'text' | 'sensitive' | 'list'; value: string; is_set: boolean; source: string }
export interface Connection {
  provider: Provider; enabled: boolean; managed_in_dashboard: boolean; sign_in: string; fields: ConnectionField[]; missing: string[]
  last_test: { at: string; ok: boolean; detail: string } | null; updated_by: string | null
}
export interface ConnectionTest { provider: Provider; ok: boolean; detail: string; scopes_visible: number | null }
