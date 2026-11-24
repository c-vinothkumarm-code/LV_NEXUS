import { AlertTriangle, Check } from 'lucide-react'
import { useState } from 'react'
import { useCan } from '../../auth/AuthContext'
import { Confirm, Pill, post, useAction } from '../../components/secops'
import { PROVIDER_LABEL, fmtAgo } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { ScopeName } from '../../hooks/useScopeNames'

interface Anomaly { id: number; rule: string; severity: string; title: string; provider: string; scope: string; scope_name?: string | null; principal: string | null
  detail: Record<string, unknown>; event_count: number; first_event_at: string; last_event_at: string; status: string }
const RULES: [string, string][] = [['new_country', 'New country'], ['new_source_ip', 'New IP'], ['unusual_hours', 'Unusual hours'],
  ['failure_spike', 'Failure spike'], ['privilege_change', 'Privilege change'], ['mass_deletion', 'Mass deletion']]

function evidence(a: Anomaly): string {
  const d = a.detail as Record<string, never>
  if (a.rule === 'new_source_ip') return `IP ${(d.source_ips as string[]).join(', ')} · ${d.known_ips} known IPs in history`
  if (a.rule === 'new_country') return `${(d.countries as string[]).join(', ')} · usually ${(d.known_countries as string[]).join(', ') || '—'}`
  if (a.rule === 'unusual_hours') return `${(d.local_hours as number[]).map((h) => `${String(h).padStart(2, '0')}:00`).join(', ')} ${d.timezone} · ${d.share_of_history_pct}% of history`
  if (a.rule === 'failure_spike' || a.rule === 'mass_deletion') return `${d.max_in_window} in ${d.window_minutes} min · ${((d.operations as string[]) ?? []).slice(0, 3).join(', ')}`
  return ((d.operations as string[]) ?? []).join(', ')
}

/** Unusual activity found by comparing each principal with its own history. Acknowledging records a reviewer note only. */
export default function Anomalies() {
  const [bump, setBump] = useState(0), [rule, setRule] = useState(''), [acking, setAcking] = useState<Anomaly | null>(null)
  const canAck = useCan('audit:investigate')
  const { data } = useApi<{ items: Anomaly[]; open_by_rule: Record<string, number>; last_run_at: string | null }>('/activity/anomalies', { rule: rule || undefined, hours: 168 }, bump)
  const { run } = useAction(() => setBump((b) => b + 1))
  if (!data) return null
  return (
    <section className="cn-card p-5" aria-label="Anomalies">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-[15px] font-semibold"><AlertTriangle size={16} style={{ color: 'var(--serious)' }} aria-hidden />Unusual activity, last 7 days</h2>
        <span className="text-[11.5px] text-ink-3">Detection runs every 5 minutes{data.last_run_at ? ` · last ${fmtAgo(data.last_run_at)}` : ''}</span>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">{RULES.map(([k, l]) => <button key={k} type="button" onClick={() => setRule(rule === k ? '' : k)}
        className={`rounded-full border px-3 py-1 text-xs ${rule === k ? 'border-accent text-accent' : 'border-line'}`}>{l} <b className="tabular">{data.open_by_rule[k] ?? 0}</b></button>)}</div>
      {data.items.length === 0 ? <p className="py-6 text-center text-sm text-ink-3">Nothing unusual detected{rule ? ' for this rule' : ''}.</p> :
        <ul className="mt-3 divide-y divide-line">{data.items.slice(0, 12).map((a) => <li key={a.id} className="flex flex-wrap items-start gap-3 py-2.5 text-sm">
          <Pill value={a.severity} />
          <div className="min-w-0 flex-1"><div className="font-medium">{a.title} <span className="font-normal text-ink-3">· {a.principal ?? 'unknown principal'}</span></div>
            <div className="truncate text-[12px] text-ink-3">{PROVIDER_LABEL[a.provider]} <ScopeName provider={a.provider} id={a.scope} name={a.scope_name} /> · {evidence(a)} · {a.event_count} event(s), {fmtAgo(a.last_event_at)}</div></div>
          {canAck && <button type="button" className="cn-btn cn-btn-ghost h-7 text-xs" onClick={() => setAcking(a)}><Check size={12} aria-hidden />Acknowledge</button>}
        </li>)}</ul>}
      {acking && <Confirm title={`Acknowledge: ${acking.title}`} body="Record who checked this and why it is expected, or what follows. Nothing is changed in the cloud."
        needReason reasonLabel="Reviewer note" confirm="Acknowledge" onCancel={() => setAcking(null)}
        onConfirm={(note) => { const a = acking; setAcking(null); run(() => post(`/activity/anomalies/${a.id}/acknowledge`, { note }), 'Acknowledged') }} />}
    </section>
  )
}
