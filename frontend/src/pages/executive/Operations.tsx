import { Cloud, Gavel, Plus, UserCog } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useCan } from '../../auth/AuthContext'
import { Panel } from '../../components/hero'
import { Drawer, Pill, Section, useAction } from '../../components/secops'
import { PROVIDER_LABEL, fmtInt } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'

interface Decision { id: number; key: string; title: string; source: string; risk_summary: string; business_impact: string; recommended_action: string; priority: string
  owner: string; due_date: string | null; status: string; overdue: boolean; decision: string | null; decided_by: string | null }
interface Ops { clouds: Record<string, { scopes: number; healthy: number; degraded: number; not_connected: number; health_pct: number | null }>
  kpis: { key: string; label: string; value: number | null; link: string; reason?: string | null }[]; iam_exceptions_by_risk: Record<string, number>; decisions: Decision[] }

/** Per-cloud connection health, identity / operations KPIs and the management decision register (executive view). */
export default function ExecutiveOperations() {
  const g = useCan('governance:manage'), sa = useCan('security:admin'), ad = useCan('admin:users')
  const canRaise = g || sa || ad
  const [bump, setBump] = useState(0)
  const [creating, setCreating] = useState(false)
  const [deciding, setDeciding] = useState<Decision | null>(null)
  const [d, setD] = useState({ title: '', source: 'manual', risk_summary: '', business_impact: '', recommended_action: '', priority: 'High', owner: '', due_date: '' })
  const [dec, setDec] = useState({ status: 'DECIDED', decision: '' })
  const { data } = useApi<Ops>('/executive/operations-health', undefined, bump)
  const { run, busy } = useAction(() => { setBump((b) => b + 1); setCreating(false); setDeciding(null) })
  if (!data) return null
  return (
    <>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <Panel icon={<Cloud size={15} />} title="Cloud health" subtitle="Share of scopes whose every data source synchronizes (Cloud Connections)">
          <div className="grid grid-cols-3 gap-3">{['aws', 'azure', 'gcp'].map((p) => { const c = data.clouds[p]; return (
            <Link key={p} to="/connections" className="cn-card cn-lift px-3 py-2"><div className="text-xs font-semibold">{PROVIDER_LABEL[p]}</div>
              <div className="tabular text-[22px] font-semibold">{c?.health_pct === null || c?.health_pct === undefined ? '—' : `${c.health_pct}%`}</div>
              <div className="text-[11px] text-ink-3">{c ? `${c.healthy}/${c.scopes} healthy · ${c.degraded} degraded` : 'not connected'}</div></Link>) })}</div>
        </Panel>
        <Panel icon={<UserCog size={15} />} title="Identity and operations">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">{data.kpis.map((k) => (
            <Link key={k.key} to={k.link} className="cn-card cn-lift px-3 py-2"><div className="text-[11px] text-ink-3">{k.label}</div><div className="tabular text-[20px] font-semibold">{k.value === null ? '—' : fmtInt(k.value)}</div>
              {k.value === null && k.reason && <div className="text-[10.5px] text-ink-3">{k.reason}</div>}</Link>))}</div>
        </Panel>
      </div>
      <Panel icon={<Gavel size={15} />} title={`Management decisions (${data.decisions.length} open)`} subtitle="Risk, business impact, accountable owner, recommended action and due date"
        action={canRaise ? <button className="cn-btn cn-btn-ghost h-8 text-xs" onClick={() => setCreating(true)}><Plus size={13} aria-hidden />Raise decision</button> : undefined}>
        {data.decisions.length === 0 ? <p className="text-sm text-ink-3">No open management decisions.</p> : <ul className="divide-y divide-line">{data.decisions.map((x) => (
          <li key={x.id} className="grid gap-1 py-2 text-sm md:grid-cols-[90px_1fr_200px_120px_110px]">
            <Pill value={x.priority} /><button className="text-left hover:underline" onClick={() => setDeciding(x)}><b>{x.title}</b><div className="text-xs text-ink-3">{x.business_impact}</div></button>
            <span className="text-xs">{x.owner}</span><span className="text-xs" style={{ color: x.overdue ? 'var(--critical)' : undefined }}>{x.due_date ?? 'no due date'}{x.overdue ? ' (overdue)' : ''}</span>
            <span className="font-mono text-xs text-ink-3">{x.key}</span></li>))}</ul>}
      </Panel>
      {creating && <Drawer title="Raise a management decision" onClose={() => setCreating(false)}>
        <form className="grid gap-2" onSubmit={(e) => { e.preventDefault(); run(() => api.post('/executive/decisions', { ...d, due_date: d.due_date || null }), 'Decision raised') }}>
          <input className="cn-input" required minLength={3} placeholder="Title" aria-label="Title" value={d.title} onChange={(e) => setD({ ...d, title: e.target.value })} />
          <input className="cn-input" placeholder="Source (e.g. finding:123, IAMX-0004)" aria-label="Source" value={d.source} onChange={(e) => setD({ ...d, source: e.target.value })} />
          {(['risk_summary', 'business_impact', 'recommended_action'] as const).map((k) => <textarea key={k} className="cn-input min-h-14" required minLength={3} placeholder={k.replace('_', ' ')} aria-label={k} value={d[k]} onChange={(e) => setD({ ...d, [k]: e.target.value })} />)}
          <div className="grid grid-cols-3 gap-2"><select className="cn-input" aria-label="Priority" value={d.priority} onChange={(e) => setD({ ...d, priority: e.target.value })}>{['Critical', 'High', 'Medium', 'Low'].map((p) => <option key={p}>{p}</option>)}</select>
            <input className="cn-input" required type="email" placeholder="Accountable owner" aria-label="Owner" value={d.owner} onChange={(e) => setD({ ...d, owner: e.target.value })} />
            <input className="cn-input" type="date" aria-label="Due date" value={d.due_date} onChange={(e) => setD({ ...d, due_date: e.target.value })} /></div>
          <button className="cn-btn cn-btn-primary h-9 w-fit text-sm" disabled={busy}>Raise</button>
        </form></Drawer>}
      {deciding && <Drawer title={`${deciding.key} · ${deciding.title}`} subtitle={<Pill value={deciding.priority} />} onClose={() => setDeciding(null)}>
        <Section title="Risk"><p className="text-sm">{deciding.risk_summary}</p><p className="mt-1 text-sm"><b>Business impact:</b> {deciding.business_impact}</p><p className="mt-1 text-sm"><b>Recommended action:</b> {deciding.recommended_action}</p>
          <p className="mt-1 text-xs text-ink-3">Owner {deciding.owner} · due {deciding.due_date ?? '—'} · source {deciding.source}</p></Section>
        <Section title="Record the decision">
          <select className="cn-input mb-2" aria-label="Status" value={dec.status} onChange={(e) => setDec({ ...dec, status: e.target.value })}>{['DECIDED', 'DEFERRED', 'CLOSED', 'OPEN'].map((s) => <option key={s}>{s}</option>)}</select>
          <textarea className="cn-input min-h-16 w-full" placeholder="Decision or reason" aria-label="Decision" value={dec.decision} onChange={(e) => setDec({ ...dec, decision: e.target.value })} />
          <button className="cn-btn cn-btn-primary mt-2 h-8 text-xs" disabled={busy} onClick={() => run(() => api.patch(`/executive/decisions/${deciding.id}`, { status: dec.status, decision: dec.decision || null }), 'Decision recorded')}>Save</button>
        </Section></Drawer>}
    </>
  )
}
