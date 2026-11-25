import { Download, FileCheck2, Landmark, PlayCircle, Scale, ShieldAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useCan } from '../../auth/AuthContext'
import { ComparisonChart, Panel, SubTabs, type HeroSeries } from '../../components/hero'
import { DataGrid, Drawer, FilterPanel, Section, Select, post, put, useAction, type Col } from '../../components/secops'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_LABEL, fmtAgo } from '../../components/ui'
import { useApi } from '../../hooks/useApi'

export const COMPLIANCE_TABS = [{ to: '/compliance', label: 'Compliance overview' }, { to: '/compliance/policies', label: 'Policy library' }]

interface Framework { key: string; name: string; version: string; obligation: string; obligation_label: string; authority: string; note: string
  score?: number | null; coverage?: number; policies?: number; policies_failing?: number; results_pass?: number; results_fail?: number; results_not_assessed?: number }
interface PolicyRow { key: string; title: string; domain: string; domain_label: string; severity: string; default_severity: string; enabled: boolean; kind: string
  status: string; why: string; remediation: string; frameworks: string[]; refs: Record<string, string[]>; params: Record<string, unknown>
  scopes_failing: number; scopes_passing: number; scopes_not_assessed: number; owner: string | null; legal: boolean
  attestation: { status: string; by: string; at: string; evidence: string; valid_until: string } | null }
interface Overview { run: { id: number; finished_at: string; trigger: string; by: string | null } | null
  totals: { policies: number; enabled: number; pass: number; fail: number; not_assessed: number }; frameworks: Framework[]
  domains: { key: string; label: string; policies: number; pass: number; fail: number; not_assessed: number }[]; top_failing: PolicyRow[]
  trend: Record<string, string | number | null>[]; disclaimer: string }
interface Detail extends PolicyRow { run_at: string | null; notes: string | null
  references: { framework: string; obligation: string; items: string[] }[]
  results: { provider: string; scope: string; scope_name: string; status: string; detail: string; evidence: { item: string; issue: string; severity?: string; evidence?: string }[]; basis: string | null }[] }

const STATUS: Record<string, { label: string; cls: string }> = {
  PASS: { label: 'Pass', cls: 'bg-good/10 text-good' }, FAIL: { label: 'Fail', cls: 'bg-critical/10 text-critical' },
  NOT_ASSESSED: { label: 'Not assessed', cls: 'bg-surface-2 text-ink-3' }, NOT_RUN: { label: 'Not run yet', cls: 'bg-surface-2 text-ink-3' },
  DISABLED: { label: 'Off', cls: 'bg-surface-2 text-ink-3' } }
const SEV: Record<string, string> = { Critical: 'text-critical', High: 'text-warning', Medium: 'text-ink-2', Low: 'text-ink-3' }

export function StatusTag({ s }: { s: string }) {
  const v = STATUS[s] ?? { label: s, cls: 'bg-surface-2 text-ink-3' }
  return <span className={`inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-[11.5px] font-semibold ${v.cls}`}>{v.label}</span>
}

function ScoreBar({ score, coverage }: { score?: number | null; coverage?: number }) {
  const s = score ?? 0
  const color = score == null ? 'var(--line)' : s >= 85 ? 'var(--good, #067647)' : s >= 60 ? 'var(--warning, #b54708)' : 'var(--critical, #b42318)'
  return (
    <div>
      <div className="flex items-baseline justify-between"><span className="tabular text-[22px] font-semibold">{score == null ? '–' : `${score}%`}</span>
        <span className="text-[11px] text-ink-3">{coverage ?? 0}% of checks assessed</span></div>
      <div className="mt-1 h-2 rounded-full bg-surface-2"><div className="h-2 rounded-full" style={{ width: `${score ?? 0}%`, background: color }} /></div>
    </div>
  )
}

function reportUrl(fw: string, format: 'html' | 'csv') { return `/api/v1/compliance/report?framework=${fw}&format=${format}` }

/** Compliance overview: legal requirements first (in force, then upcoming), voluntary frameworks, domains, the worst gaps. */
export default function ComplianceOverview() {
  const [bump, setBump] = useState(0)
  const { data, error, reload } = useApi<Overview>('/compliance/overview', undefined, bump)
  const canManage = useCan('governance:manage')
  const { run, busy } = useAction(() => setBump((b) => b + 1))
  const [open, setOpen] = useState<string | null>(null)
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  const legal = data?.frameworks.filter((f) => f.obligation === 'legal' || f.obligation === 'legal_upcoming') ?? []
  const voluntary = data?.frameworks.filter((f) => f.obligation === 'voluntary' || f.obligation === 'internal') ?? []
  const series: HeroSeries[] = [{ key: 'certin', label: 'CERT-In', color: '#1d4ed8' }, { key: 'dpdp', label: 'DPDP', color: '#7c3aed' }, { key: 'iso27001', label: 'ISO 27001', color: '#0e9384' }]
  return (
    <>
      <PageHeader eyebrow="Governance & Compliance" title="Compliance"
        description="Automated checks over your live cloud data, mapped to Indian law and to the frameworks LatentView follows. Legal requirements are shown separately from voluntary frameworks." />
      <SubTabs items={COMPLIANCE_TABS} />
      {!data ? <PageSkeleton tiles={4} /> : <>
        <div className="flex flex-wrap items-center gap-3 text-sm text-ink-3">
          <span>{data.run ? <>Last evaluated {fmtAgo(data.run.finished_at)}{data.run.by ? ` by ${data.run.by}` : ' (scheduled 07:50 and 19:50 IST)'}</> : 'Not evaluated yet'}</span>
          <span className="tabular">{data.totals.fail} failing · {data.totals.pass} passing · {data.totals.not_assessed} not assessed of {data.totals.enabled} policies</span>
          {canManage && <button className="cn-btn cn-btn-primary ml-auto h-9" disabled={busy} onClick={() => run(() => post('/compliance/evaluate'), 'Compliance evaluated')}>
            <PlayCircle size={15} aria-hidden />{busy ? 'Evaluating…' : 'Run evaluation now'}</button>}
        </div>

        <Panel icon={<Scale size={15} />} title="Legal requirements in India" subtitle="Binding on LatentView as a body corporate; DPDP security and breach rules start 13 May 2027">
          <div className="grid gap-4 md:grid-cols-2">{legal.map((f) => (
            <div key={f.key} className="rounded-xl border border-line p-4">
              <div className="flex items-start justify-between gap-2"><div><div className="font-semibold">{f.name}</div><div className="text-[11.5px] text-ink-3">{f.obligation_label} · {f.version}</div></div>
                <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${f.obligation === 'legal' ? 'bg-critical/10 text-critical' : 'bg-warning/10 text-warning'}`}>{f.obligation === 'legal' ? 'Mandatory now' : 'Mandatory from 13 May 2027'}</span></div>
              <div className="mt-3"><ScoreBar score={f.score} coverage={f.coverage} /></div>
              <p className="mt-2 text-xs text-ink-2">{f.note}</p>
              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                <Link className="cn-btn cn-btn-ghost h-8" to={`/compliance/policies?framework=${f.key}&status=FAIL`}>{f.policies_failing ?? 0} failing policies</Link>
                <a className="cn-btn cn-btn-ghost h-8" href={reportUrl(f.key, 'html')} target="_blank" rel="noopener noreferrer"><FileCheck2 size={13} aria-hidden />Audit report</a>
                <a className="cn-btn cn-btn-ghost h-8" href={reportUrl(f.key, 'csv')}><Download size={13} aria-hidden />CSV</a>
              </div>
            </div>))}</div>
        </Panel>

        <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <Panel icon={<ShieldAlert size={15} />} title="Gaps to fix first" subtitle="Failing policies, most severe first">
            {data.top_failing.length === 0 ? <p className="text-sm text-ink-3">{data.run ? 'No failing policy in the latest evaluation.' : 'Run an evaluation to see gaps.'}</p> :
              <ul className="divide-y divide-line">{data.top_failing.map((p) => (
                <li key={p.key}><button className="flex w-full items-start gap-3 py-2.5 text-left hover:bg-surface-2/50" onClick={() => setOpen(p.key)}>
                  <span className={`w-16 shrink-0 text-xs font-semibold ${SEV[p.severity] ?? ''}`}>{p.severity}</span>
                  <span className="min-w-0 flex-1"><span className="block font-medium">{p.title}</span>
                    <span className="block text-[11.5px] text-ink-3">{p.domain_label} · {p.scopes_failing} scope(s) failing{p.legal ? ' · legal requirement' : ''}</span></span>
                  <span className="text-[11px] text-ink-3">{p.key}</span></button></li>))}</ul>}
          </Panel>
          <Panel icon={<Landmark size={15} />} title="By security domain">
            <ul className="space-y-2.5">{data.domains.filter((d) => d.policies).map((d) => { const t = d.pass + d.fail + d.not_assessed || 1; return (
              <li key={d.key} className="text-xs"><div className="flex justify-between"><span>{d.label}</span><span className="tabular text-ink-3">{d.fail} fail · {d.pass} pass</span></div>
                <div className="mt-1 flex h-2 overflow-hidden rounded-full bg-surface-2">
                  <div style={{ width: `${(100 * d.fail) / t}%`, background: 'var(--critical, #b42318)' }} /><div style={{ width: `${(100 * d.pass) / t}%`, background: 'var(--good, #067647)' }} /></div></li>) })}</ul>
            <p className="mt-3 text-[11px] text-ink-3">Grey = not assessed (data not collected yet or attestation needed); never counted as passing.</p>
          </Panel>
        </div>

        <Panel title="Voluntary frameworks and internal policy" subtitle="Certifiable or attestable standards LatentView follows by choice">
          <div className="overflow-x-auto"><table className="w-full text-left text-sm">
            <thead><tr className="text-[11px] uppercase tracking-wide text-ink-3"><th className="py-1.5">Framework</th><th className="w-64">Score</th><th>Failing</th><th className="text-right">Evidence</th></tr></thead>
            <tbody>{voluntary.map((f) => (
              <tr key={f.key} className="border-t border-line"><td className="py-2.5 pr-3"><div className="font-medium">{f.name}</div><div className="text-[11.5px] text-ink-3">{f.obligation_label} · {f.authority}</div></td>
                <td className="pr-3"><ScoreBar score={f.score} coverage={f.coverage} /></td>
                <td><Link className="text-accent hover:underline" to={`/compliance/policies?framework=${f.key}&status=FAIL`}>{f.policies_failing ?? 0} of {f.policies ?? 0}</Link></td>
                <td className="text-right"><a className="text-accent hover:underline" href={reportUrl(f.key, 'html')} target="_blank" rel="noopener noreferrer">Report</a> · <a className="text-accent hover:underline" href={reportUrl(f.key, 'csv')}>CSV</a></td></tr>))}</tbody>
          </table></div>
        </Panel>

        {data.trend.length > 1 && <Panel title="Score trend" subtitle="Last 30 evaluations">
          <ComparisonChart data={data.trend} x="at" series={series} defaultMode="line" fmt={(n) => `${n}%`} xFmt={(v) => v.slice(5, 10)} height={240} /></Panel>}
        <p className="text-[11.5px] text-ink-3">{data.disclaimer}</p>
      </>}
      {open && <PolicyDrawer pkey={open} onClose={() => setOpen(null)} onChanged={() => setBump((b) => b + 1)} />}
    </>
  )
}

/** The library: every policy with its result, filters by framework / domain / result, and the detail drawer. */
export function PolicyLibrary() {
  const [sp, setSp] = useSearchParams()
  const f = { framework: sp.get('framework') ?? '', domain: sp.get('domain') ?? '', status: sp.get('status') ?? '' }
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n, { replace: true }) }
  const [bump, setBump] = useState(0)
  const { data, error, reload } = useApi<{ items: PolicyRow[]; run_at: string | null; frameworks: Record<string, string>; domains: Record<string, string> }>(
    '/compliance/policies', { framework: f.framework || undefined, domain: f.domain || undefined, status: f.status || undefined }, bump)
  const open = sp.get('policy')
  const rows = useMemo(() => (data?.items ?? []).map((p, i) => ({ ...p, id: i + 1 })), [data])
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  const cols: Col<PolicyRow & { id: number }>[] = [
    { key: 'status', label: 'Result', render: (r) => <StatusTag s={r.status} /> },
    { key: 'title', label: 'Policy', render: (r) => <div className="max-w-[28rem]"><div className="font-medium">{r.title}</div><div className="text-[11.5px] text-ink-3">{r.key} · {r.domain_label}{r.kind === 'attestation' ? ' · attestation' : ''}</div></div> },
    { key: 'severity', label: 'Severity', render: (r) => <span className={`text-xs font-semibold ${SEV[r.severity] ?? ''}`}>{r.severity}</span> },
    { key: 'scopes', label: 'Scopes', render: (r) => <span className="tabular text-xs">{r.scopes_failing} fail · {r.scopes_passing} pass · {r.scopes_not_assessed} n/a</span> },
    { key: 'fw', label: 'Frameworks', render: (r) => <span className="text-[11.5px] text-ink-3">{r.frameworks.map((k) => (data?.frameworks[k] ?? k).split(' ')[0]).join(', ')}</span> },
  ]
  return (
    <>
      <PageHeader eyebrow="Governance & Compliance" title="Policy library" description="Each policy is one automated check (or an attestation) mapped to the legal and framework requirements it supports. Open a policy for the affected accounts, evidence and the fix." />
      <SubTabs items={COMPLIANCE_TABS} />
      <FilterPanel onClear={() => setSp(new URLSearchParams(), { replace: true })}>
        <Select label="Framework" value={f.framework} onChange={(v) => set('framework', v)} options={Object.entries(data?.frameworks ?? {}).map(([value, label]) => ({ value, label }))} />
        <Select label="Domain" value={f.domain} onChange={(v) => set('domain', v)} options={Object.entries(data?.domains ?? {}).map(([value, label]) => ({ value, label }))} />
        <Select label="Result" value={f.status} onChange={(v) => set('status', v)} options={[{ value: 'FAIL', label: 'Fail' }, { value: 'PASS', label: 'Pass' }, { value: 'NOT_ASSESSED', label: 'Not assessed' }]} />
      </FilterPanel>
      {!data ? <PageSkeleton tiles={0} /> : <Panel title={`${rows.length} policies`} subtitle={data.run_at ? `Results from ${fmtAgo(data.run_at)}` : 'Not evaluated yet'}>
        <DataGrid label="Compliance policies" cols={cols} rows={rows} onOpen={(r) => set('policy', r.key)} empty="No policy matches these filters." /></Panel>}
      {open && <PolicyDrawer pkey={open} onClose={() => set('policy', '')} onChanged={() => setBump((b) => b + 1)} />}
    </>
  )
}

function PolicyDrawer({ pkey, onClose, onChanged }: { pkey: string; onClose: () => void; onChanged: () => void }) {
  const [bump, setBump] = useState(0)
  const { data } = useApi<Detail>(`/compliance/policies/${pkey}`, undefined, bump)
  const canManage = useCan('governance:manage')
  const { run, busy } = useAction(() => { setBump((b) => b + 1); onChanged() })
  const [att, setAtt] = useState({ status: 'PASS', evidence: '', valid_until: '' })
  const [showPass, setShowPass] = useState(false)
  if (!data) return <Drawer title="Loading…" onClose={onClose}><PageSkeleton tiles={0} /></Drawer>
  const results = data.results.filter((r) => showPass || r.status !== 'PASS')
  return (
    <Drawer title={data.title} subtitle={`${data.key} · ${data.domain_label} · ${data.severity}`} onClose={onClose} width={860}>
      <div className="mb-4 flex flex-wrap items-center gap-2"><StatusTag s={data.status} />
        <span className="text-xs text-ink-3">{data.scopes_failing} failing · {data.scopes_passing} passing · {data.scopes_not_assessed} not assessed{data.run_at ? ` · ${fmtAgo(data.run_at)}` : ''}</span></div>
      <Section title="Why it matters"><p className="text-sm">{data.why}</p></Section>
      <Section title="How to fix"><p className="text-sm">{data.remediation}</p></Section>
      <Section title={`Affected scopes (${data.results.length})`} action={<label className="flex items-center gap-1.5 text-xs text-ink-3"><input type="checkbox" checked={showPass} onChange={(e) => setShowPass(e.target.checked)} />Show passing</label>}>
        {results.length === 0 ? <p className="text-sm text-ink-3">{data.results.length ? 'Every assessed scope passes.' : 'No result yet: run an evaluation.'}</p> :
          <ul className="space-y-2">{results.map((r) => (
            <li key={`${r.provider}:${r.scope}`} className="rounded-lg border border-line p-3">
              <div className="flex flex-wrap items-center gap-2"><StatusTag s={r.status} /><span className="font-medium">{r.scope_name}</span>
                <span className="text-[11px] text-ink-3">{PROVIDER_LABEL[r.provider] ?? (r.provider === 'platform' ? 'LV NEXUS' : r.provider)}{r.basis ? ` · ${r.basis}` : ''}</span></div>
              <p className="mt-1 text-xs text-ink-2">{r.detail}</p>
              {r.evidence.length > 0 && <details className="mt-1.5 text-xs"><summary className="cursor-pointer text-accent">Evidence ({r.evidence.length})</summary>
                <ul className="mt-1 space-y-0.5">{r.evidence.map((e, i) => <li key={i}><b>{e.item}</b>: {e.issue}{e.evidence ? ` (${e.evidence})` : ''}</li>)}</ul></details>}
            </li>))}</ul>}
      </Section>
      <Section title="Requirements this policy supports">
        <ul className="space-y-1.5 text-xs">{data.references.map((x) => <li key={x.framework}><b>{x.framework}</b> <span className="text-ink-3">({x.obligation})</span>: {x.items.join('; ')}</li>)}</ul>
      </Section>
      {canManage && <Section title="Policy settings">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={data.enabled} disabled={busy}
            onChange={(e) => run(() => put(`/compliance/policies/${pkey}`, { enabled: e.target.checked }), e.target.checked ? 'Policy switched on' : 'Policy switched off')} />Policy on</label>
          <label className="text-xs text-ink-3">Severity<select className="cn-input mt-1 block" value={data.severity} disabled={busy}
            onChange={(e) => run(() => put(`/compliance/policies/${pkey}`, { severity: e.target.value }), 'Severity saved')}>
            {['Critical', 'High', 'Medium', 'Low'].map((s) => <option key={s}>{s}</option>)}</select></label>
          {Object.entries(data.params).filter(([, v]) => typeof v === 'number').map(([k, v]) => (
            <label key={k} className="text-xs text-ink-3">{k.replace(/_/g, ' ')}<input type="number" className="cn-input mt-1 block w-28" defaultValue={v as number} disabled={busy}
              onBlur={(e) => Number(e.target.value) !== v && run(() => put(`/compliance/policies/${pkey}`, { params: { [k]: Number(e.target.value) } }), 'Threshold saved')} /></label>))}
        </div>
        <p className="mt-2 text-[11px] text-ink-3">Changes are recorded in the audit trail and apply from the next evaluation.</p>
      </Section>}
      {data.kind === 'attestation' && <Section title="Attestation">
        {data.attestation ? <p className="mb-2 text-sm">Attested <b>{data.attestation.status}</b> by {data.attestation.by} on {data.attestation.at?.slice(0, 10)}, valid until {data.attestation.valid_until}. Evidence: {data.attestation.evidence}</p>
          : <p className="mb-2 text-sm text-ink-3">Not attested: this control cannot be read from a cloud API, so a responsible person records the result with evidence.</p>}
        {canManage && <div className="flex flex-wrap items-end gap-2">
          <label className="text-xs text-ink-3">Result<select className="cn-input mt-1 block" value={att.status} onChange={(e) => setAtt({ ...att, status: e.target.value })}><option>PASS</option><option>FAIL</option></select></label>
          <label className="min-w-[16rem] flex-1 text-xs text-ink-3">Evidence (link or reference)<input className="cn-input mt-1 block w-full" value={att.evidence} onChange={(e) => setAtt({ ...att, evidence: e.target.value })} /></label>
          <label className="text-xs text-ink-3">Valid until<input type="date" className="cn-input mt-1 block" value={att.valid_until} onChange={(e) => setAtt({ ...att, valid_until: e.target.value })} /></label>
          <button className="cn-btn cn-btn-primary h-9" disabled={busy || att.evidence.length < 5 || !att.valid_until}
            onClick={() => run(() => post(`/compliance/policies/${pkey}/attest`, att), 'Attestation recorded')}>Record attestation</button>
        </div>}
      </Section>}
    </Drawer>
  )
}
