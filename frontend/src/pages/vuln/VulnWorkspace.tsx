import { Lock, Search } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ComparisonChart, Segmented, type HeroSeries } from '../../components/hero'
import { DataGrid, Pager, Pill, fmtDT, type Col } from '../../components/secops'
import { Metric, SectionCard } from '../../components/shell'
import { ErrorNote, PageSkeleton, PROVIDER_COLOR, PROVIDER_LABEL, fmtAgo, fmtInt } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import FindingPanel from './FindingPanel'

/** One vulnerabilities page across AWS Security Hub, Microsoft Defender / Advisor and Google SCC. Each source shows how
 *  much of the estate it actually read; a refused source is shown as such, never as zero findings. */
interface Source { provider: string; source: string; label: string; open: number; critical: number; high: number; medium: number; low: number
  partitions: number; ok: number; access_denied: number; not_enabled: number; errors: number; last_success_at: string | null; status: string
  problems: { scope: string; region: string; state: string; message: string | null }[] }
interface Overview { kpis: Record<string, number>; by_provider: Record<string, Record<string, number>>; trend: { date: string; detected: number; resolved: number; open_total: number }[] }
interface Row { id: number; severity: string; title: string; resource_name: string | null; resource_id: string | null; provider: string; scope: string; region: string | null
  source: string; internal_status: string; native_state: string; owner: string | null; sla_due_at: string | null; overdue: boolean; last_observed_at: string | null }

const SEVS = ['Critical', 'High', 'Medium', 'Low'] as const
const SEV_COLOR: Record<string, string> = { Critical: 'var(--critical)', High: 'var(--serious)', Medium: 'var(--warning)', Low: 'var(--ink-3)' }
const STATUS_TEXT: Record<string, [string, string]> = { ok: ['All read', 'var(--good)'], partial: ['Partly read', 'var(--warning)'], failed: ['Not readable', 'var(--critical)'], never: ['Not synced yet', 'var(--ink-3)'] }

export default function VulnWorkspace() {
  const [provider, setProvider] = useState<'all' | 'azure' | 'aws' | 'gcp'>('all')
  const [severity, setSeverity] = useState(''), [source, setSource] = useState(''), [q, setQ] = useState(''), [page, setPage] = useState(1)
  const [open, setOpen] = useState<number | null>(null), [bump, setBump] = useState(0)
  const p = provider === 'all' ? undefined : provider
  const ov = useApi<Overview>('/security/overview', { provider: p }, bump)
  const src = useApi<{ items: Source[] }>('/security/sources', undefined, bump)
  const list = useApi<{ total: number; items: Row[] }>('/security/findings', { provider: p, severity: severity || undefined, source: source || undefined, q: q || undefined,
    status: 'OPEN,UNDER_REVIEW,REOPENED', sort: 'severity', order: 'asc', page, page_size: 25 }, bump)
  if (ov.error && !ov.data) return <ErrorNote message={ov.error.message} onRetry={ov.reload} />
  if (!ov.data || !src.data) return <PageSkeleton />
  const k = ov.data.kpis
  const sources = src.data.items.filter((s) => !p || s.provider === p)
  const blocked = sources.filter((s) => s.status === 'failed' || s.access_denied > 0)
  const series: HeroSeries[] = [{ key: 'detected', label: 'Detected', color: 'var(--serious)' }, { key: 'resolved', label: 'Resolved', color: 'var(--good)' }]
  const cols: Col<Row>[] = [
    { key: 'severity', label: 'Severity', render: (r) => <Pill value={r.severity} /> },
    { key: 'title', label: 'Finding', render: (r) => <div className="max-w-[30rem]"><div className="font-medium text-accent">{r.title}</div>
      <div className="truncate text-[11px] text-ink-3" title={r.resource_id ?? ''}>{r.resource_name || r.resource_id || '—'}</div></div> },
    { key: 'provider', label: 'Where', render: (r) => <div className="text-xs"><b>{PROVIDER_LABEL[r.provider]}</b> · {r.scope}<div className="text-ink-3">{r.region ?? 'global'}</div></div> },
    { key: 'source', label: 'Source', render: (r) => <span className="text-xs">{sources.find((s) => s.source === r.source)?.label ?? r.source}</span> },
    { key: 'owner', label: 'Owner', render: (r) => <span className="text-xs">{r.owner ?? <span className="text-ink-3">unassigned</span>}</span> },
    { key: 'sla', label: 'Due', render: (r) => <span className={`text-xs ${r.overdue ? 'font-semibold' : ''}`} style={{ color: r.overdue ? 'var(--critical)' : undefined }}>{r.overdue ? 'Overdue · ' : ''}{fmtDT(r.sla_due_at)}</span> },
  ]
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><p className="text-[11px] font-semibold uppercase tracking-[.14em] text-accent">Security Center</p>
          <h1 className="mt-1 text-[28px] font-semibold tracking-tight">Open security findings, all clouds</h1>
          <p className="mt-1 text-sm text-ink-3">AWS Security Hub, Microsoft Defender for Cloud / Advisor and Google Security Command Center, synchronised daily and on demand.</p></div>
        <Segmented label="Cloud" value={provider} onChange={(v) => { setProvider(v); setPage(1) }}
          options={[{ value: 'all', label: 'All clouds' }, ...(['azure', 'aws', 'gcp'] as const).map((x) => ({ value: x, label: PROVIDER_LABEL[x] }))]} />
      </div>

      {blocked.length > 0 && <div className="cn-card border-l-4 p-4 text-sm" style={{ borderLeftColor: 'var(--serious)' }}>
        <div className="flex items-center gap-2 font-semibold"><Lock size={14} aria-hidden />Some findings could not be read — counts below are incomplete for:</div>
        <ul className="mt-1 list-disc pl-6 text-[12.5px] text-ink-2">{blocked.map((s) => <li key={s.provider + s.source}>{s.label}: {s.access_denied ? `${s.access_denied} scope/region(s) refused access` : 'source not readable'}
          {s.problems[0]?.message ? ` — ${s.problems[0].message.slice(0, 140)}` : ''}</li>)}</ul></div>}

      <div className="cn-card grid grid-cols-2 gap-5 p-5 md:grid-cols-5">
        {SEVS.map((s) => <button key={s} type="button" onClick={() => { setSeverity(severity === s ? '' : s); setPage(1) }} className={`rounded-xl p-1 text-left ${severity === s ? 'ring-2 ring-accent/40' : ''}`}>
          <Metric label={s} value={fmtInt(k[s.toLowerCase()] ?? 0)} tone={k[s.toLowerCase()] ? SEV_COLOR[s] : undefined} note={severity === s ? 'filtering list' : 'open'} /></button>)}
        <Metric label="Overdue" value={fmtInt(k.overdue ?? 0)} note="past remediation SLA" tone={k.overdue ? 'var(--critical)' : undefined} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <SectionCard title="Sources and coverage" subtitle="Open findings per source, and how much of the estate each one could read">
          {sources.length === 0 ? <p className="py-6 text-center text-sm text-ink-3">No findings source has been synchronised yet.</p> :
            <ul className="divide-y divide-line">{sources.map((s) => { const [t, c] = STATUS_TEXT[s.status] ?? STATUS_TEXT.never; return (
              <li key={s.provider + s.source} className="flex items-center gap-3 py-2.5">
                <span className="h-8 w-1 rounded-full" style={{ background: PROVIDER_COLOR[s.provider] }} aria-hidden />
                <button type="button" className="min-w-0 flex-1 text-left" onClick={() => { setSource(source === s.source ? '' : s.source); setPage(1) }}>
                  <div className={`truncate text-sm font-medium ${source === s.source ? 'text-accent' : ''}`}>{s.label}</div>
                  <div className="text-[11.5px] text-ink-3"><span style={{ color: c }}>{t}</span> · {s.ok}/{s.partitions} scopes{s.not_enabled ? ` · ${s.not_enabled} not enabled` : ''} · {s.last_success_at ? `synced ${fmtAgo(s.last_success_at)}` : 'never synced'}</div>
                </button>
                <span className="tabular text-sm"><b style={{ color: s.critical ? 'var(--critical)' : undefined }}>{s.critical}</b> / <b>{s.high}</b> <span className="text-ink-3">/ {fmtInt(s.open)}</span></span>
              </li>) })}</ul>}
          <p className="mt-2 text-[11px] text-ink-3">Numbers: critical / high / all open. Click a source to filter the list.</p>
        </SectionCard>
        <SectionCard title="Detected vs resolved, last 30 days">
          <ComparisonChart data={ov.data.trend as unknown as Record<string, string | number>[]} x="date" series={series} xFmt={(v) => String(v).slice(5)} height={230} empty="No findings history yet." />
        </SectionCard>
      </div>

      <SectionCard title={`Open findings${list.data ? ` (${fmtInt(list.data.total)})` : ''}`} to="/vulnerabilities/findings" toLabel="Full register and exports">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <label className="relative"><Search size={13} className="absolute left-2.5 top-2.5 text-ink-3" aria-hidden />
            <input className="cn-input h-8 w-72 pl-7 text-xs" placeholder="Title, resource, control or account" value={q} onChange={(e) => { setQ(e.target.value); setPage(1) }} aria-label="Search findings" /></label>
          {(severity || source) && <button type="button" className="text-xs text-accent hover:underline" onClick={() => { setSeverity(''); setSource('') }}>Clear filters ({[severity, sources.find((s) => s.source === source)?.label].filter(Boolean).join(', ')})</button>}
        </div>
        {list.error ? <ErrorNote message={list.error.message} /> : !list.data ? <PageSkeleton tiles={0} /> : <>
          <DataGrid label="Open findings" cols={cols} rows={list.data.items} onOpen={(r) => setOpen(r.id)} empty="No open findings match. If a source above is not readable, findings there are unknown, not zero." />
          <Pager page={page} pageSize={25} total={list.data.total} onPage={setPage} /></>}
      </SectionCard>
      <p className="text-[11.5px] text-ink-3">Remediation happens in the cloud provider's console under your change process. LV NEXUS tracks status, owners and SLA; it never changes cloud resources. <Link className="text-accent hover:underline" to="/vulnerabilities/exceptions">Exceptions</Link></p>
      {open !== null && <FindingPanel id={open} onClose={() => setOpen(null)} onChanged={() => setBump((b) => b + 1)} />}
    </div>
  )
}
