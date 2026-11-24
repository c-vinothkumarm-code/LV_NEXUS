import { Activity, CheckCircle2, Eye, Gauge, PieChart as PieIcon, ShieldAlert, ShieldCheck, TrendingUp } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ArcDonut, ComparisonChart, HeroLayout, KpiCard, Panel, SubTabs } from '../../components/hero'
import { DataGrid, DownloadButton, FilterPanel, Pager, Pill, Select, TextFilter, fmtDT, type Col } from '../../components/secops'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_LABEL, fmtInt } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { useFilters } from '../../hooks/useFilters'
import { AUDIT_TABS } from '../vuln/tabs'
import EventPanel from './EventPanel'
import { ScopeName } from '../../hooks/useScopeNames'

/* eslint-disable @typescript-eslint/no-explicit-any */
const CLS_COLOR: Record<string, string> = { NORMAL: 'var(--neutral-mark)', AUTHORIZED: 'var(--good)', REVIEW_REQUIRED: 'var(--compare-current)', SUSPICIOUS: 'var(--serious)',
  RULE_VIOLATION: 'var(--critical)', NOT_EVALUATED: 'var(--compare-previous)' }
const KEYS = ['provider', 'scope', 'region', 'classification', 'status', 'category', 'actor', 'ip', 'operation', 'q', 'date_from', 'date_to', 'investigator'] as const

export function AuditOverview() {
  const { refreshKey } = useFilters()
  const [days, setDays] = useState('30')
  const ov = useApi<any>('/audit/overview', { days }, refreshKey)
  if (ov.error) return <ErrorNote message={ov.error.message} onRetry={ov.reload} />
  if (!ov.data) return <PageSkeleton tiles={6} />
  const d = ov.data, c = d.classification, s = d.status
  const open = (s.DETECTED ?? 0) + (s.REVIEWING ?? 0) + (s.INVESTIGATING ?? 0) + (s.ESCALATED ?? 0) + (s.REOPENED ?? 0)
  return (
    <>
      <PageHeader eyebrow="Live Cloud Activity" title="Audit overview" description="Every CloudTrail, Azure Activity Log and GCP Audit Log event is evaluated against the detection rules. Only rule violations, suspicious patterns and review-required matches enter the investigation workflow; normal and authorized activity is retained without tickets."
        action={<Select label="Window" value={days} onChange={(v) => setDays(v || '30')} options={[{ value: '7', label: '7 days' }, { value: '30', label: '30 days' }, { value: '90', label: '90 days' }]} all="30 days" />} />
      <SubTabs items={AUDIT_TABS} />
      <HeroLayout
        kpis={<>
          <KpiCard icon={<Activity size={15} />} label="Audit events" num={d.total} note={`${fmtInt(c.NOT_EVALUATED ?? 0)} awaiting evaluation`} to="/audit/activities" />
          <KpiCard icon={<CheckCircle2 size={15} />} label="Normal" num={c.NORMAL ?? 0} note="retained, no ticket" to="/audit/activities?classification=NORMAL" />
          <KpiCard icon={<ShieldCheck size={15} />} label="Authorized" num={(c.AUTHORIZED ?? 0) + (s.AUTHORIZED ?? 0)} note="rule-covered or analyst-approved" to="/audit/authorized" />
          <KpiCard icon={<ShieldAlert size={15} />} label="Violations" num={c.RULE_VIOLATION ?? 0} note={`${fmtInt(c.SUSPICIOUS ?? 0)} suspicious`} to="/audit/suspicious" />
          <KpiCard icon={<Eye size={15} />} label="Under investigation" num={open} note={`${fmtInt(c.REVIEW_REQUIRED ?? 0)} review-required matches`} to="/audit/queue" />
          <KpiCard icon={<Gauge size={15} />} label="Closed" num={(s.CLOSED ?? 0) + (s.NO_ACTION_REQUIRED ?? 0)} note={`${fmtInt(d.cases.PROPOSED ?? 0)} correlation proposals`} to="/audit/closed" />
        </>}
        main={<Panel icon={<TrendingUp size={15} />} title="Audit activity" subtitle="Events per day by classification" bodyClass="px-5 pb-4 pt-3 xl:pr-16">
          <ComparisonChart stacked data={d.trend} x="date" xFmt={(v) => v.slice(5)}
            series={['RULE_VIOLATION', 'SUSPICIOUS', 'REVIEW_REQUIRED', 'AUTHORIZED', 'NORMAL', 'NOT_EVALUATED'].map((k) => ({ key: k, label: k.replace('_', ' ').toLowerCase(), color: CLS_COLOR[k] }))} />
        </Panel>}
        trend={<Panel float icon={<ShieldAlert size={15} />} title="Top triggered rules" subtitle="Matches in the window">
          <ul className="space-y-2 text-xs">{(d.top_rules as [string, number][]).map(([r, n]) => <li key={r} className="flex justify-between gap-2"><span className="truncate">{r}</span><b className="tabular">{n}</b></li>)}
            {!d.top_rules.length && <li className="text-ink-3">No rule has matched.</li>}</ul>
        </Panel>}
        donut={<Panel float icon={<PieIcon size={15} />} title="Classification" subtitle="Share of events">
          <ArcDonut centre={fmtInt(d.total)} centreNote="events" items={Object.entries(c).map(([k, v]) => ({ key: k, label: k.replace('_', ' ').toLowerCase(), value: Number(v), color: CLS_COLOR[k] ?? 'var(--neutral-mark)' }))} />
        </Panel>}
        bottom={(['azure', 'gcp', 'aws'] as const).map((p) => (
          <div key={p} className="cn-card cn-lift p-5"><div className="text-sm font-semibold">{PROVIDER_LABEL[p]} {p === 'aws' ? 'CloudTrail' : p === 'azure' ? 'Activity Logs' : 'Audit Logs'}</div>
            <div className="mt-2 text-[26px] font-semibold">{fmtInt(d.by_provider[p] ?? 0)}</div><div className="text-xs text-ink-3">events in {d.window_days} days</div>
            <Link className="cn-btn cn-btn-dark mt-4 h-10 w-full justify-center" to={`/audit/${p}`}>View activities</Link></div>
        ))}
      />
      <Panel icon={<PieIcon size={15} />} title="Activity categories">
        <div className="grid gap-x-8 gap-y-1.5 text-sm sm:grid-cols-2 xl:grid-cols-3">{(d.by_category as [string, number][]).map(([k, n]) => (
          <Link key={k} to={`/audit/activities?category=${encodeURIComponent(k)}`} className="flex justify-between hover:text-accent"><span>{k}</span><b className="tabular">{n}</b></Link>))}</div>
      </Panel>
    </>
  )
}

export default function Activities({ title, description, provider, view, report = 'audit-activity' }: { title: string; description: string; provider?: string; view?: string; report?: string }) {
  const [params, setParams] = useSearchParams()
  const f = useMemo(() => Object.fromEntries(KEYS.map((k) => [k, params.get(k) ?? ''])), [params]) as Record<string, string>
  if (provider) f.provider = provider
  const [page, setPage] = useState(1)
  const [bump, setBump] = useState(0)
  const [sort, setSort] = useState<{ key: string; order: 'asc' | 'desc' }>({ key: 'time', order: 'desc' })
  const [open, setOpen] = useState<number | null>(null)
  const data = useApi<{ total: number; items: any[] }>('/audit/events', { ...f, view, sort: sort.key, order: sort.order, page, page_size: 50 }, bump)
  const reload = useCallback(() => setBump((b) => b + 1), [])
  const set = (k: string, v: string) => { const n = new URLSearchParams(params); if (v) n.set(k, v); else n.delete(k); setParams(n, { replace: true }); setPage(1) }
  const cols: Col<any>[] = [
    { key: 'time', label: 'Time (UTC)', sortable: true, render: (r) => <span className="whitespace-nowrap text-xs">{fmtDT(r.time)}</span> },
    { key: 'provider', label: 'Cloud / scope', sortable: true, render: (r) => <span className="text-xs"><b>{PROVIDER_LABEL[r.provider]}</b> · <ScopeName provider={r.provider} id={r.scope} name={r.scope_name} /><div className="text-ink-3">{r.region ?? ''}</div></span> },
    { key: 'operation', label: 'Operation', sortable: true, render: (r) => <div className="max-w-[20rem]"><div className="truncate font-medium text-accent" title={r.operation}>{r.operation}</div><div className="text-[11px] text-ink-3">{r.category ?? ''}</div></div> },
    { key: 'actor', label: 'Actor / IP', sortable: true, render: (r) => <div className="max-w-[16rem] text-xs"><div className="truncate" title={r.actor}>{r.actor ?? '—'}</div><div className="text-ink-3">{r.source_ip ?? ''}</div></div> },
    { key: 'resource', label: 'Resource', render: (r) => <span className="block max-w-[14rem] truncate text-xs" title={r.resource_id}>{r.resource_id ?? '—'}</span> },
    { key: 'result', label: 'Result', render: (r) => <span className="text-xs">{r.result}</span> },
    { key: 'classification', label: 'Classification', render: (r) => <div className="space-y-1"><Pill value={r.classification} />{r.rules.length > 0 && <div className="text-[10.5px] text-ink-3">{r.rules.join(', ')}</div>}</div> },
    { key: 'severity', label: 'Investigation', sortable: true, render: (r) => r.status ? <div className="space-y-1"><Pill value={r.status} />{r.severity && <Pill value={r.severity} />}</div> : <span className="text-xs text-ink-3">—</span> },
  ]
  return (
    <>
      <PageHeader eyebrow="Live Cloud Activity" title={title} description={description}
        action={<div className="flex gap-2"><DownloadButton url={`/api/v1/security/reports/${report}?format=csv`}>CSV</DownloadButton><DownloadButton url={`/api/v1/security/reports/${report}?format=xlsx`}>Excel</DownloadButton><DownloadButton url={`/api/v1/security/reports/${report}?format=pdf`}>PDF</DownloadButton></div>} />
      <SubTabs items={AUDIT_TABS} />
      <FilterPanel onClear={() => setParams(new URLSearchParams(), { replace: true })}>
        <TextFilter label="Search" value={f.q} onChange={(v) => set('q', v)} placeholder="Operation, actor, resource, IP, event ID" />
        {!provider && <Select label="Cloud" value={f.provider} onChange={(v) => set('provider', v)} options={['aws', 'azure', 'gcp'].map((p) => ({ value: p, label: PROVIDER_LABEL[p] }))} />}
        <TextFilter label="Account / subscription / project" value={f.scope} onChange={(v) => set('scope', v)} />
        <TextFilter label="Region" value={f.region} onChange={(v) => set('region', v)} />
        {!view && <Select label="Classification" value={f.classification} onChange={(v) => set('classification', v)} options={['NORMAL', 'AUTHORIZED', 'REVIEW_REQUIRED', 'SUSPICIOUS', 'RULE_VIOLATION']} />}
        <Select label="Investigation status" value={f.status} onChange={(v) => set('status', v)} options={['DETECTED', 'REVIEWING', 'INVESTIGATING', 'ESCALATED', 'AUTHORIZED', 'NO_ACTION_REQUIRED', 'CLOSED', 'REOPENED']} />
        <TextFilter label="Category" value={f.category} onChange={(v) => set('category', v)} />
        <TextFilter label="Actor" value={f.actor} onChange={(v) => set('actor', v)} />
        <TextFilter label="Source IP" value={f.ip} onChange={(v) => set('ip', v)} />
        <TextFilter label="Investigator" value={f.investigator} onChange={(v) => set('investigator', v)} />
        <label className="flex flex-col gap-1 text-[11px] text-ink-3">Dates<span className="flex gap-1">
          <input type="date" className="cn-input text-[12.5px] text-ink" value={f.date_from} onChange={(e) => set('date_from', e.target.value)} aria-label="From" />
          <input type="date" className="cn-input text-[12.5px] text-ink" value={f.date_to} onChange={(e) => set('date_to', e.target.value)} aria-label="To" /></span></label>
      </FilterPanel>
      <div className="cn-card p-4">
        {data.error ? <ErrorNote message={data.error.message} onRetry={data.reload} /> : !data.data ? <PageSkeleton tiles={0} /> : (
          <><DataGrid label="Audit activities" cols={cols} rows={data.data.items} sort={sort} onOpen={(r) => setOpen(r.id)}
            onSort={(k) => setSort((s) => ({ key: k, order: s.key === k && s.order === 'desc' ? 'asc' : 'desc' }))} empty="No activities match these filters." />
            <Pager page={page} pageSize={50} total={data.data.total} onPage={setPage} /></>
        )}
      </div>
      {open && <EventPanel id={open} onClose={() => setOpen(null)} onChanged={reload} onOpenEvent={setOpen} />}
    </>
  )
}
