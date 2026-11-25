import { Archive, CalendarClock, FileBarChart2, Plus } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Panel, SubTabs } from '../../components/hero'
import { DataGrid, Drawer, download, useAction, type Col } from '../../components/secops'
import { useToast } from '../../components/Toast'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_LABEL, fmtTime } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'

export const REPORT_TABS = [{ to: '/reports/library', label: 'Report library' }, { to: '/reports', label: 'Operational reports' }]
interface Rep { key: string; title: string; permission: string; available: boolean }
interface Sched { id: number; report_key: string; title: string; format: string; frequency: string; day: number | null; hour_utc: number; recipients: string[]; enabled: boolean; owner_email: string; last_run_at: string | null; next_run_at: string | null; last_status: string | null }

export default function ReportLibrary() {
  const toast = useToast()
  const [params] = useSearchParams()
  const [bump, setBump] = useState(0)
  const [f, setF] = useState({ provider: '', date_from: '', date_to: '' })
  const [creating, setCreating] = useState<Rep | null>(null)
  const [s, setS] = useState({ format: 'xlsx', frequency: 'weekly', day: '1', hour_utc: '3', recipients: '' })
  const cat = useApi<{ items: Rep[]; formats: string[] }>('/reports/catalogue')
  const sch = useApi<{ items: Sched[] }>('/reports/schedules', undefined, bump)
  const arc = useApi<{ items: { id: number; report_key: string; filename: string; size: number; generated_for: string | null; at: string }[] }>('/reports/archive', undefined, bump)
  const { run, busy } = useAction(() => { setBump((b) => b + 1); setCreating(null) })
  const archived = params.get('archive')
  useEffect(() => { if (archived) download(`/api/v1/reports/archive/${archived}`).catch((e) => toast({ kind: 'error', title: 'Download failed', text: e.message })) }, [archived, toast])
  if (cat.error) return <ErrorNote message={cat.error.message} onRetry={cat.reload} />
  if (!cat.data) return <PageSkeleton tiles={0} />
  const qs = new URLSearchParams(Object.entries(f).filter(([, v]) => v)).toString()
  const get = (key: string, fmt: string) => download(`/api/v1/reports/run/${key}?format=${fmt}${qs ? `&${qs}` : ''}`).catch((e) => toast({ kind: 'error', title: 'Report failed', text: e.message }))
  const scols: Col<Sched>[] = [
    { key: 't', label: 'Report', render: (x) => x.title }, { key: 'f', label: 'Format', render: (x) => x.format.toUpperCase() },
    { key: 'w', label: 'When (UTC)', render: (x) => `${x.frequency}${x.frequency === 'weekly' ? ` · day ${x.day}` : x.frequency === 'monthly' ? ` · day ${x.day}` : ''} · ${String(x.hour_utc).padStart(2, '0')}:00` },
    { key: 'r', label: 'Recipients', render: (x) => <span className="text-xs">{x.recipients.join(', ')}</span> }, { key: 'n', label: 'Next run', render: (x) => (x.enabled ? fmtTime(x.next_run_at) : 'disabled') },
    { key: 'l', label: 'Last run', render: (x) => (x.last_run_at ? `${fmtTime(x.last_run_at)} · ${x.last_status}` : '—') },
    { key: 'd', label: '', render: (x) => x.enabled && <button className="cn-btn cn-btn-ghost h-7 text-xs" disabled={busy} onClick={(e) => { e.stopPropagation(); run(() => api.delete(`/reports/schedules/${x.id}`), 'Schedule disabled') }}>Disable</button> },
  ]
  return (
    <>
      <PageHeader eyebrow="Reports & Alerts" title="Report library" description="Fifteen standard reports in CSV, Excel and PDF, built from synchronized data at the moment of download. Each file records its filters, generation time and the data's last synchronization." />
      <SubTabs items={REPORT_TABS} />
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-ink-3">Cloud<select className="cn-input mt-1 block" value={f.provider} onChange={(e) => setF({ ...f, provider: e.target.value })}><option value="">All clouds</option>{['aws', 'azure', 'gcp'].map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p]}</option>)}</select></label>
        <label className="text-xs text-ink-3">From<input type="date" className="cn-input mt-1 block" value={f.date_from} onChange={(e) => setF({ ...f, date_from: e.target.value })} /></label>
        <label className="text-xs text-ink-3">To<input type="date" className="cn-input mt-1 block" value={f.date_to} onChange={(e) => setF({ ...f, date_to: e.target.value })} /></label>
      </div>
      <Panel icon={<FileBarChart2 size={15} />} title="Reports">
        <ul className="divide-y divide-line">{cat.data.items.map((r) => (
          <li key={r.key} className="flex flex-wrap items-center justify-between gap-2 py-2">
            <span><span className="text-sm font-medium">{r.title}</span>{!r.available && <span className="ml-2 text-[11px] text-ink-3">needs {r.permission}</span>}</span>
            <span className="flex gap-1">{cat.data!.formats.map((fmt) => <button key={fmt} className="cn-btn cn-btn-ghost h-7 text-xs" disabled={!r.available} onClick={() => get(r.key, fmt)}>{fmt.toUpperCase()}</button>)}
              <button className="cn-btn cn-btn-ghost h-7 text-xs" disabled={!r.available} onClick={() => setCreating(r)}><Plus size={12} aria-hidden />Schedule</button></span>
          </li>))}</ul>
      </Panel>
      <Panel icon={<CalendarClock size={15} />} title="Scheduled reports" subtitle="Generated by the scheduled-reports job, archived, and e-mailed through the configured Gmail channel. A failed delivery is recorded, not reported as sent.">
        <DataGrid label="Report schedules" cols={scols} rows={sch.data?.items ?? []} empty="No scheduled reports." />
      </Panel>
      <Panel icon={<Archive size={15} />} title="Archive">
        <ul className="space-y-1 text-sm">{(arc.data?.items ?? []).map((a) => <li key={a.id} className="flex justify-between gap-2"><button className="text-accent hover:underline" onClick={() => download(`/api/v1/reports/archive/${a.id}`).catch((e) => toast({ kind: 'error', title: 'Download failed', text: e.message }))}>{a.filename}</button>
          <span className="text-xs text-ink-3">{(a.size / 1024).toFixed(0)} KB · {fmtTime(a.at)}</span></li>)}
          {(arc.data?.items.length ?? 0) === 0 && <li className="text-ink-3">No archived reports yet.</li>}</ul>
      </Panel>
      {creating && <Drawer title={`Schedule: ${creating.title}`} onClose={() => setCreating(null)}>
        <form className="grid gap-2" onSubmit={(e) => { e.preventDefault(); run(() => api.post('/reports/schedules', { report_key: creating.key, format: s.format, frequency: s.frequency, day: s.frequency === 'daily' ? null : Number(s.day), hour_utc: Number(s.hour_utc), recipients: s.recipients.split(/[,;\s]+/).filter(Boolean) }), 'Schedule created') }}>
          <div className="grid grid-cols-2 gap-2">
            <select className="cn-input" aria-label="Format" value={s.format} onChange={(e) => setS({ ...s, format: e.target.value })}>{cat.data.formats.map((x) => <option key={x} value={x}>{x.toUpperCase()}</option>)}</select>
            <select className="cn-input" aria-label="Frequency" value={s.frequency} onChange={(e) => setS({ ...s, frequency: e.target.value })}>{['daily', 'weekly', 'monthly'].map((x) => <option key={x}>{x}</option>)}</select>
            {s.frequency !== 'daily' && <input className="cn-input" type="number" min={s.frequency === 'weekly' ? 0 : 1} max={s.frequency === 'weekly' ? 6 : 28} aria-label={s.frequency === 'weekly' ? 'Weekday (0 = Monday)' : 'Day of month'} placeholder={s.frequency === 'weekly' ? 'Weekday 0–6 (Mon=0)' : 'Day 1–28'} value={s.day} onChange={(e) => setS({ ...s, day: e.target.value })} />}
            <input className="cn-input" type="number" min={0} max={23} aria-label="Hour (UTC)" value={s.hour_utc} onChange={(e) => setS({ ...s, hour_utc: e.target.value })} />
          </div>
          <input className="cn-input" required placeholder="Recipients (comma separated e-mail addresses)" aria-label="Recipients" value={s.recipients} onChange={(e) => setS({ ...s, recipients: e.target.value })} />
          <button className="cn-btn cn-btn-primary h-9 w-fit text-sm" disabled={busy}>Create schedule</button>
        </form></Drawer>}
    </>
  )
}
