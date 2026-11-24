/** Security-operations UI kit: status pills, data grid with sorting/selection/paging, side panel, filters, actions, downloads. */
import { ChevronDown, ChevronUp, Download, X } from 'lucide-react'
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useToast } from './Toast'
import { api, ApiError } from '../services/api'

/* ---- status colours (spec): Critical red, High orange, Medium yellow, Low blue; Open red, Under review blue, Exception amber,
        Resolved / Authorized green, Investigating orange, Escalated red, Closed neutral. Text stays ink; colour is the dot. ---- */
const TONE: Record<string, string> = {
  Critical: 'var(--critical)', High: 'var(--serious)', Medium: 'var(--warning)', Low: 'var(--low)', Informational: 'var(--unknown)',
  OPEN: 'var(--critical)', UNDER_REVIEW: 'var(--low)', EXCEPTION: 'var(--warning)', RESOLVED: 'var(--good)', REOPENED: 'var(--critical)', FALSE_POSITIVE: 'var(--unknown)',
  AUTHORIZED: 'var(--good)', NORMAL: 'var(--unknown)', DETECTED: 'var(--critical)', REVIEWING: 'var(--low)', INVESTIGATING: 'var(--serious)', ESCALATED: 'var(--critical)',
  NO_ACTION_REQUIRED: 'var(--unknown)', CLOSED: 'var(--unknown)', RULE_VIOLATION: 'var(--critical)', SUSPICIOUS: 'var(--serious)', REVIEW_REQUIRED: 'var(--low)',
  NOT_EVALUATED: 'var(--unknown)', PROPOSED: '#8a63d8', DISMISSED: 'var(--unknown)',
  PENDING_APPROVAL: 'var(--low)', ACTIVE: 'var(--warning)', REJECTED: 'var(--unknown)', EXPIRED: 'var(--critical)',
  COMPLETED: 'var(--good)', PARTIALLY_COMPLETED: 'var(--warning)', FAILED: 'var(--critical)', RUNNING: 'var(--low)', RETRYING: 'var(--low)', SCHEDULED: 'var(--unknown)',
  OK: 'var(--good)', PARTIALLY_CONFIGURED: 'var(--warning)', ACCESS_DENIED: 'var(--critical)', NOT_ENABLED: 'var(--warning)', ERROR: 'var(--critical)', NOT_CONFIGURED: 'var(--unknown)',
  NOT_YET_SYNCED: 'var(--unknown)', PENDING: 'var(--low)', APPROVED: 'var(--good)', MORE_INFO: 'var(--warning)', WITHDRAWN: 'var(--unknown)',
}
export const label = (s: string | null | undefined) => (s ?? '—').replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase())

export function Pill({ value, text }: { value: string | null | undefined; text?: string }) {
  if (!value) return <span className="text-xs text-ink-3">—</span>
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line bg-surface px-2 py-0.5 text-[11.5px] font-medium text-ink">
      <span className="h-2 w-2 rounded-full" style={{ background: TONE[value] ?? 'var(--unknown)' }} aria-hidden />{text ?? label(value)}
    </span>
  )
}

export const fmtDT = (v: string | null | undefined) => (v ? new Date(v).toLocaleString('en-IN', { day: '2-digit', month: 'short', year: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '—')

/* ---- actions ---- */
export function useAction(onDone?: () => void) {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const run = useCallback(async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    try { await fn(); toast({ kind: 'success', title: ok }); onDone?.(); return true }
    catch (e) { toast({ kind: 'error', title: 'Not saved', text: e instanceof ApiError || e instanceof Error ? e.message : 'Unknown error' }); return false }
    finally { setBusy(false) }
  }, [toast, onDone])
  return { run, busy }
}

/** Downloads a server-generated file with the session cookie (CSV / Excel / PDF / JSON / evidence). */
export async function download(url: string) {
  const res = await fetch(url, { credentials: 'include' })
  if (!res.ok) throw new ApiError(res.status, (await res.json().catch(() => ({ detail: res.statusText }))).detail ?? 'Download failed')
  const name = /filename="?([^"]+)"?/.exec(res.headers.get('content-disposition') ?? '')?.[1] ?? 'download'
  const href = URL.createObjectURL(await res.blob())
  Object.assign(document.createElement('a'), { href, download: name }).click()
  URL.revokeObjectURL(href)
}

export function DownloadButton({ url, children = 'Export' }: { url: string; children?: ReactNode }) {
  const toast = useToast()
  return <button className="cn-btn cn-btn-ghost h-8 text-xs" onClick={() => download(url).catch((e) => toast({ kind: 'error', title: 'Export failed', text: e.message }))}><Download size={13} aria-hidden />{children}</button>
}

/* ---- side panel ---- */
export function Drawer({ title, subtitle, onClose, children, width = 760 }: { title: ReactNode; subtitle?: ReactNode; onClose: () => void; children: ReactNode; width?: number }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null
    ref.current?.querySelector<HTMLElement>('button')?.focus()
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('keydown', onKey); opener?.focus() }
  }, [onClose])
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/35 backdrop-blur-[1px]" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-label={typeof title === 'string' ? title : 'Details'} className="cn-toast flex h-full w-full flex-col bg-surface shadow-2xl" style={{ maxWidth: width, background: 'var(--surface-1)' }}>
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0"><h2 className="text-[16px] font-semibold leading-snug">{title}</h2>{subtitle && <div className="mt-1 text-xs text-ink-3">{subtitle}</div>}</div>
          <button className="cn-btn cn-btn-ghost h-8 px-2" onClick={onClose} aria-label="Close panel"><X size={15} /></button>
        </header>
        <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </div>
  )
}

export function Section({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="mb-5">
      <div className="mb-2 flex items-center justify-between"><h3 className="text-[12px] font-semibold uppercase tracking-wide text-ink-3">{title}</h3>{action}</div>
      {children}
    </section>
  )
}

export function KV({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
      {items.map(([k, v]) => <div key={k} className="min-w-0"><dt className="text-[11px] text-ink-3">{k}</dt><dd className="break-words text-ink">{v ?? '—'}</dd></div>)}
    </dl>
  )
}

/** Vertical timeline used for status history, investigation history and event sequences. */
export function Timeline({ items }: { items: { at: string; title: ReactNode; body?: ReactNode; tone?: string }[] }) {
  if (!items.length) return <div className="text-xs text-ink-3">No entries yet.</div>
  return (
    <ol className="relative ml-2 border-l border-line pl-4">
      {items.map((it, i) => (
        <li key={i} className="mb-3 last:mb-0">
          <span className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full border-2 border-surface" style={{ background: TONE[it.tone ?? ''] ?? 'var(--accent)' }} aria-hidden />
          <div className="text-[11px] text-ink-3">{fmtDT(it.at)}</div>
          <div className="text-sm font-medium">{it.title}</div>
          {it.body && <div className="text-xs text-ink-2">{it.body}</div>}
        </li>
      ))}
    </ol>
  )
}

/* ---- data grid ---- */
export interface Col<T> { key: string; label: string; sortable?: boolean; render: (r: T) => ReactNode; className?: string }

export function DataGrid<T extends { id: number }>({ cols, rows, sort, onSort, selected, onSelect, onOpen, empty = 'Nothing matches these filters.', label: aria }: {
  cols: Col<T>[]; rows: T[]; sort?: { key: string; order: 'asc' | 'desc' }; onSort?: (key: string) => void
  selected?: Set<number>; onSelect?: (s: Set<number>) => void; onOpen?: (r: T) => void; empty?: string; label: string
}) {
  if (!rows.length) return <div className="rounded-2xl border border-dashed border-line px-4 py-10 text-center text-sm text-ink-3">{empty}</div>
  const all = selected && rows.every((r) => selected.has(r.id))
  return (
    <div className="overflow-auto rounded-xl border border-line" tabIndex={0} role="region" aria-label={aria}>
      <table className="cn-table w-full text-left text-sm">
        <thead>
          <tr className="border-b border-line text-[11px] uppercase tracking-wide text-ink-3">
            {onSelect && selected && (
              <th className="w-8 px-2.5 py-2"><input type="checkbox" aria-label="Select all on this page" checked={!!all}
                onChange={() => onSelect(new Set(all ? [] : rows.map((r) => r.id)))} /></th>
            )}
            {cols.map((c) => (
              <th key={c.key} scope="col" className="whitespace-nowrap px-2.5 py-2 font-semibold" aria-sort={sort?.key === c.key ? (sort.order === 'asc' ? 'ascending' : 'descending') : undefined}>
                {c.sortable && onSort ? (
                  <button className="inline-flex items-center gap-1 uppercase hover:text-ink" onClick={() => onSort(c.key)}>
                    {c.label}{sort?.key === c.key && (sort.order === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
                  </button>
                ) : c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className={`border-b border-line/70 last:border-0 ${onOpen ? 'cursor-pointer' : ''}`} onClick={(e) => {
              if (onOpen && !(e.target as HTMLElement).closest('input,button,a')) onOpen(r)
            }}>
              {onSelect && selected && (
                <td className="px-2.5 py-2"><input type="checkbox" aria-label={`Select row ${r.id}`} checked={selected.has(r.id)}
                  onChange={() => { const n = new Set(selected); if (n.has(r.id)) n.delete(r.id); else n.add(r.id); onSelect(n) }} /></td>
              )}
              {cols.map((c) => <td key={c.key} className={`px-2.5 py-2 align-top ${c.className ?? ''}`}>{c.render(r)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function Pager({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  return (
    <div className="mt-3 flex items-center justify-between text-xs text-ink-3">
      <span>{total.toLocaleString('en-IN')} result{total === 1 ? '' : 's'} · page {page} of {pages}</span>
      <div className="flex gap-2">
        <button className="cn-btn cn-btn-ghost h-7 text-xs" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
        <button className="cn-btn cn-btn-ghost h-7 text-xs" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </div>
    </div>
  )
}

export function Select({ label: l, value, onChange, options, all = 'All' }: { label: string; value: string; onChange: (v: string) => void; options: (string | { value: string; label?: string; count?: number })[]; all?: string }) {
  return (
    <label className="flex flex-col gap-1 text-[11px] text-ink-3">
      {l}
      <select className="cn-input min-w-[9rem] text-[12.5px] text-ink" value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">{all}</option>
        {options.map((o) => typeof o === 'string' ? <option key={o} value={o}>{label(o)}</option>
          : <option key={o.value} value={o.value}>{o.label ?? o.value}{o.count !== undefined ? ` (${o.count})` : ''}</option>)}
      </select>
    </label>
  )
}

export function TextFilter({ label: l, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  const [v, setV] = useState(value)
  useEffect(() => setV(value), [value])
  useEffect(() => { const t = setTimeout(() => v !== value && onChange(v), 350); return () => clearTimeout(t) }, [v, value, onChange])
  return <label className="flex flex-col gap-1 text-[11px] text-ink-3">{l}<input className="cn-input w-48 text-[12.5px] text-ink" value={v} placeholder={placeholder} onChange={(e) => setV(e.target.value)} /></label>
}

export function FilterPanel({ children, onClear }: { children: ReactNode; onClear?: () => void }) {
  return (
    <div className="cn-card flex flex-wrap items-end gap-3 px-4 py-3" role="search" aria-label="Filters">
      {children}
      {onClear && <button className="ml-auto text-xs font-medium text-accent hover:underline" onClick={onClear}>Clear filters</button>}
    </div>
  )
}

/** Confirmation with an optional required reason, used for consequential and bulk actions. */
export function Confirm({ title, body, needReason, reasonLabel = 'Reason', extra, confirm = 'Confirm', onCancel, onConfirm }: {
  title: string; body?: ReactNode; needReason?: boolean; reasonLabel?: string; extra?: ReactNode; confirm?: string; onCancel: () => void; onConfirm: (reason: string) => void
}) {
  const [reason, setReason] = useState('')
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/45 p-4" role="dialog" aria-modal="true" aria-label={title}>
      <div className="cn-card w-full max-w-lg p-5" style={{ boxShadow: 'var(--shadow-2)' }}>
        <h2 className="text-base font-semibold">{title}</h2>
        {body && <div className="mt-1 text-sm text-ink-2">{body}</div>}
        {extra}
        {needReason !== undefined && (
          <label className="mt-3 block text-xs text-ink-3">{reasonLabel}{needReason ? ' (required)' : ' (optional)'}
            <textarea className="cn-input mt-1 h-24 w-full rounded-xl py-2 text-sm text-ink" style={{ borderRadius: 12 }} value={reason} onChange={(e) => setReason(e.target.value)} autoFocus />
          </label>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button className="cn-btn cn-btn-ghost" onClick={onCancel}>Cancel</button>
          <button className="cn-btn cn-btn-primary" disabled={!!needReason && !reason.trim()} onClick={() => onConfirm(reason)}>{confirm}</button>
        </div>
      </div>
    </div>
  )
}

export const post = <T,>(path: string, body?: unknown) => api.post<T>(path, body)
export const put = <T,>(path: string, body?: unknown) => api.put<T>(path, body)

export function fileToBase64(file: File): Promise<string> {
  return new Promise((res, rej) => {
    const r = new FileReader()
    r.onload = () => res(String(r.result).split(',')[1] ?? '')
    r.onerror = () => rej(r.error)
    r.readAsDataURL(file)
  })
}
