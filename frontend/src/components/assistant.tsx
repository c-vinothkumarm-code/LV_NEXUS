import { ArrowUpRight, Bot, ChevronDown, ChevronRight, Copy, Database, Loader2, RotateCcw, Send, Sparkles, X } from 'lucide-react'
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useCan } from '../auth/AuthContext'
import { ApiError } from '../services/api'
import { post } from './secops'
import { fmtAgo } from './ui'

/** LV NEXUS assistant: a chat panel available on every page. Answers are built from the platform's own data through
 *  permission-checked tools; every answer shows that verified data with its source and time, and any text written by an
 *  AI model is labelled as AI insight. The assistant never changes anything. */
interface Fact { fact: string; link?: string; section?: string }
interface Result { tool: string; title: string; source: string; as_of: string | null; facts: Fact[]; gap?: string }
interface Answer { id: number; question: string; summary: string; ai_insight: string | null; model: string | null; results: Result[]; denied: string[]
  follow_up_of: string | null; suggestions: string[]; filters: Record<string, string | number> }
type Msg = { role: 'user'; text: string } | { role: 'assistant'; answer: Answer } | { role: 'error'; text: string }

const STARTERS = ['Give me the current executive overview.', 'What are the top operational risks?', 'Which actions are pending?',
  'Summarize the latest API failures.', 'What are the key trends this month?', 'Generate an executive summary for the management review.']

interface Ctx { open: boolean; setOpen: (v: boolean) => void; ask: (q: string) => void }
const AssistantCtx = createContext<Ctx>({ open: false, setOpen: () => undefined, ask: () => undefined })
export const useAssistant = () => useContext(AssistantCtx)

export function AssistantProvider({ children }: { children: ReactNode }) {
  const can = useCan('ai:use')
  const [open, setOpen] = useState(false)
  const [msgs, setMsgs] = useState<Msg[]>([])
  const [busy, setBusy] = useState(false)
  const send = useCallback(async (q: string) => {
    const question = q.trim()
    if (!question || busy) return
    setOpen(true)
    setMsgs((m) => [...m, { role: 'user', text: question }])
    setBusy(true)
    try {
      const answer = await post<Answer>('/ai/ask', { question })
      setMsgs((m) => [...m, { role: 'assistant', answer }])
    } catch (e) {
      setMsgs((m) => [...m, { role: 'error', text: e instanceof ApiError || e instanceof Error ? e.message : 'The assistant could not answer right now.' }])
    } finally { setBusy(false) }
  }, [busy])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if ((e.ctrlKey || e.metaKey) && e.key === 'j') { e.preventDefault(); setOpen((o) => !o) } }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
  return (
    <AssistantCtx.Provider value={{ open, setOpen, ask: send }}>
      {children}
      {can && open && <Panel msgs={msgs} busy={busy} onSend={send} onClose={() => setOpen(false)} onReset={() => setMsgs([])} />}
    </AssistantCtx.Provider>
  )
}

export function AssistantButton() {
  const { open, setOpen } = useAssistant()
  if (!useCan('ai:use')) return null
  return (
    <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} aria-label="Open the LV NEXUS assistant (Ctrl+J)" title="Ask the assistant (Ctrl+J)"
      className="cn-btn h-9 rounded-full px-3 text-xs text-white" style={{ background: 'var(--brand-gradient)' }}>
      <Sparkles size={14} aria-hidden /><span className="hidden sm:inline">Ask the assistant</span>
    </button>
  )
}

function ResultCard({ r, onNavigate }: { r: Result; onNavigate: () => void }) {
  const [open, setOpen] = useState(true)
  const sections = r.facts.some((f) => f.section)
  let last = ''
  return (
    <div className="rounded-xl border border-line bg-surface">
      <button type="button" className="flex w-full items-center gap-2 px-3 py-2 text-left" onClick={() => setOpen(!open)} aria-expanded={open}>
        {open ? <ChevronDown size={13} aria-hidden /> : <ChevronRight size={13} aria-hidden />}
        <Database size={13} className="text-accent" aria-hidden /><span className="min-w-0 flex-1 truncate text-[12.5px] font-semibold">{r.title}</span>
        <span className="shrink-0 text-[10.5px] text-ink-3">{r.as_of ? `data ${fmtAgo(r.as_of)}` : ''}</span>
      </button>
      {open && <div className="border-t border-line px-3 py-2">
        {r.facts.length === 0 && <p className="text-[12.5px] text-ink-3">{r.gap ?? 'Nothing found in the collected data.'}</p>}
        <ul className="space-y-1.5">{r.facts.map((f, i) => {
          const head = sections && f.section && f.section !== last ? (last = f.section!) : null
          return <li key={i}>
            {head && <div className="mb-1 mt-2 text-[10.5px] font-semibold uppercase tracking-wide text-ink-3 first:mt-0">{head}</div>}
            <div className="flex items-start gap-1.5 text-[12.5px] leading-snug"><span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-hidden />
              <span className="min-w-0 flex-1">{f.fact}</span>
              {f.link && <Link to={f.link} onClick={onNavigate} className="shrink-0 text-accent hover:underline" aria-label="Open the page"><ArrowUpRight size={13} /></Link>}</div>
          </li>
        })}</ul>
        {r.facts.length > 0 && r.gap && <p className="mt-1.5 text-[11.5px] text-ink-3">{r.gap}</p>}
        <p className="mt-2 text-[10.5px] text-ink-3">Source: {r.source}</p>
      </div>}
    </div>
  )
}

function AnswerView({ a, onAsk, onNavigate }: { a: Answer; onAsk: (q: string) => void; onNavigate: () => void }) {
  const [copied, setCopied] = useState(false)
  const copy = () => { navigator.clipboard?.writeText(a.ai_insight ? `${a.ai_insight}\n\n${a.summary}` : a.summary).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) }) }
  return (
    <div className="space-y-2">
      {a.follow_up_of && <p className="text-[11px] text-ink-3">Follow-up to “{a.follow_up_of}”{a.filters.provider ? ` · ${String(a.filters.provider).toUpperCase()} only` : ''}</p>}
      {a.ai_insight && <div className="rounded-xl border p-3" style={{ borderColor: 'color-mix(in srgb, var(--accent) 35%, var(--line))', background: 'color-mix(in srgb, var(--accent) 6%, var(--surface-1))' }}>
        <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-accent"><Sparkles size={12} aria-hidden />AI insight
          <span className="font-normal normal-case tracking-normal text-ink-3">· written by {a.model ?? 'the AI model'} from the verified data below</span></div>
        <div className="whitespace-pre-wrap text-[13px] leading-relaxed">{a.ai_insight}</div>
      </div>}
      <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-ink-3"><Database size={12} aria-hidden />Verified data
        <span className="font-normal normal-case tracking-normal">· from LV NEXUS records{a.ai_insight ? '' : ' (no AI model configured: factual summary)'}</span></div>
      {a.results.map((r) => <ResultCard key={r.tool} r={r} onNavigate={onNavigate} />)}
      {a.denied.length > 0 && <p className="rounded-lg bg-surface-2 px-3 py-2 text-[12px] text-ink-2">Not available for your role: {a.denied.join('; ')}.</p>}
      <div className="flex flex-wrap items-center gap-1.5 pt-1">
        {a.suggestions.map((s) => <button key={s} type="button" onClick={() => onAsk(s)} className="rounded-full border border-line px-2.5 py-1 text-[11.5px] hover:border-accent hover:text-accent">{s}</button>)}
        <button type="button" onClick={copy} className="ml-auto inline-flex items-center gap-1 text-[11.5px] text-ink-3 hover:text-ink"><Copy size={12} aria-hidden />{copied ? 'Copied' : 'Copy'}</button>
      </div>
    </div>
  )
}

function Panel({ msgs, busy, onSend, onClose, onReset }: { msgs: Msg[]; busy: boolean; onSend: (q: string) => void; onClose: () => void; onReset: () => void }) {
  const [q, setQ] = useState('')
  const end = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLTextAreaElement>(null)
  useEffect(() => { end.current?.scrollIntoView({ behavior: 'smooth' }) }, [msgs, busy])
  useEffect(() => { input.current?.focus() }, [])
  useEffect(() => { const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose(); window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k) }, [onClose])
  const submit = () => { if (q.trim().length >= 2) { onSend(q); setQ('') } }
  return (
    <aside role="dialog" aria-label="LV NEXUS assistant" className="fixed inset-y-0 right-0 z-50 flex w-full max-w-[520px] flex-col border-l border-line bg-surface shadow-2xl cn-slide-panel">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <span className="grid h-8 w-8 place-items-center rounded-full text-white" style={{ background: 'var(--brand-gradient)' }}><Bot size={16} aria-hidden /></span>
        <div className="min-w-0 flex-1"><div className="text-[14px] font-semibold">LV NEXUS assistant</div>
          <div className="text-[11px] text-ink-3">Answers from your cloud data · read-only · respects your role</div></div>
        {msgs.length > 0 && <button type="button" onClick={onReset} className="rounded-full p-1.5 text-ink-3 hover:bg-surface-2 hover:text-ink" aria-label="New conversation" title="New conversation"><RotateCcw size={15} /></button>}
        <button type="button" onClick={onClose} className="rounded-full p-1.5 text-ink-3 hover:bg-surface-2 hover:text-ink" aria-label="Close the assistant"><X size={17} /></button>
      </header>
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-4" aria-live="polite">
        {msgs.length === 0 && <div className="space-y-3">
          <p className="text-[13px] text-ink-2">Ask about risk, cost, access, activity or platform health. Every answer shows the data it comes from, and you can ask follow-ups like “and for AWS only?”.</p>
          <div className="grid gap-2">{STARTERS.map((s) => <button key={s} type="button" onClick={() => onSend(s)}
            className="rounded-xl border border-line px-3 py-2 text-left text-[13px] hover:border-accent hover:bg-surface-2">{s}</button>)}</div>
        </div>}
        {msgs.map((m, i) => m.role === 'user'
          ? <div key={i} className="flex justify-end"><div className="max-w-[85%] rounded-2xl rounded-br-md bg-accent px-3.5 py-2 text-[13px] text-white">{m.text}</div></div>
          : m.role === 'error'
            ? <div key={i} className="rounded-xl border px-3 py-2 text-[12.5px]" style={{ borderColor: 'var(--critical)', color: 'var(--critical)' }}>{m.text}</div>
            : <AnswerView key={i} a={m.answer} onAsk={onSend} onNavigate={onClose} />)}
        {busy && <div className="flex items-center gap-2 text-[12.5px] text-ink-3"><Loader2 size={14} className="animate-spin" aria-hidden />Reading the collected data…</div>}
        <div ref={end} />
      </div>
      <form className="border-t border-line p-3" onSubmit={(e) => { e.preventDefault(); submit() }}>
        <div className="flex items-end gap-2 rounded-2xl border border-line bg-surface-2 px-3 py-2 focus-within:border-accent">
          <textarea ref={input} rows={1} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Ask a question…" aria-label="Your question"
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit() } }}
            className="max-h-32 min-h-[24px] flex-1 resize-none border-0 bg-transparent text-[13.5px] outline-none focus:outline-none focus-visible:outline-none" style={{ boxShadow: "none" }} />
          <button type="submit" disabled={busy || q.trim().length < 2} className="grid h-8 w-8 place-items-center rounded-full bg-accent text-white disabled:opacity-40" aria-label="Send"><Send size={14} /></button>
        </div>
        <p className="mt-1.5 text-center text-[10.5px] text-ink-3">The assistant never changes cloud resources, access or budgets. Check important figures on the linked pages.</p>
      </form>
    </aside>
  )
}
