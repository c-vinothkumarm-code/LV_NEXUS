import { ArrowUpRight, ClipboardList, Sparkles } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useCan } from '../auth/AuthContext'
import { useApi } from '../hooks/useApi'
import { useAssistant } from './assistant'
import { fmtTime } from './ui'

interface Brief { generated_at: string; source: string; sections: { title: string; facts: { fact: string; link: string | null }[] }[] }
const ORDER = ['Position', 'Top risks', 'Trends', 'Pending actions', 'Platform health']

/** Executive brief: verified headline facts for management, each linked to its page. Same data the assistant uses. */
export function ExecutiveBrief() {
  const { data, error } = useApi<Brief>('/home/brief')
  const { ask } = useAssistant()
  const canAsk = useCan('ai:use')
  if (error) return null
  return (
    <section className="cn-card overflow-hidden" aria-label="Executive brief">
      <header className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-4" style={{ background: 'linear-gradient(120deg, color-mix(in srgb, var(--accent) 9%, transparent), transparent 70%)' }}>
        <span className="grid h-9 w-9 place-items-center rounded-xl bg-accent text-white"><ClipboardList size={17} aria-hidden /></span>
        <div className="min-w-0 flex-1"><h2 className="text-[16px] font-semibold tracking-tight">Executive brief</h2>
          <p className="text-[12px] text-ink-3">Verified from collected cloud data{data ? ` · ${fmtTime(data.generated_at)}` : ''} · every line links to its source</p></div>
        {canAsk && <button type="button" onClick={() => ask('Generate an executive summary for the management review.')} className="cn-btn cn-btn-primary h-9">
          <Sparkles size={14} aria-hidden />Draft management summary</button>}
      </header>
      {!data ? <div className="grid gap-3 p-5 md:grid-cols-2">{[0, 1, 2, 3].map((i) => <div key={i} className="cn-skeleton h-24 rounded-xl" />)}</div> : (
        <div className="grid gap-x-8 gap-y-5 p-5 md:grid-cols-2 xl:grid-cols-3">
          {[...data.sections].sort((a, b) => ORDER.indexOf(a.title) - ORDER.indexOf(b.title)).map((s) => (
            <div key={s.title}>
              <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-[.12em] text-accent">{s.title}</h3>
              <ul className="space-y-1.5">{s.facts.map((f, i) => (
                <li key={i} className="flex items-start gap-2 text-[13px] leading-snug">
                  <span className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-hidden />
                  {f.link ? <Link to={f.link} className="group min-w-0 flex-1 hover:text-accent">{f.fact}<ArrowUpRight size={12} className="ml-0.5 inline opacity-0 group-hover:opacity-100" aria-hidden /></Link>
                    : <span className="min-w-0 flex-1">{f.fact}</span>}
                </li>))}</ul>
            </div>))}
        </div>)}
    </section>
  )
}
