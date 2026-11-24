import { Bot, Play, Send, ShieldAlert, Sparkles } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Panel, Segmented } from '../../components/hero'
import { DataGrid, Drawer, KV, Pill, Section, Timeline, useAction, type Col } from '../../components/secops'
import { useToast } from '../../components/Toast'
import { ErrorNote, PageHeader, PageSkeleton, fmtTime } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'

interface Status { model_configured: boolean; model: string | null; tools: { name: string; description: string; available: boolean }[]; agents: { key: string; name: string; available: boolean }[]; policy: string }
interface Fact { fact: string; link?: string; from?: string }
interface Answer { id: number; question: string; answer: string; answer_source: string; results: { tool: string; title: string; source: string; as_of: string | null; facts: Fact[] }[]; denied: string[] }
interface Rec { id: number; agent: string; agent_name: string; title: string; category: string; priority: string; rationale: string; evidence: Fact[] | Record<string, unknown>; recommended_action: string
  action_type: string; required_permission: string | null; confidence: string; status: string; reviewed_by: string | null; approved_by: string | null; executed_by: string | null; verification: string | null; created_at: string }

const STEPS: Record<string, { action: string; label: string; notes?: boolean; when: (r: Rec) => boolean }[]> = {
  PROPOSED: [{ action: 'accept', label: 'Accept (information only)', when: (r) => !r.required_permission }, { action: 'request_approval', label: 'Request approval', when: (r) => !!r.required_permission }, { action: 'dismiss', label: 'Dismiss', notes: true, when: () => true }],
  APPROVAL_REQUESTED: [{ action: 'approve', label: 'Approve', when: () => true }, { action: 'reject', label: 'Reject', notes: true, when: () => true }],
  APPROVED: [{ action: 'executed', label: 'Record that a person made the change', notes: true, when: () => true }],
  EXECUTED: [{ action: 'verify', label: 'Verify against the latest data', when: () => true }],
}

function RecPanel({ id, onClose, onChanged }: { id: number; onClose: () => void; onChanged: () => void }) {
  const [bump, setBump] = useState(0)
  const [notes, setNotes] = useState('')
  const { data } = useApi<Rec & { history: { action: string; actor: string; notes: string | null; at: string }[] }>(`/ai/recommendations/${id}`, undefined, bump)
  const { run, busy } = useAction(() => { setBump((b) => b + 1); setNotes(''); onChanged() })
  if (!data) return <Drawer title="Recommendation" onClose={onClose}><div className="text-sm text-ink-3">Loading…</div></Drawer>
  const ev: Fact[] = Array.isArray(data.evidence) ? data.evidence : Object.entries(data.evidence ?? {}).map(([k, v]) => ({ fact: `${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}` }))
  const steps = (STEPS[data.status] ?? []).filter((s) => s.when(data))
  return (
    <Drawer title={data.title} subtitle={<span className="flex gap-2"><Pill value={data.priority} /><Pill value={data.status === 'VERIFIED' ? 'APPROVED' : data.status === 'DISMISSED' || data.status === 'REJECTED' ? 'REJECTED' : 'PENDING'} text={data.status.replace(/_/g, ' ').toLowerCase()} /></span>} onClose={onClose}>
      <Section title="Why"><p className="text-sm">{data.rationale}</p></Section>
      <Section title="Evidence"><ul className="space-y-1 text-sm">{ev.map((e, i) => <li key={i}>{e.link ? <Link className="text-accent hover:underline" to={e.link}>{e.fact}</Link> : e.fact}</li>)}</ul></Section>
      <Section title="Recommended action"><KV items={[['Action', data.recommended_action], ['Type', data.action_type], ['Needs approval from', data.required_permission ?? 'No approval: information only'], ['Confidence', data.confidence], ['Agent', data.agent_name], ['Verification', data.verification ?? '—']]} />
        <p className="mt-2 text-[11px] text-ink-3">LV NEXUS never makes this change. A person makes it in the cloud console or through change management, records it here, and the platform verifies it against the next synchronization.</p></Section>
      {steps.length > 0 && <Section title="Next step">
        <textarea className="cn-input min-h-14 w-full" placeholder="Notes (required to dismiss, reject or record execution)" aria-label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
        <div className="mt-2 flex flex-wrap gap-2">{steps.map((s) => <button key={s.action} className={`cn-btn h-8 text-xs ${s.notes ? 'cn-btn-ghost' : 'cn-btn-primary'}`} disabled={busy || (!!s.notes && !notes.trim())}
          onClick={() => run(() => api.post(`/ai/recommendations/${id}/step`, { action: s.action, notes: notes || null }), s.label)}>{s.label}</button>)}</div></Section>}
      <Section title="Governance trail"><Timeline items={data.history.map((h) => ({ at: h.at, title: h.action.replace(/_/g, ' '), text: `${h.actor}${h.notes ? ` · ${h.notes}` : ''}` }))} /></Section>
    </Drawer>
  )
}

/** AI Intelligence Center: copilot over the platform's own records, specialist agents, and governed recommendations. */
export default function Intelligence() {
  const toast = useToast()
  const status = useApi<Status>('/ai/status')
  const [q, setQ] = useState('')
  const [asking, setAsking] = useState(false)
  const [answers, setAnswers] = useState<Answer[]>([])
  const [filter, setFilter] = useState('PROPOSED')
  const [bump, setBump] = useState(0)
  const [open, setOpen] = useState<number | null>(null)
  const recs = useApi<{ items: Rec[] }>('/ai/recommendations', { status: filter || undefined }, bump)
  const runs = useApi<{ items: { id: number; agent: string; started_by: string; status: string; summary: string; recommendations: number; at: string }[] }>('/ai/runs', undefined, bump)
  const { run, busy } = useAction(() => setBump((b) => b + 1))
  if (status.error) return <ErrorNote message={status.error.message} onRetry={status.reload} />
  if (!status.data) return <PageSkeleton tiles={3} />
  const ask = async (question: string) => {
    if (question.trim().length < 3) return
    setAsking(true)
    try { const a = await api.post<Answer>('/ai/ask', { question }); setAnswers((x) => [a, ...x].slice(0, 10)); setQ('') }
    catch (e) { toast({ kind: 'error', title: 'Copilot', text: e instanceof Error ? e.message : 'Failed' }) }
    finally { setAsking(false) }
  }
  const cols: Col<Rec>[] = [
    { key: 'p', label: 'Priority', render: (r) => <Pill value={r.priority} /> }, { key: 't', label: 'Recommendation', render: (r) => <div className="max-w-md"><div className="font-medium">{r.title}</div><div className="text-[11px] text-ink-3">{r.agent_name} · {r.category}</div></div> },
    { key: 'a', label: 'Action', render: (r) => <span className="text-xs">{r.recommended_action}</span> }, { key: 'g', label: 'Approval', render: (r) => r.required_permission ?? 'information only' },
    { key: 's', label: 'Status', render: (r) => r.status.replace(/_/g, ' ').toLowerCase() }, { key: 'c', label: 'Created', render: (r) => fmtTime(r.created_at) },
  ]
  const suggestions = ['Which critical vulnerabilities are open?', 'Which subscriptions exceeded budget this month?', 'Who has privileged access without an approval?', 'Which resources are publicly exposed?', 'What are the top cost drivers this month?']
  return (
    <>
      <PageHeader eyebrow="Administration" title="Cloud Intelligence Copilot and agents" description={status.data.policy} />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Panel icon={<Sparkles size={15} />} title="Copilot" subtitle={status.data.model_configured ? `Answers written by ${status.data.model} from the facts below` : 'No language model configured: answers are assembled from the facts directly'}>
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); ask(q) }}>
            <input className="cn-input flex-1" placeholder="Ask about security, cost, budgets, access or inventory…" aria-label="Question" value={q} onChange={(e) => setQ(e.target.value)} />
            <button className="cn-btn cn-btn-primary h-9 text-sm" disabled={asking}><Send size={14} aria-hidden />{asking ? 'Asking…' : 'Ask'}</button>
          </form>
          <div className="mt-2 flex flex-wrap gap-1">{suggestions.map((s) => <button key={s} className="cn-btn cn-btn-ghost h-7 text-[11px]" onClick={() => ask(s)} disabled={asking}>{s}</button>)}</div>
          <div className="mt-3 space-y-3">{answers.map((a) => (
            <article key={a.id} className="rounded-lg border border-line p-3">
              <div className="text-sm font-semibold">{a.question}</div>
              <p className="mt-1 whitespace-pre-wrap text-sm">{a.answer}</p>
              <div className="mt-1 text-[11px] text-ink-3">Answer source: {a.answer_source}{a.denied.length ? ` · not consulted (no permission): ${a.denied.join(', ')}` : ''}</div>
              {a.results.map((r) => <details key={r.tool} className="mt-2 text-xs"><summary className="cursor-pointer">{r.title} · {r.facts.length} facts · {r.source}{r.as_of ? ` · data as of ${fmtTime(r.as_of)}` : ' · never synchronized'}</summary>
                <ul className="mt-1 list-disc space-y-0.5 pl-5">{r.facts.map((f, i) => <li key={i}>{f.link ? <Link className="text-accent hover:underline" to={f.link}>{f.fact}</Link> : f.fact}</li>)}</ul></details>)}
            </article>))}</div>
        </Panel>
        <Panel icon={<Bot size={15} />} title="Agents" subtitle="Each run reads current data and proposes recommendations; none acts on its own.">
          <ul className="space-y-2">{status.data.agents.map((a) => <li key={a.key} className="flex items-center justify-between gap-2 text-sm"><span>{a.name}</span>
            <button className="cn-btn cn-btn-ghost h-7 text-xs" disabled={!a.available || busy} title={a.available ? undefined : 'Your role does not include this agent'} onClick={() => run(() => api.post(`/ai/agents/${a.key}/run`), `${a.name} finished`)}><Play size={12} aria-hidden />Run</button></li>)}</ul>
          <div className="mt-3 border-t border-line pt-2 text-[11px] text-ink-3">Recent runs</div>
          <ul className="mt-1 space-y-1 text-xs">{(runs.data?.items ?? []).slice(0, 8).map((r) => <li key={r.id}><b>{r.agent}</b> · {r.recommendations} recommendations · {fmtTime(r.at)}<div className="text-ink-3">{r.summary}</div></li>)}</ul>
        </Panel>
      </div>
      <Panel icon={<ShieldAlert size={15} />} title="Recommendations" subtitle="Recommendation → review → approval → execution by a person → verification → audit"
        action={<Segmented label="Status" value={filter} onChange={setFilter} options={[{ value: 'PROPOSED', label: 'Proposed' }, { value: 'APPROVAL_REQUESTED', label: 'Awaiting approval' }, { value: 'APPROVED', label: 'Approved' }, { value: 'EXECUTED', label: 'Executed' }, { value: '', label: 'All' }]} />}>
        <DataGrid label="AI recommendations" cols={cols} rows={recs.data?.items ?? []} onOpen={(r) => setOpen(r.id)} empty="No recommendations in this state. Run an agent to analyse the current data." />
      </Panel>
      {open !== null && <RecPanel id={open} onClose={() => setOpen(null)} onChanged={() => setBump((b) => b + 1)} />}
    </>
  )
}
