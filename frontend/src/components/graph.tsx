import { useMemo, useState } from 'react'

export interface GNode { id: string; col: number; label: string; sub?: string; tone?: 'critical' | 'warning' | 'accent' | null; details: [string, string][] }
export interface GEdge { from: string; to: string; label?: string; dashed?: boolean }

const TONE: Record<string, string> = { critical: 'var(--critical)', warning: 'var(--warning)', accent: 'var(--accent)' }

/**
 * Layered relationship graph (left to right), drawn only from records the API returned: no inferred nodes or permissions.
 * Keyboard accessible: every node is a button; the selected node's details are listed beside the graph.
 */
export function RelationGraph({ columns, nodes, edges, height = 360 }: { columns: string[]; nodes: GNode[]; edges: GEdge[]; height?: number }) {
  const [sel, setSel] = useState<string | null>(nodes[0]?.id ?? null)
  const W = 920, colW = W / columns.length, nodeW = Math.min(190, colW - 26), nodeH = 40
  const layout = useMemo(() => {
    const pos = new Map<string, { x: number; y: number }>()
    columns.forEach((_, c) => {
      const list = nodes.filter((n) => n.col === c)
      const gap = Math.max(nodeH + 12, (height - 40) / Math.max(1, list.length))
      const top = Math.max(30, (height - gap * list.length) / 2 + 6)
      list.forEach((n, i) => pos.set(n.id, { x: c * colW + (colW - nodeW) / 2, y: top + i * gap }))
    })
    return pos
  }, [columns, nodes, height, colW, nodeW])
  const h = Math.max(height, ...[...layout.values()].map((p) => p.y + nodeH + 16))
  const related = useMemo(() => {
    if (!sel) return new Set<string>()
    const out = new Set([sel]); let grow = true
    while (grow) { grow = false; for (const e of edges) { if (out.has(e.from) && !out.has(e.to)) { out.add(e.to); grow = true } if (out.has(e.to) && !out.has(e.from) && e.to === sel) { out.add(e.from); grow = true } } }
    return out
  }, [sel, edges])
  const selNode = nodes.find((n) => n.id === sel)
  return (
    <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_260px]">
      <div className="overflow-x-auto rounded-xl border border-line bg-surface-2">
        <svg viewBox={`0 0 ${W} ${h}`} className="min-w-[640px]" role="group" aria-label={`Relationship graph: ${columns.join(' → ')}`}>
          {columns.map((c, i) => <text key={c} x={i * colW + colW / 2} y={18} textAnchor="middle" className="fill-[var(--text-muted)] text-[11px] font-semibold uppercase tracking-wider">{c}</text>)}
          {edges.map((e, i) => {
            const a = layout.get(e.from), b = layout.get(e.to)
            if (!a || !b) return null
            const x1 = a.x + nodeW, y1 = a.y + nodeH / 2, x2 = b.x, y2 = b.y + nodeH / 2, mx = (x1 + x2) / 2
            const on = related.has(e.from) && related.has(e.to)
            return <g key={i}><path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" stroke={on ? 'var(--accent)' : 'var(--line-strong)'}
              strokeWidth={on ? 2 : 1.2} strokeDasharray={e.dashed ? '5 4' : undefined} opacity={sel && !on ? 0.35 : 1} />
              {e.label && on && <text x={mx} y={(y1 + y2) / 2 - 4} textAnchor="middle" className="fill-[var(--text-muted)] text-[10px]">{e.label}</text>}</g>
          })}
          {nodes.map((n) => {
            const p = layout.get(n.id)!
            const active = n.id === sel, dim = sel && !related.has(n.id)
            return (
              <g key={n.id} transform={`translate(${p.x},${p.y})`} opacity={dim ? 0.45 : 1} style={{ cursor: 'pointer' }}
                role="button" tabIndex={0} aria-pressed={active} aria-label={`${columns[n.col]}: ${n.label}`}
                onClick={() => setSel(n.id)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSel(n.id) } }}>
                <rect width={nodeW} height={nodeH} rx={10} fill="var(--surface-1)" stroke={active ? 'var(--accent)' : n.tone ? TONE[n.tone] : 'var(--line)'} strokeWidth={active ? 2 : 1.2} />
                {n.tone && <circle cx={12} cy={nodeH / 2} r={4} fill={TONE[n.tone]} />}
                <text x={n.tone ? 22 : 10} y={17} className="fill-[var(--text-primary)] text-[12px] font-semibold">{n.label.length > 26 ? `${n.label.slice(0, 25)}…` : n.label}</text>
                {n.sub && <text x={n.tone ? 22 : 10} y={31} className="fill-[var(--text-muted)] text-[10.5px]">{n.sub.length > 30 ? `${n.sub.slice(0, 29)}…` : n.sub}</text>}
              </g>
            )
          })}
        </svg>
      </div>
      <aside className="rounded-xl border border-line p-3 text-xs" aria-live="polite">
        {selNode ? <>
          <div className="text-[10.5px] font-semibold uppercase tracking-wider text-ink-3">{columns[selNode.col]}</div>
          <div className="mt-0.5 text-sm font-semibold text-ink">{selNode.label}</div>
          <dl className="mt-2 space-y-1.5">{selNode.details.filter(([, v]) => v).map(([k, v]) => <div key={k}><dt className="text-ink-3">{k}</dt><dd className="break-words text-ink">{v}</dd></div>)}</dl>
        </> : <p className="text-ink-3">Select a node.</p>}
      </aside>
    </div>
  )
}
