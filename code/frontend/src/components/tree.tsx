import { ChevronRight } from 'lucide-react'
import { useState, type ReactNode } from 'react'

export interface TreeNode { id: string; children?: TreeNode[] }

/** Keyboard-accessible expandable tree. `render` draws a row; rows are buttons that select the node. */
export function Tree<T extends TreeNode>({ nodes, render, selected, onSelect, defaultOpen = 1, filter }: {
  nodes: T[]; render: (n: T, depth: number) => ReactNode; selected?: string | null; onSelect?: (n: T) => void; defaultOpen?: number
  filter?: (n: T) => boolean
}) {
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const keep = (n: T): boolean => !filter || filter(n) || ((n.children as T[] | undefined) ?? []).some(keep)
  const Row = ({ n, depth }: { n: T; depth: number }) => {
    const kids = ((n.children as T[] | undefined) ?? []).filter(keep)
    const isOpen = open[n.id] ?? (depth < defaultOpen || (!!filter && kids.length > 0))
    return (
      <li role="treeitem" aria-expanded={kids.length ? isOpen : undefined} aria-selected={selected === n.id}>
        <div className={`group flex items-center gap-1 rounded-lg pr-2 ${selected === n.id ? 'bg-accent-soft ring-1 ring-accent/30' : 'hover:bg-surface-2'}`}
          style={{ paddingLeft: depth * 16 + 4 }}>
          <button type="button" aria-label={isOpen ? 'Collapse' : 'Expand'} disabled={!kids.length} onClick={() => setOpen((o) => ({ ...o, [n.id]: !isOpen }))}
            className="grid h-6 w-6 shrink-0 place-items-center rounded text-ink-3 hover:text-ink disabled:opacity-0">
            <ChevronRight size={14} className={`transition-transform ${isOpen ? 'rotate-90' : ''}`} aria-hidden />
          </button>
          <button type="button" className="min-w-0 flex-1 py-1.5 text-left" onClick={() => onSelect?.(n)}>{render(n, depth)}</button>
        </div>
        {isOpen && kids.length > 0 && <ul role="group">{kids.map((c) => <Row key={c.id} n={c} depth={depth + 1} />)}</ul>}
      </li>
    )
  }
  return <ul role="tree" className="space-y-0.5">{nodes.filter(keep).map((n) => <Row key={n.id} n={n} depth={0} />)}</ul>
}
