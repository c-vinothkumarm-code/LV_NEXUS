import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { prefersReducedMotion } from '../hooks/useMotion'

const axis = { fontSize: 11, fill: 'var(--text-muted)' }
const tooltip = {
  contentStyle: { background: 'var(--surface-1)', border: '1px solid var(--line)', borderRadius: 10, fontSize: 12, color: 'var(--text-primary)', boxShadow: 'var(--shadow-2)' },
  labelStyle: { color: 'var(--text-primary)', fontWeight: 600 },
  itemStyle: { color: 'var(--text-secondary)' },
  cursor: { fill: 'var(--surface-2)' },
}
const legend = {
  wrapperStyle: { fontSize: 12 }, iconType: 'square' as const, iconSize: 9, itemSorter: null,
  formatter: (value: string) => <span style={{ color: 'var(--text-secondary)' }}>{value}</span>,
}
const animate = () => !prefersReducedMotion()

export interface Series { key: string; label: string; color: string }
type Fmt = (n: number) => string

/** Bars with a 2px surface gap between segments; one axis; legend for more than one series. */
export function StackedBars({ data, category, series, height = 240, horizontal = false, stacked = true, valueFormat }: {
  data: Record<string, string | number>[]; category: string; series: Series[]; height?: number; horizontal?: boolean; stacked?: boolean; valueFormat?: Fmt
}) {
  const fmt = valueFormat ?? ((n: number) => n.toLocaleString('en-IN'))
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout={horizontal ? 'vertical' : 'horizontal'} margin={{ top: 8, right: 12, bottom: 0, left: 0 }} barCategoryGap="28%" barGap={2}>
        <CartesianGrid stroke="var(--line)" strokeDasharray="2 4" vertical={horizontal} horizontal={!horizontal} />
        {horizontal ? (
          <>
            <XAxis type="number" allowDecimals={false} tick={axis} axisLine={false} tickLine={false} tickFormatter={fmt} />
            <YAxis type="category" dataKey={category} tick={{ ...axis, fill: 'var(--text-secondary)' }} axisLine={false} tickLine={false} width={120} />
          </>
        ) : (
          <>
            <XAxis dataKey={category} tick={{ ...axis, fill: 'var(--text-secondary)' }} axisLine={{ stroke: 'var(--line)' }} tickLine={false} />
            <YAxis allowDecimals={false} tick={axis} axisLine={false} tickLine={false} width={52} tickFormatter={fmt} />
          </>
        )}
        <Tooltip {...tooltip} formatter={(v) => fmt(Number(v))} />
        {series.length > 1 && <Legend {...legend} />}
        {series.map((s, i) => (
          <Bar key={s.key} dataKey={s.key} name={s.label} stackId={stacked ? 'a' : undefined} fill={s.color} stroke="var(--surface-1)" strokeWidth={stacked ? 2 : 0} maxBarSize={38}
            radius={!stacked || i === series.length - 1 ? (horizontal ? [0, 4, 4, 0] : [4, 4, 0, 0]) : 0} isAnimationActive={animate()} animationDuration={500} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  )
}

export function Lines({ data, x, series, height = 240, valueFormat }: { data: Record<string, string | number>[]; x: string; series: Series[]; height?: number; valueFormat?: Fmt }) {
  const fmt = valueFormat ?? ((n: number) => n.toLocaleString('en-IN'))
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: 0 }}>
        <CartesianGrid stroke="var(--line)" strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey={x} tick={axis} axisLine={{ stroke: 'var(--line)' }} tickLine={false} minTickGap={28} tickFormatter={(d: string) => (/^\d{4}-\d{2}-\d{2}$/.test(d) ? d.slice(5) : d)} />
        <YAxis tick={axis} axisLine={false} tickLine={false} width={56} tickFormatter={fmt} />
        <Tooltip {...tooltip} cursor={{ stroke: 'var(--text-muted)', strokeWidth: 1 }} formatter={(v) => fmt(Number(v))} />
        {series.length > 1 && <Legend {...legend} iconType="plainline" iconSize={14} />}
        {series.map((s) => (
          <Line key={s.key} type="monotone" dataKey={s.key} name={s.label} stroke={s.color} strokeWidth={2} dot={false}
            activeDot={{ r: 4, stroke: 'var(--surface-1)', strokeWidth: 2 }} isAnimationActive={animate()} animationDuration={600} connectNulls={false} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  )
}

/** Accessible fallback: the same numbers as a table. */
export function DataTableToggle({ columns, rows }: { columns: string[]; rows: (string | number)[][] }) {
  return (
    <details className="mt-2 text-xs text-ink-2">
      <summary className="cursor-pointer select-none">View as table</summary>
      <table className="tabular mt-2 w-full text-left">
        <thead><tr className="text-ink-3">{columns.map((c) => <th key={c} scope="col" className="py-1 pr-3 font-medium">{c}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i} className="border-t border-line/60">{r.map((c, j) => <td key={j} className="py-1 pr-3">{c}</td>)}</tr>)}</tbody>
      </table>
    </details>
  )
}
