import { AlertTriangle, Cpu, Gauge, Globe2, HeartPulse, PieChart as PieIcon, Power, PowerOff, Server } from 'lucide-react'
import { useState } from 'react'
import { ArcDonut, CARD_ORDER, ComparisonChart, HeroLayout, KpiCard, MONITORING_TABS, Panel, ProviderCard, Segmented, SubTabs } from '../components/hero'
import {
  Card, CollectionNotice, EmptyState, ErrorNote, ExportButton, Freshness, Meter, PageHeader, PageSkeleton, ProviderTag, StatusBadge, Table,
  fmtBytes, fmtInt, fmtTime,
} from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useFilters } from '../hooks/useFilters'
import type { Infra } from '../services/api'

const HEALTH_LABEL: Record<string, string> = { healthy: 'Healthy', warning: 'Warning', critical: 'Critical', partial: 'Partial data', unknown: 'Unknown', stopped: 'Stopped' }
const HEALTH_COLOR: Record<string, string> = { healthy: 'var(--good)', warning: 'var(--warning)', critical: 'var(--critical)', partial: 'var(--neutral-mark)', unknown: 'var(--neutral-mark)', stopped: 'var(--surface-3)' }

/** A metric cell: "no data" when the platform has no reading; a real 0 shows as 0%. */
function Pct({ value, running }: { value: number | null; running: boolean }) {
  if (!running) return <span className="text-xs text-ink-3">not running</span>
  return <Meter value={value} />
}
const shortType = (t: string) => t.replace(/^Microsoft\./i, '').replace(/^virtual_machine$/, 'Virtual machines (all clouds)')

export default function Infrastructure() {
  const { filters: f, set, refreshKey, refresh } = useFilters()
  const [view, setView] = useState<'cpu' | 'region' | 'cloud'>('cpu')
  const { data, error, loading, reload } = useApi<Infra>('/dashboard/infrastructure', { provider: f.provider, scope: f.scope, region: f.region, environment: f.environment }, refreshKey)
  if (error) return <ErrorNote message={error.message} onRetry={reload} />
  if (!data) return loading ? <PageSkeleton tiles={6} /> : null
  const has = data.collection.state === 'collected'
  const h = data.by_health
  const total = Object.values(h).reduce((a, n) => a + n, 0)
  const running = data.by_power_state.running ?? 0
  const n = (v: number | undefined) => (has ? v ?? 0 : null)
  const regions = Object.entries(data.by_region).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([region, vms]) => ({ region, vms }))
  const types = Object.entries(data.resources_by_type).sort((a, b) => b[1] - a[1])
  const u = data.utilisation
  const stopped = Object.entries(data.by_power_state).filter(([k]) => k !== 'running').reduce((a, [, v]) => a + v, 0)
  const cpuRows = data.vms.filter((v) => v.power_state === 'running' && v.cpu_percent !== null).sort((a, b) => (b.cpu_percent ?? 0) - (a.cpu_percent ?? 0)).slice(0, 24)
    .map((v) => ({ vm: v.name ?? '(unnamed)', cpu: v.cpu_percent, memory: v.memory_percent }))
  const byCloud = (['azure', 'aws', 'gcp'] as const).map((p) => { const vs = data.vms.filter((v) => v.provider === p); const r = vs.filter((v) => v.power_state === 'running').length; return { cloud: p === 'azure' ? 'Azure' : p.toUpperCase(), running: r, stopped: vs.length - r } })
  return (
    <>
      <PageHeader eyebrow="Infrastructure Health" title="Monitoring: resources and virtual machines"
        description="Inventory, availability and utilisation across clouds. A VM missing a metric shows as partial data, never as healthy, and a real reading of 0% is shown as 0%."
        action={<Freshness at={data.collection.last_run_at} label="VMs collected" state={data.collection.last_status} onRefresh={refresh} />} />
      <SubTabs items={MONITORING_TABS} />
      <CollectionNotice collection={data.collection} what="VM data" />
      <HeroLayout
        kpis={<>
          <KpiCard icon={<Server size={15} />} label="Virtual machines" num={n(total)} note={has ? `${fmtInt(data.public_ip_count)} with a public IP` : 'Not collected'} />
          <KpiCard icon={<Power size={15} />} label="Running" num={n(running)} note={has && total ? `${((100 * running) / total).toFixed(0)}% availability` : undefined} />
          <KpiCard icon={<PowerOff size={15} />} label="Stopped" num={has ? stopped : null} note="stopped or deallocated" />
          <KpiCard icon={<HeartPulse size={15} />} label="Healthy" num={n(h.healthy)} note="metrics present, within limits" />
          <KpiCard icon={<AlertTriangle size={15} />} label="Warning or critical" num={has ? (h.warning ?? 0) + (h.critical ?? 0) : null} note={`${fmtInt(data.open_alerts.length)} open alerts`} />
          <KpiCard icon={<Globe2 size={15} />} label="Open to internet" num={n(data.exposed_count)} note="management or data ports exposed" />
        </>}
        main={
          <Panel icon={<Cpu size={15} />} title={view === 'cpu' ? 'Utilisation by VM' : view === 'region' ? 'VMs by region' : 'VMs by cloud'}
            subtitle={view === 'cpu' ? `Latest sample, running VMs (top ${cpuRows.length}); memory where the guest agent reports it` : view === 'region' ? 'Top 10 regions' : 'Running and stopped'}
            action={<Segmented label="View" value={view} onChange={setView} options={[{ value: 'cpu', label: 'CPU' }, { value: 'region', label: 'Regions' }, { value: 'cloud', label: 'By cloud' }]} />}
            bodyClass="px-5 pb-4 pt-3 xl:pr-16">
            {view === 'cpu' ? <ComparisonChart key="u" data={cpuRows} x="vm" fmt={(v) => `${v.toFixed(0)}%`} xFmt={(v) => v.length > 14 ? `${v.slice(0, 13)}…` : v}
                series={[{ key: 'cpu', label: 'CPU %', color: 'var(--compare-current)' }, { key: 'memory', label: 'Memory %', color: 'var(--compare-previous)' }]} empty={<EmptyState title="No CPU samples collected" />} />
              : view === 'region' ? <ComparisonChart key="r" data={regions} x="region" series={[{ key: 'vms', label: 'VMs', color: 'var(--compare-current)' }]} empty={<EmptyState title="No region data" />} />
              : <ComparisonChart key="c" stacked data={byCloud} x="cloud" series={[{ key: 'running', label: 'Running', color: 'var(--compare-current)' }, { key: 'stopped', label: 'Not running', color: 'var(--compare-previous)' }]} empty={<EmptyState title="No VMs in the inventory" />} />}
          </Panel>
        }
        trend={
          <Panel float icon={<Gauge size={15} />} title="Resource utilisation" subtitle="Average of the latest sample, running VMs">
            <div className="space-y-3.5">
              {(['cpu', 'memory', 'disk'] as const).map((k) => (
                <div key={k}>
                  <div className="mb-1 flex justify-between text-xs"><span className="font-semibold text-ink">{k === 'cpu' ? 'CPU' : k === 'memory' ? 'Memory' : 'Disk'}</span>
                    <span className="text-ink-3">{u[k].reporting} reporting{u[k].missing ? ` · ${u[k].missing} without data` : ''}</span></div>
                  <Meter value={u[k].average} tone="var(--compare-current)" label={`${k} average`} />
                  {u[k].max !== null && <div className="mt-0.5 text-[11px] text-ink-3">peak {u[k].max}%</div>}
                </div>
              ))}
              <p className="text-[11px] text-ink-3">Memory and disk need the guest agent (Azure Monitor Agent, CloudWatch agent, Ops Agent); without it they show "no data", not 0.</p>
            </div>
          </Panel>
        }
        donut={
          <Panel float icon={<PieIcon size={15} />} title="VM health" subtitle="All VMs by health state">
            <ArcDonut centre={has ? fmtInt(total) : '—'} centreNote="VMs" emptyText="No VMs in the inventory."
              items={Object.entries(h).map(([k, v]) => ({ key: k, label: HEALTH_LABEL[k] ?? k, value: v, color: HEALTH_COLOR[k] ?? 'var(--neutral-mark)' }))} />
          </Panel>
        }
        bottom={CARD_ORDER.filter((p) => !f.provider || p === f.provider).map((p) => {
          const vms = data.vms.filter((v) => v.provider === p)
          const run = vms.filter((v) => v.power_state === 'running')
          const cpu = run.map((v) => v.cpu_percent).filter((c): c is number => c !== null)
          const alerts = data.open_alerts.filter((a) => a.provider === p).length
          return (
            <ProviderCard key={p} provider={p} to="/monitoring" action="Show this cloud" onAction={() => set({ provider: p, scope: '' })}
              value={has ? fmtInt(data.by_provider[p] ?? 0) : '—'} valueLabel="Virtual machines"
              side={{ value: cpu.length ? `${(cpu.reduce((x, y) => x + y, 0) / cpu.length).toFixed(0)}%` : '—', label: 'Average CPU' }}
              split={vms.length ? { left: { label: 'Running', value: fmtInt(run.length) }, right: { label: 'Not running', value: fmtInt(vms.length - run.length) }, ratio: run.length / vms.length } : null}
              note={!has ? 'Not collected' : vms.length ? undefined : 'No VMs for this cloud'}
              extra={<div>{alerts ? `${alerts} open monitoring alert${alerts === 1 ? '' : 's'}` : 'No open monitoring alerts'} · {vms.filter((v) => v.exposed_ports?.length).length} exposed</div>} />
          )
        })}
      />

      <div className="grid gap-4 xl:grid-cols-3">
        <Card icon={<Server size={15} />} title="Cloud resource inventory" subtitle="By resource type. Azure lists every resource; AWS and GCP contribute VMs." className="xl:col-span-2"
          action={<ExportButton name="Resource inventory by type" head={['Resource type', 'Count']} rows={types} />}>
          <Table dense maxHeight={320} empty="Resource inventory not collected yet" head={['Resource type', 'Count']} rows={types.map(([t, c]) => [<span className="text-xs">{shortType(t)}</span>, <span className="tabular">{fmtInt(c)}</span>])} />
        </Card>
        <Card icon={<Server size={15} />} title="VMs by account / subscription">
          <Table dense maxHeight={320} empty="No VMs" head={['Scope', 'VMs']} rows={Object.entries(data.by_scope).sort((a, b) => b[1] - a[1]).map(([s, c]) => [<code className="break-all text-xs">{s}</code>, <span className="tabular">{fmtInt(c)}</span>])} />
        </Card>
      </div>

      <Card icon={<Server size={15} />} title="Monitoring alerts" subtitle="Open alerts; they resolve themselves when the condition clears">
        <Table empty="No open VM alerts" head={['Raised', 'Cloud', 'VM', 'Alert', 'Severity', 'Detail']} rows={data.open_alerts.map((a) => [
          <span className="whitespace-nowrap text-xs">{fmtTime(a.created_at)}</span>, a.provider ? <ProviderTag provider={a.provider} /> : '—', <span className="font-medium">{a.vm ?? a.vm_id}</span>,
          a.type.replace(/_/g, ' '), <StatusBadge status={a.severity} />, <span className="text-xs text-ink-2">{a.message}</span>])} />
      </Card>

      <Card icon={<Server size={15} />} title="Virtual machine inventory" subtitle="First 500 matching the filters; metrics are the latest collected sample"
        action={<ExportButton name="VM inventory" head={['Cloud', 'Scope', 'Name', 'Region', 'Type', 'State', 'CPU %', 'Memory %', 'Disk %', 'Network in', 'Network out', 'Public IP', 'Private IP', 'Open ports', 'Health']}
          rows={data.vms.map((v) => [v.provider, v.scope, v.name, v.region, v.instance_type, v.power_state, v.cpu_percent ?? 'no data', v.memory_percent ?? 'no data', v.disk_percent ?? 'no data',
            v.network_in_bytes ?? 'no data', v.network_out_bytes ?? 'no data', v.public_ip, v.private_ip, v.exposed_ports.join(' '), v.health_status])} />}>
        <Table empty="No VMs in the inventory" head={['VM', 'State', 'CPU', 'Memory', 'Disk', 'Network in / out', 'Addresses', 'Internet-open ports', 'Health']} rows={data.vms.map((v) => {
          const on = v.power_state === 'running'
          return [
            <div><div className="font-medium">{v.name ?? '—'}</div><div className="text-xs text-ink-3"><ProviderTag provider={v.provider} /> · {v.region ?? '—'} · {v.instance_type ?? '—'}</div></div>,
            <span className="text-xs">{v.power_state ?? '—'}</span>, <Pct value={v.cpu_percent} running={on} />, <Pct value={v.memory_percent} running={on} />, <Pct value={v.disk_percent} running={on} />,
            <span className="whitespace-nowrap text-xs text-ink-2">{on ? `${fmtBytes(v.network_in_bytes)} / ${fmtBytes(v.network_out_bytes)}` : '—'}</span>,
            <div className="text-xs"><div>{v.public_ip ? <span className="font-medium">{v.public_ip}</span> : <span className="text-ink-3">no public IP</span>}</div><div className="text-ink-3">{v.private_ip ?? '—'}</div></div>,
            <span className="text-xs">{v.exposed_ports.length ? v.exposed_ports.join(', ') : '—'}</span>,
            <StatusBadge status={v.health_status === 'partial' ? 'unknown' : v.health_status} label={HEALTH_LABEL[v.health_status] ?? v.health_status} />,
          ]
        })} />
      </Card>
      <p className="text-center text-[11px] text-ink-3">Generated {fmtTime(data.generated_at)}. Memory and disk need a guest monitoring agent (CloudWatch agent, Ops Agent, Azure Monitor agent / VM Insights).</p>
    </>
  )
}
