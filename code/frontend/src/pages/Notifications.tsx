import { AlertTriangle, Bell, CheckCircle2, OctagonAlert, Send } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useCan } from '../auth/AuthContext'
import { IconBadge, Panel } from '../components/hero'
import { EmptyState, ErrorNote, Freshness, PageHeader, PageSkeleton, StatusBadge, fmtInt } from '../components/ui'
import { useApi } from '../hooks/useApi'
import { useFilters } from '../hooks/useFilters'
import type { Automation, Overview } from '../services/api'

const LINK: Record<string, string> = { soc: '/audit', finops: '/cost/overview', infrastructure: '/monitoring', automation: '/automation', inventory: '/inventory' }
const ICON: Record<string, React.ReactNode> = {
  critical: <OctagonAlert size={16} className="text-critical" />, serious: <AlertTriangle size={16} className="text-serious" />, warning: <AlertTriangle size={16} className="text-warning" />,
}

/** In-app notifications: alerts the API derives from current state. They clear themselves when the condition clears. */
export default function Notifications() {
  const { refreshKey, refresh } = useFilters()
  const canAuto = useCan('automation:read')
  const ov = useApi<Overview>('/dashboard/overview', undefined, refreshKey)
  const auto = useApi<Automation>(canAuto ? '/dashboard/automation' : null, undefined, refreshKey)
  if (ov.error) return <ErrorNote message={ov.error.message} onRetry={ov.reload} />
  if (!ov.data) return <PageSkeleton tiles={3} />
  const alerts = ov.data.alerts
  const n = auto.data?.notifications ?? {}
  return (
    <>
      <PageHeader eyebrow="Reports & Alerts" title="Notifications" description="Active alerts across security, cost, infrastructure and automation. Each one stays until its cause is resolved; nothing is dismissed automatically."
        action={<Freshness at={ov.data.generated_at} label="Checked" onRefresh={refresh} />} />
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel icon={<Bell size={15} />} title={`Active alerts (${alerts.length})`} className="xl:col-span-2">
          {alerts.length === 0 ? <EmptyState icon={<CheckCircle2 size={18} />} title="No active alerts">Alerts appear when a collection fails, a budget level is reached, the scheduler stops or a critical finding is open.</EmptyState> : (
            <ul className="cn-stagger space-y-2">
              {alerts.map((a, i) => (
                <li key={i} className="flex items-start gap-3 rounded-2xl border border-line bg-surface-2 px-4 py-3">
                  <IconBadge>{ICON[a.level] ?? <Bell size={15} />}</IconBadge>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold capitalize">{a.area}</span><StatusBadge status={a.level} /></div>
                    <div className="mt-0.5 text-sm text-ink-2">{a.text}</div>
                  </div>
                  {LINK[a.area] && <Link to={LINK[a.area]} className="cn-btn cn-btn-ghost h-8 text-xs">Open</Link>}
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel icon={<Send size={15} />} title="Email and Chat delivery" subtitle="All notification messages by status">
          {!canAuto ? <EmptyState title="Requires automation access" /> : Object.keys(n).length === 0 ? <EmptyState title="No messages recorded">Email and Google Chat stay idle until configured.</EmptyState> : (
            <ul className="space-y-2 text-sm">{Object.entries(n).map(([k, v]) => <li key={k} className="flex justify-between"><StatusBadge status={k} /><span className="tabular font-semibold">{fmtInt(v)}</span></li>)}</ul>
          )}
        </Panel>
      </div>
    </>
  )
}
