import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { AssistantProvider } from './components/assistant'
import { AccessDenied, NotFound } from './components/states'
import { useCan, useMe } from './auth/AuthContext'
import { EmptyState } from './components/ui'
import { FilterProvider } from './hooks/useFilters'
import AppLayout from './layouts/AppLayout'
import Access from './pages/Access'
import Automation from './pages/Automation'
import Governance from './pages/Governance'
import Infrastructure from './pages/Infrastructure'
import Notifications from './pages/Notifications'
import Onboarding from './pages/Onboarding'
import Reports from './pages/Reports'
import Activities, { AuditOverview } from './pages/audit/Activities'
import { Cases, Rules } from './pages/audit/CasesRules'
import { IntegrationsHome, Permissions, RegionCoverage, Schedule, SyncDashboard, SyncHistory } from './pages/integrations/Integrations'
import Findings from './pages/vuln/Findings'
import Explorer from './pages/inventory/Explorer'
import CloudServicesInventory, { CloudServiceAsset, CloudServicesActivity } from './pages/assets/CloudServices'
import { BudgetAlerts, BudgetRegister, BudgetSettings } from './pages/budget/Budgets'
import { Exceptions, History, Sla } from './pages/vuln/Others'
import VulnOverview from './pages/vuln/Overview'
import CommandCenter from './pages/executive/CommandCenter'
import HomeOverview from './pages/home/Overview'
import CloudAccounts from './pages/accounts/CloudAccounts'
import CostOverview from './pages/cost/CostOverview'
import VulnWorkspace from './pages/vuln/VulnWorkspace'
import SystemHealth from './pages/health/SystemHealth'
import AccessView from './pages/access/AccessView'
import { CostOptimization } from './pages/cost/Cost'
import Intelligence from './pages/ai/Intelligence'
import ReportLibrary from './pages/reports/Library'
import LiveActivity from './pages/activity/LiveActivity'
import AuditTrail from './pages/audit/Trail'
import Connections from './pages/connections/Connections'
import OnboardCloud from './pages/connections/OnboardCloud'
import CostAnalysis from './pages/cost/Analysis'
import BillingPeriods from './pages/cost/BillingPeriods'
import ComplianceOverview, { PolicyLibrary } from './pages/compliance/Compliance'

const V = (perm: string, el: React.ReactNode) => <AnyGuard perms={perm.split('|')}>{el}</AnyGuard>

/** Hides a page from users without the permission (the API enforces the same rule independently). */
function Guard({ perm, children }: { perm: string; children: React.ReactNode }) {
  return useCan(perm) ? <>{children}</> : <AccessDenied />
}

/** Like Guard, for pages open to several permissions (e.g. cloud engineers see only their assigned findings). */
function AnyGuard({ perms, children }: { perms: string[]; children: React.ReactNode }) {
  const me = useMe()
  return perms.some((p) => me?.permissions.includes(p)) ? <>{children}</> : <AccessDenied />
}

/** Command Center for people with organisation-wide visibility; Project Owners start at their assigned resources. */
function Home() {
  const all = useCan('inventory:read'), assigned = useCan('inventory:read_assigned')
  if (all) return <HomeOverview />
  if (assigned) return <Navigate to="/monitoring" replace />
  return <EmptyState title="No pages are available for your role">Ask an administrator for the role you need.</EmptyState>
}

/** Old links (e-mails, bookmarks) to a page that was folded into another keep their query string. */
function RedirectKeepQuery({ to, hash }: { to: string; hash?: string }) {
  const { search } = useLocation()
  return <Navigate to={`${to}${search}${hash ? `#${hash}` : ''}`} replace />
}

export default function App() {
  return (
    <FilterProvider>
      <AssistantProvider>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<Home />} />
          <Route path="executive" element={<Guard perm="inventory:read"><CommandCenter /></Guard>} />
          <Route path="accounts" element={V('inventory:read|inventory:read_assigned', <CloudAccounts />)} />
          <Route path="system-health" element={V('automation:read|inventory:read', <SystemHealth />)} />
          <Route path="dashboard" element={<Navigate to="/cost/overview" replace />} />
          <Route path="inventory/explorer" element={V('inventory:read|inventory:read_assigned', <Explorer />)} />
          <Route path="cloud-services" element={V('assets:read', <CloudServicesInventory />)} />
          <Route path="cloud-services/activity" element={V('assets:read', <CloudServicesActivity />)} />
          <Route path="cloud-services/asset" element={V('assets:read', <CloudServiceAsset />)} />
          <Route path="budgets" element={<Guard perm="budget:read"><BudgetRegister /></Guard>} />
          <Route path="budgets/requests" element={<RedirectKeepQuery to="/budgets" hash="approvals" />} />
          <Route path="budgets/alerts" element={<Guard perm="budget:read"><BudgetAlerts /></Guard>} />
          <Route path="budgets/settings" element={<Guard perm="budget:read"><BudgetSettings /></Guard>} />
          <Route path="inventory" element={<Guard perm="onboarding:read"><Onboarding /></Guard>} />
          <Route path="finops" element={<Navigate to="/cost/analysis" replace />} />
          <Route path="soc" element={<Navigate to="/audit" replace />} />
          <Route path="monitoring" element={V('infra:read|inventory:read_assigned', <Infrastructure />)} />
          <Route path="automation" element={<Guard perm="automation:read"><Automation /></Guard>} />
          <Route path="governance" element={<Guard perm="onboarding:read"><Governance /></Guard>} />
          <Route path="reports" element={<Guard perm="automation:read"><Reports /></Guard>} />
          <Route path="notifications" element={<Guard perm="inventory:read"><Notifications /></Guard>} />
          <Route path="admin/access" element={<Guard perm="admin:users"><Access /></Guard>} />
          <Route path="operations" element={<Navigate to="/executive" replace />} />
          <Route path="access" element={V('access:read', <AccessView />)} />
          <Route path="access/*" element={<Navigate to="/access" replace />} />
          <Route path="cost" element={<Navigate to="/cost/analysis" replace />} />
          <Route path="cost/overview" element={<Guard perm="finops:read"><CostOverview /></Guard>} />
          <Route path="cost/analysis" element={<Guard perm="finops:read"><CostAnalysis /></Guard>} />
          <Route path="cost/billing-periods" element={<Guard perm="finops:read"><BillingPeriods /></Guard>} />
          <Route path="activity" element={V('audit:read', <LiveActivity />)} />
          <Route path="audit/trail" element={V('audit:read|admin:users', <AuditTrail />)} />
          <Route path="connections" element={V('sync:read|onboarding:read|inventory:read', <Connections />)} />
          <Route path="connections/onboard" element={<Guard perm="onboarding:read"><OnboardCloud /></Guard>} />
          <Route path="connections/onboard/:provider" element={<Guard perm="onboarding:read"><OnboardCloud /></Guard>} />
          <Route path="cost/optimization" element={<Guard perm="finops:read"><CostOptimization /></Guard>} />
          <Route path="compliance" element={<AnyGuard perms={["onboarding:read", "reports:export"]}><ComplianceOverview /></AnyGuard>} />
          <Route path="compliance/policies" element={<AnyGuard perms={["onboarding:read", "reports:export"]}><PolicyLibrary /></AnyGuard>} />
          <Route path="ai" element={<Guard perm="ai:use"><Intelligence /></Guard>} />
          <Route path="reports/library" element={<Guard perm="reports:export"><ReportLibrary /></Guard>} />
          {/* A. Vulnerability management */}
          <Route path="vulnerabilities" element={V('vuln:read|vuln:read_assigned', <VulnWorkspace />)} />
          <Route path="vulnerabilities/overview" element={V('vuln:read|vuln:read_assigned', <VulnOverview />)} />
          <Route path="vulnerabilities/findings" element={V('vuln:read|vuln:read_assigned', <Findings key="all" title="All findings" description="Native findings from every connected cloud. Select a finding for its details, remediation guidance, history and actions." />)} />
          <Route path="vulnerabilities/aws" element={V('vuln:read|vuln:read_assigned', <Findings key="aws" provider="aws" title="AWS Security Hub findings" description="AWS Foundational Security Best Practices, CIS and other enabled standards, AWS Config controls and integrated detections, across connected accounts and regions." />)} />
          <Route path="vulnerabilities/azure" element={V('vuln:read|vuln:read_assigned', <Findings key="azure" provider="azure" title="Azure security findings" description="Azure Advisor recommendations in the Security category, by subscription and resource group. Cost, reliability, performance and operational recommendations are excluded unless you include them." />)} />
          <Route path="vulnerabilities/gcp" element={V('vuln:read|vuln:read_assigned', <Findings key="gcp" provider="gcp" title="GCP Security Command Center findings" description="Vulnerability, misconfiguration, threat and posture findings from SCC at organization, folder and project level, depending on the SCC tier and access." />)} />
          <Route path="vulnerabilities/remediation" element={V('vuln:read|vuln:read_assigned', <Findings key="rem" title="Remediation tracking" report="sla" preset={{ status: 'OPEN,UNDER_REVIEW,REOPENED', sort: 'sla_due_at', order: 'asc' }} description="Unresolved findings by due date with owners. Engineers add progress comments and evidence and request verification; analysts verify and resolve." />)} />
          <Route path="vulnerabilities/exceptions" element={V('vuln:read|exception:approve', <Exceptions />)} />
          <Route path="vulnerabilities/sla" element={V('vuln:read|vuln:read_assigned', <Sla />)} />
          <Route path="vulnerabilities/history" element={V('vuln:read', <History />)} />
          {/* B. Cloud audit operations */}
          <Route path="audit" element={V('audit:read', <AuditOverview />)} />
          <Route path="audit/activities" element={V('audit:read', <Activities key="all" title="All activities" description="The centralized audit repository: every collected event with its rule-engine classification. Normal and authorized activity stays searchable and exportable." />)} />
          <Route path="audit/aws" element={V('audit:read', <Activities key="aws" provider="aws" title="AWS CloudTrail" description="Management events (and data events where enabled) from every connected account and region." />)} />
          <Route path="audit/azure" element={V('audit:read', <Activities key="azure" provider="azure" title="Azure Activity Logs" description="Subscription and resource-level administrative operations from every connected subscription." />)} />
          <Route path="audit/gcp" element={V('audit:read', <Activities key="gcp" provider="gcp" title="GCP Cloud Audit Logs" description="Admin Activity, System Event and Policy Denied logs (Data Access where enabled) from every connected project." />)} />
          <Route path="audit/queue" element={V('audit:read', <Activities key="queue" view="queue" report="suspicious-activity" title="Investigation queue" description="Flagged activities awaiting or under investigation: detected, reviewing, investigating, escalated or reopened." />)} />
          <Route path="audit/authorized" element={V('audit:read', <Activities key="auth" view="authorized" report="authorized-activity" title="Authorized activities" description="Activities covered by an approved authorization rule or authorized by an analyst, with the approval reference." />)} />
          <Route path="audit/suspicious" element={V('audit:read', <Activities key="susp" view="suspicious" report="suspicious-activity" title="Suspicious activities" description="Rule violations and suspicious patterns. Unusual is not the same as malicious: an analyst decides." />)} />
          <Route path="audit/closed" element={V('audit:read', <Activities key="closed" view="closed" report="closed-investigations" title="Closed investigations" description="Activities closed or confirmed as needing no action, with their closure reason." />)} />
          <Route path="audit/cases" element={V('audit:read', <Cases />)} />
          <Route path="audit/rules" element={V('audit:read|audit:rules', <Rules />)} />
          {/* C. Integration & synchronization */}
          <Route path="integrations" element={V('sync:read', <IntegrationsHome />)} />
          <Route path="integrations/regions" element={V('sync:read', <RegionCoverage />)} />
          <Route path="integrations/sync" element={V('sync:read', <SyncDashboard />)} />
          <Route path="integrations/history" element={V('sync:read', <SyncHistory />)} />
          <Route path="integrations/failed" element={V('sync:read', <RegionCoverage failedOnly />)} />
          <Route path="integrations/permissions" element={V('sync:read', <Permissions />)} />
          <Route path="integrations/schedule" element={V('sync:read', <Schedule />)} />
          {/* earlier addresses keep working */}
          <Route path="infrastructure" element={<Navigate to="/monitoring" replace />} />
          <Route path="onboarding" element={<Navigate to="/inventory" replace />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
      </AssistantProvider>
    </FilterProvider>
  )
}
