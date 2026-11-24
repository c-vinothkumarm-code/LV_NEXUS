export const VULN_TABS = [
  { to: '/vulnerabilities', label: 'Overview' }, { to: '/vulnerabilities/overview', label: 'Posture analytics' }, { to: '/vulnerabilities/findings', label: 'All findings' },
  { to: '/vulnerabilities/aws', label: 'AWS Security Hub' }, { to: '/vulnerabilities/azure', label: 'Azure Advisor' }, { to: '/vulnerabilities/gcp', label: 'GCP SCC' },
  { to: '/vulnerabilities/exceptions', label: 'Exceptions' }, { to: '/vulnerabilities/remediation', label: 'Remediation' },
  { to: '/vulnerabilities/sla', label: 'SLA monitoring' }, { to: '/vulnerabilities/history', label: 'Finding history' },
]
export const AUDIT_TABS = [
  { to: '/audit', label: 'Audit overview' }, { to: '/audit/activities', label: 'All activities' }, { to: '/audit/aws', label: 'AWS CloudTrail' },
  { to: '/audit/azure', label: 'Azure Activity Logs' }, { to: '/audit/gcp', label: 'GCP Audit Logs' }, { to: '/audit/queue', label: 'Investigation queue' },
  { to: '/audit/authorized', label: 'Authorized' }, { to: '/audit/suspicious', label: 'Suspicious' }, { to: '/audit/closed', label: 'Closed' },
  { to: '/audit/cases', label: 'Investigation history' }, { to: '/audit/rules', label: 'Detection rules' },
]
export const INTEG_TABS = [
  { to: '/integrations', label: 'Cloud integrations' }, { to: '/inventory', label: 'Account discovery' }, { to: '/integrations/regions', label: 'Region coverage' },
  { to: '/integrations/sync', label: 'Synchronization' }, { to: '/integrations/history', label: 'Sync history' }, { to: '/integrations/failed', label: 'Failed jobs' },
  { to: '/integrations/permissions', label: 'Permissions' }, { to: '/integrations/schedule', label: 'Schedule' },
]
