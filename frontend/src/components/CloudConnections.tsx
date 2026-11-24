import { CheckCircle2, PlugZap, XCircle } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useCan } from '../auth/AuthContext'
import { useApi } from '../hooks/useApi'
import { api, type Connection, type ConnectionTest } from '../services/api'
import { Card, ErrorNote, PROVIDER_LABEL, ProviderTag, SCOPE_NOUN, StatusBadge, fmtTime } from './ui'

const input = 'h-8 w-full rounded-md border border-line bg-surface px-2 text-sm text-ink placeholder:text-ink-3 disabled:opacity-60'
const Code = ({ text }: { text: string }) => (
  <>{text.split('`').map((part, i) => (i % 2 ? <code key={i} className="rounded bg-surface-2 px-1">{part}</code> : part))}</>
)

function ConnectionPanel({ conn, canManage, onChanged }: { conn: Connection; canManage: boolean; onChanged: () => void }) {
  const [enabled, setEnabled] = useState(conn.enabled)
  const [values, setValues] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState<'' | 'save' | 'test'>('')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [test, setTest] = useState<ConnectionTest | null>(null)

  useEffect(() => {
    setEnabled(conn.enabled)
    setValues(Object.fromEntries(conn.fields.map((f) => [f.key, f.value])))
  }, [conn])

  const save = async (): Promise<boolean> => {
    setBusy('save'); setError(''); setSaved(false)
    try {
      await api.put(`/connections/${conn.provider}`, { enabled, config: values })
      setSaved(true); onChanged()
      return true
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save'); return false
    } finally { setBusy('') }
  }
  const runTest = async () => {
    setTest(null)
    if (!(await save())) return
    setBusy('test')
    try { setTest(await api.post<ConnectionTest>(`/connections/${conn.provider}/test`)); onChanged() }
    catch (e) { setError(e instanceof Error ? e.message : 'Test failed') }
    finally { setBusy('') }
  }
  const shown = test ?? (conn.last_test ? { ok: conn.last_test.ok, detail: conn.last_test.detail } : null)

  return (
    <div className="rounded-md border border-line p-3">
      <div className="flex items-center justify-between">
        <ProviderTag provider={conn.provider} />
        <StatusBadge status={conn.enabled ? 'pass' : 'unknown'} label={conn.enabled ? 'Enabled' : 'Not enabled'} />
      </div>
      <p className="mt-2 text-xs text-ink-2"><Code text={conn.sign_in} /></p>
      <div className="mt-3 space-y-2">
        {conn.fields.map((f) => (
          <label key={f.key} className="block text-xs text-ink-2">
            <span className="font-medium text-ink">{f.label}</span>{f.required && <span> (required)</span>}
            <input className={`${input} mt-1`} disabled={!canManage} type={f.kind === 'sensitive' ? 'password' : 'text'} autoComplete="off"
              value={values[f.key] ?? ''} onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
              placeholder={f.kind === 'sensitive' && f.is_set ? 'Saved. Leave blank to keep it.' : ''} />
            <span className="mt-0.5 block text-ink-3"><Code text={f.help} />{f.source === 'environment' ? ' Currently taken from .env.' : ''}</span>
          </label>
        ))}
      </div>
      {canManage ? (
        <>
          <label className="mt-3 flex items-center gap-2 text-sm">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Include {PROVIDER_LABEL[conn.provider]} {SCOPE_NOUN[conn.provider]} in discovery and scheduled jobs
          </label>
          <div className="mt-3 flex flex-wrap gap-2">
            <button onClick={save} disabled={busy !== ''} className="rounded-md bg-accent-btn px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50">{busy === 'save' ? 'Saving…' : 'Save'}</button>
            <button onClick={runTest} disabled={busy !== ''} className="inline-flex items-center gap-1 rounded-md border border-line px-3 py-1.5 text-xs hover:bg-surface-2 disabled:opacity-50">
              <PlugZap size={13} />{busy === 'test' ? 'Testing…' : 'Save and test connection'}
            </button>
          </div>
        </>
      ) : <p className="mt-3 text-xs text-ink-3">Only administrators can change connections.</p>}
      {error && <div className="mt-2"><ErrorNote message={error} /></div>}
      {saved && !error && !test && busy === '' && <p className="mt-2 text-xs text-ink-2">Saved.</p>}
      {shown && (
        <div className="mt-2 flex items-start gap-1.5 rounded-md bg-surface-2 px-2 py-1.5 text-xs">
          {shown.ok ? <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-good" /> : <XCircle size={14} className="mt-0.5 shrink-0 text-critical" />}
          <span className="break-words"><span className="font-medium">{shown.ok ? 'Connection works.' : 'Connection failed.'}</span> {shown.detail}
            {!test && conn.last_test && <span className="text-ink-3"> (tested {fmtTime(conn.last_test.at)})</span>}</span>
        </div>
      )}
    </div>
  )
}

/** Connect clouds from the dashboard. Identifiers only: no password, key or secret is entered here. */
export default function CloudConnections({ onDiscovered }: { onDiscovered: () => void }) {
  const [bump, setBump] = useState(0)
  const { data, error } = useApi<{ providers: Connection[] }>('/connections', undefined, bump)
  const canManage = useCan('connections:manage')
  const canRun = useCan('automation:run')
  const [message, setMessage] = useState('')
  const anyEnabled = data?.providers.some((p) => p.enabled) ?? false

  const discover = async () => {
    setMessage('')
    try {
      await api.post('/jobs/account_discovery/run')
      setMessage('Discovery started. Results appear below in a few moments; the run is also listed under Monitoring › Automation.')
      for (const delay of [3000, 8000, 15000]) setTimeout(onDiscovered, delay)
    } catch (e) { setMessage(e instanceof Error ? e.message : 'Could not start discovery') }
  }

  if (error) return <ErrorNote message={error.message} />
  if (!data) return null
  return (
    <Card title="Connect your clouds" subtitle="Enter each cloud's identifiers, test, then run discovery. Accounts, projects and subscriptions are then found automatically; you never add them one by one."
      action={canRun ? (
        <button onClick={discover} disabled={!anyEnabled} title={anyEnabled ? '' : 'Enable at least one cloud first'}
          className="whitespace-nowrap rounded-md bg-accent-btn px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50">Run discovery now</button>
      ) : undefined}>
      <div className="grid gap-4 lg:grid-cols-3">
        {data.providers.map((c) => <ConnectionPanel key={c.provider} conn={c} canManage={canManage} onChanged={() => setBump((b) => b + 1)} />)}
      </div>
      {message && <p className="mt-3 rounded-md bg-surface-2 px-3 py-2 text-sm">{message}</p>}
      <p className="mt-3 text-xs text-ink-3">
        Access is read-only and uses the identity signed in on the machine running the API. Passwords, access keys and client secrets are not entered or stored here.
        Where an account needs a role or permission, a task appears below for a person to approve and carry out.
      </p>
    </Card>
  )
}
