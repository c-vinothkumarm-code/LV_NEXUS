import { CheckCircle2, Copy, Download, ExternalLink, Eye, EyeOff, KeyRound, Play, Plug, Power, RefreshCw, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ProviderBadge, Panel } from '../../components/hero'
import { Confirm, Pill, download, fmtDT } from '../../components/secops'
import { useToast } from '../../components/Toast'
import { ErrorNote, PageHeader, PageSkeleton, PROVIDER_NAME, SCOPE_NOUN } from '../../components/ui'
import { useApi } from '../../hooks/useApi'
import { api, type Connection, type Provider } from '../../services/api'

interface KitStep { id: string; who: string; title: string; body: string; files?: string[]; links?: { label: string; url: string }[]; ready?: boolean }
interface VerifyStep { key: string; title: string; status: 'PASS' | 'WARN' | 'FAIL'; detail: string; fix: string | null }
interface Verify { status: 'PASS' | 'WARN' | 'FAIL'; at: string; by: string; steps: VerifyStep[]; scopes_visible: number; sampled: string[] }
interface Kit {
  provider: Provider; title: string; summary: string; secret_notice: string | null; external_id: { value: string | null; is_set: boolean } | null
  steps: KitStep[]; connection: Connection; inputs: { key: string; label: string; help: string; required: boolean; value: string }[]
  files: { name: string; label: string }[]; last_verify: Verify | null; activated_at: string | null; can_manage: boolean
}
interface Overview { providers: { provider: Provider; enabled: boolean; last_verify: { status: string; at: string; scopes_visible: number } | null; activated_at: string | null }[] }

const ORDER: Provider[] = ['aws', 'azure', 'gcp']
const TONE = { PASS: 'APPROVED', WARN: 'High', FAIL: 'Critical' } as const
const field = 'cn-input mt-1 h-8 w-full rounded-md px-2 text-sm text-ink disabled:opacity-60'
const isSafeUrl = (u: string) => /^https:\/\/[a-z0-9.-]+\.(amazon\.com|amazonaws\.com|microsoft\.com|microsoftonline\.com|azure\.com|cloud\.google\.com)(\/|$|\?|#)/i.test(u)

/** Guided, read-only onboarding of a cloud: identifiers -> generated kit for the cloud administrator -> live verification -> switch on. */
export default function OnboardCloud() {
  const params = useParams()
  const nav = useNavigate()
  const provider = (ORDER.includes(params.provider as Provider) ? params.provider : 'aws') as Provider
  const [bump, setBump] = useState(0)
  const ov = useApi<Overview>('/onboarding/wizard', undefined, bump)
  const kit = useApi<Kit>(`/onboarding/wizard/${provider}`, undefined, bump)
  const reload = () => setBump((b) => b + 1)

  return (
    <>
      <PageHeader eyebrow="Integrations" title="Onboard a cloud"
        description="Connect an AWS organization, an Azure tenant or a Google Cloud organization once, at the top level. LV NEXUS generates the read-only access kit for your cloud administrator, verifies the result live and only then switches the cloud on. New accounts, subscriptions and projects are then covered automatically." />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3" role="tablist" aria-label="Cloud">
        {ORDER.map((p) => {
          const o = ov.data?.providers.find((x) => x.provider === p)
          return (
            <button key={p} role="tab" aria-selected={p === provider} onClick={() => nav(`/connections/onboard/${p}`)}
              className={`cn-card cn-lift flex items-center gap-3 px-4 py-3 text-left ${p === provider ? 'ring-2 ring-[var(--accent)]' : ''}`}>
              <ProviderBadge provider={p} />
              <div className="min-w-0">
                <div className="text-sm font-semibold">{PROVIDER_NAME[p]}</div>
                <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-ink-3">
                  <Pill value={o?.enabled ? 'APPROVED' : 'NOT_CONFIGURED'} text={o?.enabled ? 'Connected' : 'Not connected'} />
                  {o?.last_verify && <Pill value={TONE[o.last_verify.status as keyof typeof TONE]} text={`Verified ${o.last_verify.status} · ${fmtDT(o.last_verify.at)}`} />}
                </div>
              </div>
            </button>
          )
        })}
      </div>
      {kit.error ? <ErrorNote message={kit.error.message} onRetry={reload} /> : !kit.data ? <PageSkeleton tiles={2} /> :
        <Wizard key={provider} kit={kit.data} onChanged={reload} />}
    </>
  )
}

function Wizard({ kit, onChanged }: { kit: Kit; onChanged: () => void }) {
  const toast = useToast()
  const p = kit.provider
  const [cfg, setCfg] = useState<Record<string, string>>({})
  const [inp, setInp] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState('')
  const [verify, setVerify] = useState<Verify | null>(kit.last_verify)
  const [rotate, setRotate] = useState(false)
  const [showId, setShowId] = useState(false)

  useEffect(() => {
    setCfg(Object.fromEntries(kit.connection.fields.filter((f) => f.kind !== 'sensitive').map((f) => [f.key, f.value])))
    setInp(Object.fromEntries(kit.inputs.map((i) => [i.key, i.value])))
    setVerify(kit.last_verify)
  }, [kit])

  const act = async (name: string, fn: () => Promise<unknown>, ok?: string) => {
    setBusy(name)
    try { await fn(); if (ok) toast({ kind: 'success', title: ok }); onChanged() }
    catch (e) { toast({ kind: 'error', title: 'Not done', text: e instanceof Error ? e.message : 'Unknown error' }) }
    finally { setBusy('') }
  }
  const save = () => act('save', () => api.put(`/onboarding/wizard/${p}/inputs`, { config: cfg, inputs: inp }), 'Details saved')
  const runVerify = () => act('verify', async () => { setVerify(await api.post<Verify>(`/onboarding/wizard/${p}/verify`)) })
  const activate = () => act('activate', () => api.post(`/onboarding/wizard/${p}/activate`), `${PROVIDER_NAME[p]} connected. Discovery started.`)
  const fetchFile = (name: string) => download(`/api/v1/onboarding/wizard/${p}/files/${encodeURIComponent(name)}`)
    .catch((e) => toast({ kind: 'error', title: 'Download failed', text: e.message }))
  const fileLabel = (n: string) => kit.files.find((f) => f.name === n)?.label ?? n
  const ro = !kit.can_manage
  const required = [...kit.connection.fields.filter((f) => f.required && !f.is_set).map((f) => f.label), ...kit.inputs.filter((i) => i.required && !i.value).map((i) => i.label)]

  return (
    <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
      <div className="min-w-0 space-y-4">
        <Panel icon={<Plug size={15} />} title={`1. ${kit.title}: your identifiers`} subtitle={kit.summary}>
          {kit.secret_notice && <p className="mb-3 text-xs text-ink-3">{kit.secret_notice}</p>}
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {kit.connection.fields.filter((f) => f.kind !== 'sensitive').map((f) => (
              <label key={f.key} className="block text-xs text-ink-2"><span className="font-medium text-ink">{f.label}</span>{f.required && ' (required)'}
                <input className={field} disabled={ro} value={cfg[f.key] ?? ''} onChange={(e) => setCfg({ ...cfg, [f.key]: e.target.value })} autoComplete="off" />
                <span className="mt-0.5 block text-ink-3">{f.help}{f.source === 'environment' ? ' Currently taken from the server settings.' : ''}</span></label>))}
            {kit.inputs.map((i) => (
              <label key={i.key} className="block text-xs text-ink-2"><span className="font-medium text-ink">{i.label}</span>{i.required && ' (required)'}
                <input className={field} disabled={ro} value={inp[i.key] ?? ''} onChange={(e) => setInp({ ...inp, [i.key]: e.target.value })} autoComplete="off" />
                <span className="mt-0.5 block text-ink-3">{i.help}</span></label>))}
          </div>
          {kit.external_id && (
            <div className="mt-4 rounded-md border border-line p-3 text-xs">
              <div className="flex items-center gap-2 font-medium text-ink"><KeyRound size={14} aria-hidden />External ID</div>
              <p className="mt-1 text-ink-3">A random value that only LV NEXUS and your member roles know, so no other party can use the role (confused-deputy protection). Shown to connection managers only; never logged.</p>
              {kit.external_id.is_set ? (
                kit.external_id.value ? (
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <code className="rounded bg-surface-2 px-2 py-1 font-mono">{showId ? kit.external_id.value : '•'.repeat(24)}</code>
                    <button className="cn-btn cn-btn-ghost h-7 text-xs" onClick={() => setShowId(!showId)}>{showId ? <EyeOff size={13} /> : <Eye size={13} />}{showId ? 'Hide' : 'Show'}</button>
                    <button className="cn-btn cn-btn-ghost h-7 text-xs" onClick={() => navigator.clipboard.writeText(kit.external_id!.value!).then(() => toast({ kind: 'success', title: 'Copied' }))}><Copy size={13} />Copy</button>
                    <button className="cn-btn cn-btn-ghost h-7 text-xs" onClick={() => setRotate(true)}><RefreshCw size={13} />Rotate</button>
                  </div>) : <p className="mt-2 text-ink-2">Set.</p>
              ) : !ro && <button className="cn-btn cn-btn-primary mt-2 h-8 text-xs" disabled={busy === 'ext'} onClick={() => act('ext', () => api.post('/onboarding/wizard/aws/external-id', {}), 'External ID created')}>Generate external ID</button>}
            </div>)}
          {!ro && <div className="mt-4 flex items-center gap-3">
            <button className="cn-btn cn-btn-primary" disabled={busy === 'save'} onClick={save}>{busy === 'save' ? 'Saving…' : 'Save details'}</button>
            {required.length > 0 && <span className="text-xs text-ink-3">Still needed: {required.join(', ')}</span>}
          </div>}
        </Panel>

        {kit.steps.map((s, i) => (
          <Panel key={s.id} icon={<ShieldCheck size={15} />} title={`${i + 2}. ${s.title}`} subtitle={<span className="text-[11px]">Done by: <b>{s.who}</b></span>}
            action={s.ready === false ? <Pill value="PENDING" text="Waiting for the stack outputs" /> : undefined}>
            <p className="text-sm text-ink-2">{s.body}</p>
            {(s.files?.length || s.links?.length) ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {s.files?.map((f) => <button key={f} className="cn-btn cn-btn-ghost h-auto min-h-8 whitespace-normal py-1.5 text-left text-xs" disabled={ro} title={ro ? 'Connection managers only' : f} onClick={() => fetchFile(f)}><Download size={13} />{fileLabel(f)}</button>)}
                {s.links?.filter((l) => isSafeUrl(l.url)).map((l) => <a key={l.url} className="cn-btn cn-btn-ghost h-auto min-h-8 whitespace-normal py-1.5 text-left text-xs" href={l.url} target="_blank" rel="noopener noreferrer"><ExternalLink size={13} />{l.label}</a>)}
              </div>) : null}
          </Panel>))}

        <Panel icon={<CheckCircle2 size={15} />} title={`${kit.steps.length + 2}. Verify and connect`}
          subtitle="Read-only checks with the same code the scheduled collection uses: settings, server credential, sign-in and discovery, and read access on a sample of scopes.">
          <div className="flex flex-wrap items-center gap-3">
            <button className="cn-btn cn-btn-primary" disabled={ro || busy === 'verify'} onClick={runVerify}><Play size={14} />{busy === 'verify' ? 'Verifying… (up to a minute)' : 'Run verification'}</button>
            <button className="cn-btn" disabled={ro || busy === 'activate' || !verify || verify.status === 'FAIL' || kit.connection.enabled} onClick={activate}
              title={verify?.status === 'FAIL' ? 'Fix the failed checks first' : undefined}><Power size={14} />{kit.connection.enabled ? 'Connected' : 'Connect and start discovery'}</button>
            {kit.activated_at && <span className="text-xs text-ink-3">Connected {fmtDT(kit.activated_at)}</span>}
          </div>
          {verify && (
            <div className="mt-4">
              <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-ink-3">
                <Pill value={TONE[verify.status]} text={`Result: ${verify.status}`} /> {fmtDT(verify.at)} by {verify.by} · {verify.scopes_visible} {SCOPE_NOUN[p]} visible
                {verify.status === 'WARN' && <span>· warnings do not block connecting; fix them for full coverage</span>}
              </div>
              <div className="overflow-x-auto"><table className="w-full min-w-[560px] text-left text-xs">
                <thead><tr className="border-b border-line text-ink-3">{['Check', 'Result', 'Detail', 'How to fix'].map((h) => <th key={h} className="px-1 py-1">{h}</th>)}</tr></thead>
                <tbody>{verify.steps.map((s) => (
                  <tr key={s.key} className="border-b border-line/60 align-top"><td className="px-1 py-1.5 font-medium">{s.title}</td>
                    <td className="px-1 py-1.5"><Pill value={TONE[s.status]} text={s.status} /></td><td className="px-1 py-1.5 text-ink-2">{s.detail}</td>
                    <td className="px-1 py-1.5 text-ink-2">{s.fix ?? '—'}</td></tr>))}</tbody>
              </table></div>
            </div>)}
        </Panel>
      </div>

      <aside className="min-w-0 space-y-4">
        <Panel icon={<ShieldCheck size={15} />} title="Security model">
          <ul className="list-disc space-y-1.5 pl-4 text-xs text-ink-2">
            <li>Read-only. LV NEXUS never writes, changes or deletes anything in your cloud, and never grants itself access.</li>
            <li>No stored passwords or access keys: {p === 'aws' ? 'IAM Roles Anywhere issues 1-hour credentials from the server certificate' : p === 'azure' ? 'the app signs in with a certificate; no client secret' : 'workload identity federation; no service-account key'}.</li>
            <li>The private key is created on the LV NEXUS server and never leaves it.</li>
            <li>Granted once at the top level, so new {SCOPE_NOUN[p]} are covered automatically.</li>
            {p === 'aws' && <li>Explicit deny on reading data content and secrets (S3 objects, secret values, parameters, KMS decrypt, database items); optional restriction to the server IP.</li>}
            <li>Your administrator deploys the kit through your change process; removing the role / assignment / binding cuts access immediately.</li>
            <li>Every action on this page is recorded in the audit log.</li>
          </ul>
        </Panel>
        <Panel icon={<Plug size={15} />} title="Current connection">
          <div className="space-y-1 text-xs text-ink-2">
            <div>Status: <Pill value={kit.connection.enabled ? 'APPROVED' : 'NOT_CONFIGURED'} text={kit.connection.enabled ? 'Connected' : 'Not connected'} /></div>
            {kit.connection.last_test && <div>Last test: {fmtDT(kit.connection.last_test.at)} · {kit.connection.last_test.ok ? 'OK' : 'failed'}</div>}
            {kit.connection.updated_by && <div>Last changed by {kit.connection.updated_by}</div>}
          </div>
        </Panel>
      </aside>

      {rotate && <Confirm title="Rotate the external ID?" confirm="Rotate"
        body="A new external ID is created. Every member role must then be updated with it through the StackSet (download the AWS script again and update the StackSet parameter). Until then, AWS collection stops for those accounts."
        onCancel={() => setRotate(false)}
        onConfirm={() => { setRotate(false); act('ext', () => api.post('/onboarding/wizard/aws/external-id', { rotate: true }), 'External ID rotated') }} />}
    </div>
  )
}
