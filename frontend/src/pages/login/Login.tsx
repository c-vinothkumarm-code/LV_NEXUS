import { AlertTriangle, ArrowRight, Building2, Info, LockKeyhole, ShieldCheck } from 'lucide-react'
import { lazy, Suspense, useCallback, useEffect, useState } from 'react'
import { CompanyLogo, HeroLogo, ProductLogo } from '../../components/brand/Brand'
import { api, type AuthProviders } from '../../services/api'
import { BRAND } from '../../theme/brand'
import NetworkBackground from './NetworkBackground'
import './login.css'

// three.js is loaded only here, in its own chunk; the form never waits for it
const ConnectedIntelligence = lazy(() => import('./ConnectedIntelligence'))

function webglAvailable() {
  try {
    const c = document.createElement('canvas')
    return !!(c.getContext('webgl2') || c.getContext('webgl'))
  } catch { return false }
}

const STEPS: Record<string, string[]> = {
  entra: ['Preparing a secure request', 'Opening Microsoft sign-in', 'Waiting for Microsoft Entra ID'],
  google: ['Preparing a secure request (PKCE)', 'Opening Google Workspace sign-in', 'Verifying your LatentView account'],
  dev: ['Starting a local developer session', 'Loading your workspace'],
}

/** Sign-in page. Only providers the server reports as configured are offered; every button starts a real flow. */
export default function Login({ reason }: { reason?: 'expired' | 'signed_out' | null }) {
  const [info, setInfo] = useState<AuthProviders | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState<string | null>(null)
  const [step, setStep] = useState(0)
  const [gl, setGl] = useState(() => webglAvailable())
  const [revealed, setRevealed] = useState(false)
  const [narrow, setNarrow] = useState(() => window.matchMedia('(max-width: 1023px)').matches)
  useEffect(() => {
    const m = window.matchMedia('(max-width: 1023px)')
    const on = () => setNarrow(m.matches)
    m.addEventListener('change', on)
    return () => m.removeEventListener('change', on)
  }, [])
  const onFail = useCallback(() => setGl(false), [])
  const onReady = useCallback(() => setRevealed(true), [])
  const urlCode = new URLSearchParams(window.location.search).get('error')
  // the server sends a code, never free text: the message shown comes from the server's own list
  const urlError = urlCode ? (info?.messages?.[urlCode] ?? (info ? 'Sign-in failed. Please try again.' : '')) : ''

  useEffect(() => {
    api.get<AuthProviders>('/auth/providers').then(setInfo).catch(() => setError('The LV NEXUS service is not reachable. Check that the backend is running.'))
  }, [])

  const start = (id: string, url: string) => {
    setBusy(id); setStep(0)
    const steps = STEPS[id] ?? STEPS.dev
    steps.slice(1).forEach((_, i) => setTimeout(() => setStep(i + 1), 450 * (i + 1)))
    setTimeout(() => { window.location.href = url }, 380)  // the redirect itself is immediate; the steps narrate it
  }

  const notice = reason === 'expired' ? { icon: <Info size={15} />, text: 'Your session has ended. Sign in again to continue.' }
    : reason === 'signed_out' ? { icon: <ShieldCheck size={15} />, text: 'You have signed out securely.' } : null

  return (
    <div className="cn-login2 grid min-h-screen grid-rows-[auto_1fr] lg:grid-cols-[minmax(0,1.3fr)_minmax(420px,1fr)] lg:grid-rows-1">
      <section className="cn-login-stage relative h-[230px] overflow-hidden lg:h-auto lg:min-h-screen" aria-label={`${BRAND.product}, ${BRAND.tagline}`}>
        {gl ? <Suspense fallback={null}><ConnectedIntelligence lite={narrow} onFail={onFail} onReady={onReady} /></Suspense>
          : <NetworkBackground />}
        <div className={`cn-login-focal pointer-events-none absolute inset-0 hidden place-items-center lg:grid ${revealed || !gl ? 'is-in' : ''}`}><HeroLogo /></div>
        <div className="absolute inset-x-0 bottom-0 hidden p-10 lg:block">
          <div className={`cn-login-copy max-w-xl ${revealed || !gl ? 'is-in' : ''}`}>
            <div className="text-[13px] font-semibold uppercase tracking-[.22em] text-cyan-300/90">{BRAND.product}</div>
            <h1 className="mt-2 text-[34px] font-semibold leading-tight tracking-tight text-white">{BRAND.tagline}</h1>
            <p className="mt-2 text-[15px] font-medium tracking-wide text-blue-100/85">{BRAND.pillars}</p>
            <div className="mt-6 flex items-center gap-2 text-[12px] text-blue-100/70">
              <span>Powered by</span><CompanyLogo onDark height={14} className="text-[12.5px] text-white" />
            </div>
          </div>
        </div>
      </section>

      <section className="cn-login-side flex flex-col justify-center px-5 py-8 sm:px-10" aria-labelledby="signin-title">
        <div className="cn-login-enter mx-auto w-full max-w-[420px]">
          <ProductLogo />
          {info?.demo_mode && <div role="status" className="mt-6 rounded-xl border px-3 py-2 text-xs text-ink" style={{ borderColor: 'color-mix(in srgb, var(--warning) 50%, var(--line))', background: 'color-mix(in srgb, var(--warning) 12%, transparent)' }}>
            <b>Demo mode:</b> fictional sample data on a separate demo database. No cloud is connected.</div>}
          <h2 id="signin-title" className="mt-8 text-[26px] font-semibold tracking-tight text-ink">Welcome back</h2>
          <p className="mt-1.5 text-sm text-ink-2">Secure enterprise access to {BRAND.product} for authorized {BRAND.company} corporate accounts. Sign in with your organization's identity provider.</p>

          {notice && <div className="mt-5 flex items-center gap-2 rounded-xl border border-line bg-surface-2 px-3 py-2 text-sm text-ink">{notice.icon}{notice.text}</div>}
          {(urlError || error) && <div role="alert" className="mt-5 flex items-start gap-2 rounded-xl border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-900"><AlertTriangle size={15} className="mt-0.5 shrink-0" />{error || urlError}</div>}

          <div className="mt-6 space-y-3">
            {!info && !error && <div className="cn-skeleton h-11 rounded-full" aria-busy="true" aria-label="Loading sign-in options" />}
            {info?.problem && <div role="alert" className="flex items-start gap-2 rounded-xl border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-950"><AlertTriangle size={15} className="mt-0.5 shrink-0" />{info.problem}</div>}
            {info?.providers.map((p) => (
              <button key={p.id} onClick={() => start(p.id, p.url)} disabled={busy !== null}
                className="cn-login-btn group flex h-12 w-full items-center justify-center gap-2.5 px-4 text-sm font-semibold">
                {busy === p.id ? <span className="cn-spinner" aria-hidden /> : p.id === 'dev' ? <LockKeyhole size={15} aria-hidden /> : <Building2 size={15} aria-hidden />}
                <span>{busy === p.id ? 'Signing in…' : p.label}</span>
                {busy !== p.id && <ArrowRight size={15} className="transition-transform group-hover:translate-x-0.5" aria-hidden />}
              </button>
            ))}
            {busy && (
              <div className="pt-1" aria-live="polite">
                <div className="cn-progress" />
                <ol className="mt-3 space-y-1 text-xs text-ink-2">
                  {(STEPS[busy] ?? STEPS.dev).map((s, i) => (
                    <li key={s} className={`flex items-center gap-2 transition-opacity ${i <= step ? 'opacity-100' : 'opacity-40'}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${i < step ? 'bg-emerald-600' : i === step ? 'bg-accent cn-live' : 'bg-line'}`} />{s}
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>

          {info?.mode === 'dev' && (
            <p className="mt-5 rounded-xl border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-950">
              Development mode: this signs in a local administrator without an identity provider. It is refused when APP_ENV=production.
            </p>
          )}
          <div className="mt-6 flex items-center gap-2 border-t border-line pt-4 text-xs text-ink-2">
            <ShieldCheck size={14} aria-hidden />
            Session kept in a secure, HttpOnly cookie{info ? ` for up to ${Math.round(info.session_minutes / 60)} hours` : ''}. No password or token is stored in this browser.
          </div>
          <details className="mt-4 text-xs text-ink-2">
            <summary className="cursor-pointer font-medium text-ink hover:text-accent">Security and privacy</summary>
            <ul className="mt-2 list-disc space-y-1 pl-4">
              <li>Sign-in and multi-factor authentication are handled by your identity provider; {BRAND.product} never sees your password.</li>
              <li>Access is limited to approved corporate accounts and is checked on the server for every request (role-based access control).</li>
              <li>Cloud access is read-only. Sign-ins and actions are recorded in the application audit trail.</li>
            </ul>
          </details>
        </div>
        <footer className="mx-auto mt-10 w-full max-w-[420px] text-[11px] text-ink-3">© {new Date().getFullYear()} {BRAND.company} · {BRAND.product} · {BRAND.tagline}</footer>
      </section>
    </div>
  )
}
