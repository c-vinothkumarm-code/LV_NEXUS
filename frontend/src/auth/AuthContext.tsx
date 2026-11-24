import { createContext, useRef, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { ProductMark } from '../components/brand/Brand'
import { useToast } from '../components/Toast'
import Login from '../pages/login/Login'
import { api, ApiError, type Me } from '../services/api'
import { BRAND } from '../theme/brand'

interface AuthState { me: Me; signOut: () => Promise<void> }
const Ctx = createContext<AuthState | null>(null)
export const useAuth = () => useContext(Ctx)
export const useMe = () => useContext(Ctx)?.me ?? null
export const useCan = (permission: string) => useMe()?.permissions.includes(permission) ?? false

type Status = { kind: 'loading' } | { kind: 'in'; me: Me } | { kind: 'out'; reason: 'expired' | 'signed_out' | null } | { kind: 'down'; message: string }

function Splash({ text }: { text: string }) {
  return (
    <div className="grid h-screen place-items-center" style={{ background: 'var(--page-gradient), var(--page)' }}>
      <div className="flex w-64 flex-col items-center gap-4 text-center" aria-busy="true">
        <ProductMark size={44} />
        <div className="text-sm font-semibold">{BRAND.fullName}</div>
        <div className="w-full overflow-hidden rounded-full" style={{ background: 'var(--surface-3)' }}><div className="cn-progress" style={{ background: 'transparent' }} /></div>
        <div className="text-xs text-ink-3">{text}</div>
      </div>
    </div>
  )
}

/** Session lives only in the server's HttpOnly cookie. The browser keeps no token; it only asks "who am I?". */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>({ kind: 'loading' })
  const toast = useToast()

  const load = useCallback(async () => {
    try {
      setStatus({ kind: 'in', me: await api.get<Me>('/auth/me') })
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setStatus({ kind: 'out', reason: null })
      else setStatus({ kind: 'down', message: e instanceof Error ? e.message : 'Cannot reach the API' })
    }
  }, [])

  useEffect(() => { void load() }, [load])

  useEffect(() => {  // any API call answered 401 = the session ended
    const onExpired = () => setStatus((s) => (s.kind === 'in' ? { kind: 'out', reason: 'expired' } : s))
    window.addEventListener('cloudnexus:unauthorized', onExpired)
    return () => window.removeEventListener('cloudnexus:unauthorized', onExpired)
  }, [])

  // Renewal: while the person is active, the session is renewed (with a new session ID) shortly before it ends.
  // The server refuses renewal past the absolute sign-in limit; then a warning is shown and sign-in is required.
  const lastActive = useRef(Date.now())
  useEffect(() => {
    const mark = () => { lastActive.current = Date.now() }
    window.addEventListener('pointerdown', mark); window.addEventListener('keydown', mark)
    return () => { window.removeEventListener('pointerdown', mark); window.removeEventListener('keydown', mark) }
  }, [])

  useEffect(() => {
    if (status.kind !== 'in' || !status.me.session_expires_at) return
    const left = new Date(status.me.session_expires_at).getTime() - Date.now()
    const renewAt = Math.max(0, left - 10 * 60_000)
    const timers = [
      setTimeout(async () => {
        if (Date.now() - lastActive.current > 15 * 60_000) return  // idle: let the session end
        try { await api.post('/auth/renew'); setStatus({ kind: 'in', me: await api.get<Me>('/auth/me') }) }
        catch { toast({ kind: 'warning', title: 'Session ends soon', text: 'The maximum session length has been reached. Save your work; you will need to sign in again.' }) }
      }, renewAt),
      setTimeout(() => setStatus({ kind: 'out', reason: 'expired' }), Math.max(0, left)),
    ]
    return () => timers.forEach(clearTimeout)
  }, [status, toast])

  const signOut = useCallback(async () => {
    try { await api.post('/auth/logout') } finally { setStatus({ kind: 'out', reason: 'signed_out' }) }
  }, [])

  if (status.kind === 'loading') return <Splash text="Verifying your session…" />
  if (status.kind === 'out') return <Login reason={status.reason} />
  if (status.kind === 'down') {
    return (
      <div className="grid h-screen place-items-center px-6 text-center">
        <div className="max-w-md">
          <ProductMark size={40} />
          <h1 className="mt-4 text-lg font-semibold">The Command Center service is not reachable</h1>
          <p className="mt-1 text-sm text-ink-2">{status.message}. Check that the API is running, then try again.</p>
          <button className="cn-btn cn-btn-primary mt-4" onClick={() => { setStatus({ kind: 'loading' }); void load() }}>Try again</button>
        </div>
      </div>
    )
  }
  return <Ctx.Provider value={{ me: status.me, signOut }}>{children}</Ctx.Provider>
}
