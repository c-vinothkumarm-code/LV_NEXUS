import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react'
import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'

type Kind = 'success' | 'error' | 'warning' | 'info'
interface Toast { id: number; kind: Kind; title: string; text?: string }
const Ctx = createContext<(t: Omit<Toast, 'id'>) => void>(() => {})
export const useToast = () => useContext(Ctx)

const ICON = { success: CheckCircle2, error: XCircle, warning: AlertTriangle, info: Info }
const TONE = { success: 'text-good', error: 'text-critical', warning: 'text-warning', info: 'text-accent' }

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([])
  const dismiss = (id: number) => setItems((xs) => xs.filter((x) => x.id !== id))
  const push = useCallback((t: Omit<Toast, 'id'>) => {
    const id = Date.now() + Math.random()
    setItems((xs) => [...xs.slice(-3), { ...t, id }])
    setTimeout(() => dismiss(id), t.kind === 'error' ? 9000 : 5000)
  }, [])
  return (
    <Ctx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2" role="status" aria-live="polite">
        {items.map((t) => {
          const Icon = ICON[t.kind]
          return (
            <div key={t.id} className="cn-toast cn-card pointer-events-auto flex items-start gap-2.5 px-3.5 py-3" style={{ boxShadow: 'var(--shadow-2)' }}>
              <Icon size={18} className={`mt-0.5 shrink-0 ${TONE[t.kind]}`} aria-hidden />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold">{t.title}</div>
                {t.text && <div className="mt-0.5 break-words text-xs text-ink-2">{t.text}</div>}
              </div>
              <button className="rounded p-0.5 text-ink-3 hover:text-ink" onClick={() => dismiss(t.id)} aria-label="Dismiss notification"><X size={14} /></button>
            </div>
          )
        })}
      </div>
    </Ctx.Provider>
  )
}
