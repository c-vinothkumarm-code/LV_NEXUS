import { X } from 'lucide-react'
import { useEffect, useRef, type ReactNode } from 'react'

/** Accessible dialog: focus moves in, Escape and the backdrop close it, focus returns to the opener. */
export default function Modal({ title, subtitle, onClose, children, width = 720 }: { title: string; subtitle?: ReactNode; onClose: () => void; children: ReactNode; width?: number }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null
    ref.current?.querySelector<HTMLElement>('button, [href], input, select, textarea')?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
      if (e.key === 'Tab' && ref.current) {  // keep focus inside the dialog
        const els = [...ref.current.querySelectorAll<HTMLElement>('button, [href], input, select, textarea')].filter((x) => !x.hasAttribute('disabled'))
        if (!els.length) return
        const [first, last] = [els[0], els[els.length - 1]]
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus() }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
      }
    }
    document.addEventListener('keydown', onKey)
    document.body.style.overflow = 'hidden'
    return () => { document.removeEventListener('keydown', onKey); document.body.style.overflow = ''; opener?.focus() }
  }, [onClose])
  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/45 p-4 pt-[6vh] backdrop-blur-[2px]" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="cn-modal-title" className="cn-card cn-page w-full" style={{ maxWidth: width, boxShadow: 'var(--shadow-2)' }}>
        <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
          <div className="min-w-0">
            <h2 id="cn-modal-title" className="text-base font-semibold">{title}</h2>
            {subtitle && <div className="mt-0.5 text-xs text-ink-3">{subtitle}</div>}
          </div>
          <button className="cn-btn cn-btn-ghost h-8 px-2" onClick={onClose} aria-label="Close"><X size={15} /></button>
        </header>
        <div className="max-h-[75vh] overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </div>
  )
}
