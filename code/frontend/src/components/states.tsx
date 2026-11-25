import { ArrowLeft, Compass, Home, LockKeyhole } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'

/** Full-page states with a clear way forward: back to the previous page, or home. */
function StatePage({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  const nav = useNavigate()
  return (
    <section className="cn-card mx-auto mt-10 max-w-xl p-8 text-center" role="alert">
      <div className="mx-auto mb-4 grid h-14 w-14 place-items-center rounded-2xl bg-surface-2 text-accent">{icon}</div>
      <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
      <div className="mt-2 text-sm text-ink-3">{children}</div>
      <div className="mt-6 flex justify-center gap-2">
        <button type="button" className="cn-btn cn-btn-ghost" onClick={() => nav(-1)}><ArrowLeft size={14} aria-hidden />Go back</button>
        <Link to="/" className="cn-btn cn-btn-primary"><Home size={14} aria-hidden />Home</Link>
      </div>
    </section>
  )
}

export function NotFound() {
  return <StatePage icon={<Compass size={26} aria-hidden />} title="Page not found">This address does not exist or has moved. Use Back, Home or the navigation on the left.</StatePage>
}

export function AccessDenied({ what = 'this page' }: { what?: string }) {
  return <StatePage icon={<LockKeyhole size={26} aria-hidden />} title="You do not have access">Your role does not include {what}. Ask an administrator (Administration → Users and roles) for the role that grants it.</StatePage>
}
