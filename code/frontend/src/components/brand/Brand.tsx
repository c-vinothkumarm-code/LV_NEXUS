import { useEffect, useId, useState } from 'react'
import { BRAND } from '../../theme/brand'

/** LV NEXUS product mark (stand-in until the official LV NEXUS logo file is supplied): a hub joined to three cloud nodes. Original artwork for this product, not the LatentView logo. */
export function ProductMark({ size = 28, title = BRAND.fullName }: { size?: number; title?: string }) {
  const gid = `cn-mark-${useId().replace(/[^a-zA-Z0-9-]/g, '')}`  // unique per instance: a hidden copy must not own the gradient
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" role="img" aria-label={title}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--brand-blue)" />
          <stop offset="1" stopColor="var(--brand-teal)" />
        </linearGradient>
      </defs>
      <rect x="1" y="1" width="30" height="30" rx="8" fill={`url(#${gid})`} />
      <g stroke="#fff" strokeWidth="1.6" strokeLinecap="round" opacity=".9">
        <line x1="16" y1="16.5" x2="16" y2="8" />
        <line x1="16" y1="16.5" x2="8.6" y2="21" />
        <line x1="16" y1="16.5" x2="23.4" y2="21" />
      </g>
      <circle cx="16" cy="16.5" r="3.4" fill="#fff" />
      <circle cx="16" cy="7.6" r="2.3" fill="#fff" opacity=".92" />
      <circle cx="8.3" cy="21.4" r="2.3" fill="#fff" opacity=".92" />
      <circle cx="23.7" cy="21.4" r="2.3" fill="#fff" opacity=".92" />
    </svg>
  )
}

/** Shows the official LatentView logo file when it has been added to /public/brand, otherwise the plain name. */
export function CompanyLogo({ onDark = false, height = 16, className = '' }: { onDark?: boolean; height?: number; className?: string }) {
  const [failed, setFailed] = useState(false)
  if (failed) return <span className={`font-semibold tracking-wide ${className}`}>{BRAND.company}</span>
  return <img src={onDark ? BRAND.companyLogoOnDark : BRAND.companyLogo} alt={BRAND.company} height={height} style={{ height }} className={className} onError={() => setFailed(true)} />
}

function useIsDark() {
  const [dark, setDark] = useState(() => document.documentElement.dataset.theme === 'dark')
  useEffect(() => {
    const on = () => setDark(document.documentElement.dataset.theme === 'dark')
    window.addEventListener('cn-theme-change', on)
    return () => window.removeEventListener('cn-theme-change', on)
  }, [])
  return dark
}

/** LV NEXUS identity for the shell: the official LV NEXUS logo file when supplied in /public/brand, otherwise the product
 *  mark with the name set in text. The LatentView Analytics company line uses the official company logo file when present. */
export function ProductLogo({ compact = false, onDark }: { compact?: boolean; onDark?: boolean }) {
  const themeDark = useIsDark()
  const dark = onDark ?? themeDark
  const [official, setOfficial] = useState(true)
  if (official && !compact) {
    return <img src={dark ? BRAND.productLogoOnDark : BRAND.productLogo} alt={BRAND.product} style={{ height: 34, width: 'auto' }} onError={() => setOfficial(false)} />
  }
  return (
    <div className="flex min-w-0 items-center gap-2.5">
      <ProductMark size={compact ? 30 : 32} title={BRAND.product} />
      {!compact && (
        <div className="min-w-0 leading-none">
          <div className="cn-side-brand-name text-[16px] font-bold tracking-[.04em]">LV <span style={{ color: 'var(--accent)' }}>NEXUS</span></div>
          <div className="cn-side-brand-sub mt-1 truncate text-[9.5px] font-semibold uppercase tracking-[.14em]"><CompanyLogo onDark={dark} height={10} /></div>
        </div>
      )}
    </div>
  )
}

/** Large centred identity for the sign-in scene: the official LV NEXUS logo file when present (aspect ratio kept),
 *  otherwise the product mark and the name in text. Never a drawn approximation of the official logo. */
export function HeroLogo() {
  const [official, setOfficial] = useState(true)
  if (official) return <img src={BRAND.productLogoOnDark} alt={BRAND.product} style={{ height: 76, width: 'auto', maxWidth: '70%' }} onError={() => setOfficial(false)} />
  return (
    <div className="flex flex-col items-center gap-3">
      <ProductMark size={68} title={BRAND.product} />
      <div className="text-[34px] font-bold leading-none tracking-[.08em] text-white">LV <span style={{ color: 'var(--brand-cyan)' }}>NEXUS</span></div>
    </div>
  )
}

export function Wordmark({ onDark = false, compact = false }: { onDark?: boolean; compact?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <ProductMark size={compact ? 30 : 32} />
      {!compact && (
        <div className="leading-tight">
          <div className={`text-[11px] uppercase tracking-[.14em] ${onDark ? 'text-white/70' : 'text-ink-3'}`}><CompanyLogo onDark={onDark} height={11} /></div>
          <div className={`text-[17px] font-bold tracking-[.04em] ${onDark ? 'text-white' : 'text-ink'}`} style={{ fontFamily: 'var(--font-display)' }}>
            LV <span style={{ color: onDark ? 'var(--brand-cyan)' : 'var(--accent)' }}>NEXUS</span>
          </div>
        </div>
      )}
    </div>
  )
}
