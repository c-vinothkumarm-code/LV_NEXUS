import { useEffect, useRef, useState } from 'react'

export function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
}

/** Eases a number from its previous value to `target`. Data is never delayed: with reduced motion it jumps at once. */
export function useCountUp(target: number | null | undefined, duration = 650): number | null {
  const [value, setValue] = useState<number | null>(target ?? null)
  const from = useRef(0)
  useEffect(() => {
    if (target === null || target === undefined) { setValue(null); return }
    if (prefersReducedMotion() || !Number.isFinite(target)) { setValue(target); from.current = target; return }
    const start = performance.now(), a = from.current, b = target
    let raf = 0
    const tick = (t: number) => {
      const k = Math.min(1, (t - start) / duration), e = 1 - Math.pow(1 - k, 3)
      setValue(a + (b - a) * e)
      if (k < 1) raf = requestAnimationFrame(tick)
      else from.current = b
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])
  return value
}
