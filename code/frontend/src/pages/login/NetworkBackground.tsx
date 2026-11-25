import { useEffect, useRef } from 'react'
import { prefersReducedMotion } from '../../hooks/useMotion'

interface Node { x: number; y: number; vx: number; vy: number; r: number; hub: boolean; phase: number }

/**
 * Drifting cloud/network nodes joined by faint links. Cheap by design: at most ~70 nodes, device-pixel ratio capped
 * at 2, paused while the tab is hidden, and a single still frame when the user prefers reduced motion.
 */
export default function NetworkBackground() {
  const ref = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const canvas = ref.current!
    const ctx = canvas.getContext('2d')!
    const still = prefersReducedMotion()
    let w = 0, h = 0, raf = 0, nodes: Node[] = []
    const hubColors = ['47,85,201', '15,151,168', '138,99,216']  // provider series colours
    const resize = () => {
      const dpr = Math.min(2, window.devicePixelRatio || 1)
      w = canvas.clientWidth; h = canvas.clientHeight
      canvas.width = w * dpr; canvas.height = h * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      const count = Math.min(70, Math.round((w * h) / 22000))
      nodes = Array.from({ length: count }, (_, i) => ({
        x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - 0.5) * 0.22, vy: (Math.random() - 0.5) * 0.22,
        r: i < 3 ? 3.2 : 1 + Math.random() * 1.4, hub: i < 3, phase: Math.random() * Math.PI * 2,
      }))
    }
    const draw = (t: number) => {
      ctx.clearRect(0, 0, w, h)
      const link = Math.min(170, Math.max(110, w / 9))
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i]
        if (!still) {
          a.x += a.vx; a.y += a.vy
          if (a.x < -20) a.x = w + 20; else if (a.x > w + 20) a.x = -20
          if (a.y < -20) a.y = h + 20; else if (a.y > h + 20) a.y = -20
        }
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j], dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy
          if (d2 < link * link) {
            const k = 1 - Math.sqrt(d2) / link
            ctx.strokeStyle = `rgba(37,62,150,${(a.hub || b.hub ? 0.34 : 0.18) * k})`
            ctx.lineWidth = a.hub || b.hub ? 1 : 0.7
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke()
          }
        }
      }
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i]
        if (n.hub) {
          const pulse = still ? 1 : 0.75 + 0.25 * Math.sin(t / 1400 + n.phase)
          const g = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, 26)
          g.addColorStop(0, `rgba(${hubColors[i % 3]},${0.38 * pulse})`); g.addColorStop(1, `rgba(${hubColors[i % 3]},0)`)
          ctx.fillStyle = g; ctx.beginPath(); ctx.arc(n.x, n.y, 26, 0, Math.PI * 2); ctx.fill()
        }
        ctx.fillStyle = n.hub ? 'rgba(255,255,255,.98)' : 'rgba(47,79,174,.5)'
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2); ctx.fill()
      }
      if (!still && !document.hidden) raf = requestAnimationFrame(draw)
    }
    const onVisibility = () => { cancelAnimationFrame(raf); if (!document.hidden && !still) raf = requestAnimationFrame(draw) }
    resize(); draw(0)
    window.addEventListener('resize', resize)
    document.addEventListener('visibilitychange', onVisibility)
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize); document.removeEventListener('visibilitychange', onVisibility) }
  }, [])
  return <canvas ref={ref} className="absolute inset-0 h-full w-full" aria-hidden />
}
