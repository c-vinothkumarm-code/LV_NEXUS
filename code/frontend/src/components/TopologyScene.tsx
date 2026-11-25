import { useEffect, useRef, useState } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'
import { prefersReducedMotion } from '../hooks/useMotion'

export interface TopoNode {
  id: string; parent: string | null; level: number; label: string; provider: 'aws' | 'azure' | 'gcp'
  alert: 'critical' | 'high' | null; detail: string
}

const PROVIDER_HEX: Record<string, string> = { azure: '#4f7cf0', aws: '#14b8c8', gcp: '#9277e8' }
const RADIUS = [1.6, 3.4, 5.2, 6.9]
const SIZE = [0.9, 0.55, 0.42, 0.26]

/**
 * 3D view of the collected hierarchy (cloud -> organization / management group / folder -> account / subscription /
 * project -> region / resource group). Only relationships returned by the API are drawn; positions are a layout, not
 * geography. Drag to rotate, scroll to zoom, click a node to open it. Rendering pauses when hidden or off screen.
 */
export default function TopologyScene({ nodes, selected, onSelect, onFail }: {
  nodes: TopoNode[]; selected?: string | null; onSelect: (id: string) => void; onFail: () => void
}) {
  const host = useRef<HTMLDivElement>(null)
  const [hover, setHover] = useState<{ x: number; y: number; n: TopoNode } | null>(null)
  const selRef = useRef<string | null | undefined>(selected)
  selRef.current = selected

  useEffect(() => {
    const el = host.current!
    let renderer: THREE.WebGLRenderer
    try { renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'low-power' }) } catch { onFail(); return }
    renderer.setPixelRatio(Math.min(1.75, window.devicePixelRatio || 1))
    el.appendChild(renderer.domElement)
    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 200)
    camera.position.set(0, 6, 15)
    const controls = new OrbitControls(camera, renderer.domElement)
    controls.enableDamping = true
    controls.minDistance = 5; controls.maxDistance = 60
    controls.autoRotate = !prefersReducedMotion()
    controls.autoRotateSpeed = 0.35

    // radial layout: each cloud owns a sector; leaves spread evenly, parents sit at the mean angle of their children
    const byId = new Map(nodes.map((n) => [n.id, n]))
    const kids = new Map<string, TopoNode[]>()
    nodes.forEach((n) => { if (n.parent && byId.has(n.parent)) kids.set(n.parent, [...(kids.get(n.parent) ?? []), n]) })
    const roots = nodes.filter((n) => !n.parent || !byId.has(n.parent))
    const leaves = (n: TopoNode): number => (kids.get(n.id)?.length ? kids.get(n.id)!.reduce((a, c) => a + leaves(c), 0) : 1)
    const angle = new Map<string, number>()
    const place = (n: TopoNode, a0: number, a1: number) => {
      const ch = kids.get(n.id) ?? []
      if (!ch.length) { angle.set(n.id, (a0 + a1) / 2); return }
      const total = ch.reduce((a, c) => a + leaves(c), 0)
      let a = a0
      ch.forEach((c) => { const w = ((a1 - a0) * leaves(c)) / total; place(c, a, a + w); a += w })
      angle.set(n.id, ch.reduce((s, c) => s + angle.get(c.id)!, 0) / ch.length)
    }
    const totalLeaves = roots.reduce((a, r) => a + leaves(r), 0) || 1
    let a = 0
    roots.forEach((r) => { const w = (Math.PI * 2 * leaves(r)) / totalLeaves; place(r, a + 0.04, a + w - 0.04); a += w })
    const pos = new Map<string, THREE.Vector3>()
    nodes.forEach((n, i) => {
      const r = RADIUS[Math.min(n.level, 3)], th = angle.get(n.id) ?? 0
      const lift = n.level === 0 ? 0 : ((i % 7) - 3) * 0.32 * (n.level / 3)
      pos.set(n.id, new THREE.Vector3(Math.cos(th) * r, lift, Math.sin(th) * r))
    })

    const spriteC = document.createElement('canvas'); spriteC.width = spriteC.height = 64
    const g = spriteC.getContext('2d')!, gr = g.createRadialGradient(32, 32, 0, 32, 32, 32)
    gr.addColorStop(0, 'rgba(255,255,255,1)'); gr.addColorStop(0.45, 'rgba(255,255,255,.9)'); gr.addColorStop(1, 'rgba(255,255,255,0)')
    g.fillStyle = gr; g.fillRect(0, 0, 64, 64)
    const sprite = new THREE.CanvasTexture(spriteC)

    const groups: { points: THREE.Points; list: TopoNode[] }[] = []
    for (let lvl = 0; lvl <= 3; lvl++) {
      const list = nodes.filter((n) => Math.min(n.level, 3) === lvl)
      if (!list.length) continue
      const p = new Float32Array(list.length * 3), c = new Float32Array(list.length * 3)
      list.forEach((n, i) => {
        const v = pos.get(n.id)!; p.set([v.x, v.y, v.z], i * 3)
        const col = new THREE.Color(n.alert === 'critical' ? '#ef4444' : n.alert === 'high' ? '#f97316' : PROVIDER_HEX[n.provider])
        c.set([col.r, col.g, col.b], i * 3)
      })
      const geo = new THREE.BufferGeometry()
      geo.setAttribute('position', new THREE.BufferAttribute(p, 3)); geo.setAttribute('color', new THREE.BufferAttribute(c, 3))
      const pts = new THREE.Points(geo, new THREE.PointsMaterial({ size: SIZE[lvl], map: sprite, vertexColors: true, transparent: true, depthWrite: false, alphaTest: 0.05 }))
      scene.add(pts); groups.push({ points: pts, list })
    }
    const lp: number[] = []
    nodes.forEach((n) => { if (n.parent && pos.has(n.parent)) { const a1 = pos.get(n.parent)!, b1 = pos.get(n.id)!; lp.push(a1.x, a1.y, a1.z, b1.x, b1.y, b1.z) } })
    const lgeo = new THREE.BufferGeometry(); lgeo.setAttribute('position', new THREE.Float32BufferAttribute(lp, 3))
    const lmat = new THREE.LineBasicMaterial({ color: 0x60a5fa, transparent: true, opacity: 0.28 })
    scene.add(new THREE.LineSegments(lgeo, lmat))
    const ringMat = new THREE.MeshBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.9, side: THREE.DoubleSide })
    const ring = new THREE.Mesh(new THREE.RingGeometry(0.42, 0.5, 40), ringMat)
    ring.visible = false; scene.add(ring)

    const ray = new THREE.Raycaster(); ray.params.Points = { threshold: 0.25 }
    const mouse = new THREE.Vector2()
    const pick = (ev: PointerEvent) => {
      const r = renderer.domElement.getBoundingClientRect()
      mouse.set(((ev.clientX - r.left) / r.width) * 2 - 1, -((ev.clientY - r.top) / r.height) * 2 + 1)
      ray.setFromCamera(mouse, camera)
      for (const grp of [...groups].reverse()) {
        const hit = ray.intersectObject(grp.points)[0]
        if (hit && hit.index !== undefined) return { n: grp.list[hit.index], x: ev.clientX - r.left, y: ev.clientY - r.top }
      }
      return null
    }
    let downAt = 0
    const onMove = (ev: PointerEvent) => { const h = pick(ev); setHover(h); renderer.domElement.style.cursor = h ? 'pointer' : 'grab' }
    const onDown = () => { downAt = performance.now() }
    const onUp = (ev: PointerEvent) => { if (performance.now() - downAt < 250) { const h = pick(ev); if (h) onSelect(h.n.id) } }
    renderer.domElement.addEventListener('pointermove', onMove)
    renderer.domElement.addEventListener('pointerdown', onDown)
    renderer.domElement.addEventListener('pointerup', onUp)
    renderer.domElement.addEventListener('pointerleave', () => setHover(null))

    let fitted = false
    const resize = () => {
      const w = el.clientWidth, h = el.clientHeight
      if (!w || !h) return
      renderer.setSize(w, h); camera.aspect = w / h; camera.updateProjectionMatrix()
      if (!fitted) {  // frame the whole layout once (outer radius ~7.5) whatever the panel shape
        const dist = 7.8 / Math.tan((camera.fov * Math.PI) / 360) / Math.min(1, camera.aspect)
        camera.position.set(0, dist * 0.42, dist * 0.92); controls.update(); fitted = true
      }
    }
    resize()
    const ro = new ResizeObserver(resize); ro.observe(el)
    let raf = 0, visible = true, onScreen = true
    const loop = () => {
      controls.update()
      const s = selRef.current && pos.get(selRef.current)
      ring.visible = !!s
      if (s) { ring.position.copy(s); ring.lookAt(camera.position) }
      renderer.render(scene, camera)
      if (visible && onScreen) raf = requestAnimationFrame(loop)
    }
    const resume = () => { cancelAnimationFrame(raf); if (visible && onScreen) raf = requestAnimationFrame(loop) }
    const onVis = () => { visible = document.visibilityState === 'visible'; resume() }
    document.addEventListener('visibilitychange', onVis)
    const io = new IntersectionObserver(([e]) => { onScreen = e.isIntersecting; resume() }); io.observe(el)
    raf = requestAnimationFrame(loop)
    return () => {
      cancelAnimationFrame(raf); ro.disconnect(); io.disconnect(); document.removeEventListener('visibilitychange', onVis)
      controls.dispose()
      groups.forEach((grp) => { grp.points.geometry.dispose(); (grp.points.material as THREE.Material).dispose() })
      lgeo.dispose(); lmat.dispose(); ring.geometry.dispose(); ringMat.dispose(); sprite.dispose()
      renderer.dispose(); renderer.domElement.remove()
    }
  }, [nodes, onSelect, onFail])

  return (
    <div className="relative h-full w-full">
      <div ref={host} className="absolute inset-0" role="img" aria-label={`3D topology of ${nodes.length} collected nodes. Use the tree view for keyboard navigation.`} />
      {hover && (
        <div className="pointer-events-none absolute z-10 max-w-[260px] rounded-lg border border-line bg-surface px-2.5 py-1.5 text-xs shadow-lg" style={{ left: hover.x + 12, top: hover.y + 12 }}>
          <div className="font-semibold text-ink">{hover.n.label}</div><div className="text-ink-3">{hover.n.detail}</div>
        </div>
      )}
    </div>
  )
}
