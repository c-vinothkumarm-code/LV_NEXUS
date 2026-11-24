import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { prefersReducedMotion } from '../../hooks/useMotion'

/**
 * "Connected Intelligence": the LV NEXUS signature scene (original artwork; it does not draw or morph any logo).
 *
 * Sequence: navy space -> blue / cyan particles light up -> nodes appear and link into a geometric network -> the network
 * expands into a two-shell 3D structure around an empty centre (where the page places the logo, undistorted) -> data
 * pulses travel along the links continuously while the scene rotates slowly.
 *
 * Budget: one WebGL renderer, <= 900 particles (300 in lite mode), ~160 links, DPR capped at 1.75, renders only while the
 * tab is visible and the canvas is on screen, one still frame with reduced motion. Calls onFail() when WebGL is missing
 * so the page can show its 2D fallback.
 */
export default function ConnectedIntelligence({ lite = false, onFail, onReady }: { lite?: boolean; onFail?: () => void; onReady?: () => void }) {
  const host = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = host.current!
    let renderer: THREE.WebGLRenderer
    try {
      renderer = new THREE.WebGLRenderer({ antialias: !lite, alpha: true, powerPreference: 'low-power' })
    } catch {
      onFail?.()
      return
    }
    const still = prefersReducedMotion()
    renderer.setPixelRatio(Math.min(1.75, window.devicePixelRatio || 1))
    renderer.setClearColor(0x000000, 0)
    el.appendChild(renderer.domElement)
    renderer.domElement.setAttribute('aria-hidden', 'true')

    const scene = new THREE.Scene()
    scene.fog = new THREE.FogExp2(0x071328, 0.055)
    const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100)
    camera.position.set(0, 0.6, 12)

    // soft round sprite for particles and nodes (generated, no image files)
    const spriteCanvas = document.createElement('canvas')
    spriteCanvas.width = spriteCanvas.height = 64
    const g = spriteCanvas.getContext('2d')!
    const grad = g.createRadialGradient(32, 32, 0, 32, 32, 32)
    grad.addColorStop(0, 'rgba(255,255,255,1)'); grad.addColorStop(0.25, 'rgba(255,255,255,.85)'); grad.addColorStop(1, 'rgba(255,255,255,0)')
    g.fillStyle = grad; g.fillRect(0, 0, 64, 64)
    const sprite = new THREE.CanvasTexture(spriteCanvas)

    const BLUE = new THREE.Color('#3b82f6'), CYAN = new THREE.Color('#22d3ee'), WHITE = new THREE.Color('#e0f2fe')
    const group = new THREE.Group()
    scene.add(group)

    // 1. ambient particles in a wide shell
    const pCount = lite ? 300 : 900
    const pPos = new Float32Array(pCount * 3), pCol = new Float32Array(pCount * 3), pSeed = new Float32Array(pCount)
    for (let i = 0; i < pCount; i++) {
      const r = 6 + Math.random() * 10, th = Math.random() * Math.PI * 2, ph = Math.acos(2 * Math.random() - 1)
      pPos.set([r * Math.sin(ph) * Math.cos(th), r * Math.cos(ph) * 0.6, r * Math.sin(ph) * Math.sin(th)], i * 3)
      const c = Math.random() < 0.6 ? BLUE : CYAN
      pCol.set([c.r, c.g, c.b], i * 3)
      pSeed[i] = Math.random()
    }
    const pGeo = new THREE.BufferGeometry()
    pGeo.setAttribute('position', new THREE.BufferAttribute(pPos, 3))
    pGeo.setAttribute('color', new THREE.BufferAttribute(pCol, 3))
    const pMat = new THREE.PointsMaterial({ size: 0.09, map: sprite, vertexColors: true, transparent: true, opacity: 0, depthWrite: false, blending: THREE.AdditiveBlending })
    const particles = new THREE.Points(pGeo, pMat)
    scene.add(particles)

    // 2. the network: two geodesic shells (inner + outer) with links between near neighbours and across shells
    const inner = new THREE.IcosahedronGeometry(2.1, 1), outer = new THREE.IcosahedronGeometry(3.6, 1)
    const uniq = (geo: THREE.BufferGeometry) => {
      const a = geo.getAttribute('position'), seen = new Map<string, THREE.Vector3>()
      for (let i = 0; i < a.count; i++) {
        const v = new THREE.Vector3().fromBufferAttribute(a, i)
        seen.set(`${v.x.toFixed(2)},${v.y.toFixed(2)},${v.z.toFixed(2)}`, v)
      }
      return [...seen.values()]
    }
    const innerNodes = uniq(inner), outerNodes = uniq(outer)
    inner.dispose(); outer.dispose()
    const nodes = [...innerNodes, ...outerNodes]
    const links: [number, number][] = []
    const near = (list: THREE.Vector3[], offset: number, max: number) => {
      for (let i = 0; i < list.length; i++) for (let j = i + 1; j < list.length; j++) if (list[i].distanceTo(list[j]) < max) links.push([offset + i, offset + j])
    }
    near(innerNodes, 0, 1.35)
    near(outerNodes, innerNodes.length, 2.0)
    innerNodes.forEach((v, i) => {  // spokes: each inner node to its closest outer node
      let best = 0, bd = Infinity
      outerNodes.forEach((w, j) => { const d = v.distanceTo(w); if (d < bd) { bd = d; best = j } })
      if (i % 2 === 0) links.push([i, innerNodes.length + best])
    })
    links.sort(() => Math.random() - 0.5)  // links light up in a scattered order

    const nPos = new Float32Array(nodes.length * 3), nCol = new Float32Array(nodes.length * 3)
    nodes.forEach((v, i) => { nPos.set([v.x, v.y, v.z], i * 3); const c = i < innerNodes.length ? CYAN : BLUE; nCol.set([c.r, c.g, c.b], i * 3) })
    const nGeo = new THREE.BufferGeometry()
    nGeo.setAttribute('position', new THREE.BufferAttribute(nPos, 3))
    nGeo.setAttribute('color', new THREE.BufferAttribute(nCol, 3))
    const nMat = new THREE.PointsMaterial({ size: 0.34, map: sprite, vertexColors: true, transparent: true, opacity: 0, depthWrite: false, blending: THREE.AdditiveBlending })
    const nodePoints = new THREE.Points(nGeo, nMat)
    group.add(nodePoints)

    const lPos = new Float32Array(links.length * 6)
    links.forEach(([a, b], i) => { lPos.set([nodes[a].x, nodes[a].y, nodes[a].z, nodes[b].x, nodes[b].y, nodes[b].z], i * 6) })
    const lGeo = new THREE.BufferGeometry()
    lGeo.setAttribute('position', new THREE.BufferAttribute(lPos, 3))
    lGeo.setDrawRange(0, 0)
    const lMat = new THREE.LineBasicMaterial({ color: 0x60a5fa, transparent: true, opacity: 0.38, depthWrite: false, blending: THREE.AdditiveBlending })
    group.add(new THREE.LineSegments(lGeo, lMat))

    // 3. data pulses travelling along links (continuous intelligence)
    const pulseCount = lite ? 14 : 36
    const pulses = Array.from({ length: pulseCount }, () => ({ link: Math.floor(Math.random() * links.length), t: Math.random(), speed: 0.25 + Math.random() * 0.45 }))
    const puPos = new Float32Array(pulseCount * 3)
    const puGeo = new THREE.BufferGeometry()
    puGeo.setAttribute('position', new THREE.BufferAttribute(puPos, 3))
    const puMat = new THREE.PointsMaterial({ size: 0.22, map: sprite, color: WHITE, transparent: true, opacity: 0, depthWrite: false, blending: THREE.AdditiveBlending })
    group.add(new THREE.Points(puGeo, puMat))

    // 4. a faint halo ring behind the centre, where the page shows the logo
    const ring = new THREE.Mesh(new THREE.RingGeometry(1.15, 1.2, 96), new THREE.MeshBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0, side: THREE.DoubleSide }))
    scene.add(ring)

    const resize = () => {
      const w = el.clientWidth, h = el.clientHeight
      if (!w || !h) return
      renderer.setSize(w, h, false)
      renderer.domElement.style.width = '100%'; renderer.domElement.style.height = '100%'
      camera.aspect = w / h
      camera.position.z = w / h < 0.9 ? 15 : 12
      camera.updateProjectionMatrix()
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(el)

    const ease = (x: number) => 1 - Math.pow(1 - Math.min(1, Math.max(0, x)), 3)
    const start = performance.now()
    let raf = 0, visible = true, onScreen = true, ready = false
    const frame = (now: number) => {
      const t = still ? 8 : (now - start) / 1000
      // sequence
      pMat.opacity = 0.75 * ease(t / 1.2)
      nMat.opacity = ease((t - 0.8) / 1.2)
      lGeo.setDrawRange(0, Math.floor(links.length * 2 * ease((t - 1.2) / 2.4)))
      const grow = 0.55 + 0.45 * ease((t - 2.4) / 2.2)
      group.scale.setScalar(grow)
      puMat.opacity = 0.95 * ease((t - 3.6) / 1)
      ;(ring.material as THREE.MeshBasicMaterial).opacity = 0.35 * ease((t - 4.2) / 1.2)
      if (!ready && t > 4.2) { ready = true; onReady?.() }
      // continuous motion
      group.rotation.y = t * 0.09
      group.rotation.x = Math.sin(t * 0.13) * 0.12
      particles.rotation.y = -t * 0.015
      nMat.size = 0.34 + Math.sin(t * 2.2) * 0.05  // node pulse
      camera.position.x = Math.sin(t * 0.05) * 0.8
      camera.lookAt(0, 0, 0)
      ring.lookAt(camera.position)
      for (let i = 0; i < pulseCount; i++) {
        const p = pulses[i]
        p.t += still ? 0 : p.speed * 0.016
        if (p.t > 1) { p.t = 0; p.link = Math.floor(Math.random() * links.length) }
        const [a, b] = links[p.link]
        puPos[i * 3] = nodes[a].x + (nodes[b].x - nodes[a].x) * p.t
        puPos[i * 3 + 1] = nodes[a].y + (nodes[b].y - nodes[a].y) * p.t
        puPos[i * 3 + 2] = nodes[a].z + (nodes[b].z - nodes[a].z) * p.t
      }
      puGeo.attributes.position.needsUpdate = true
      renderer.render(scene, camera)
      if (!still && visible && onScreen) raf = requestAnimationFrame(frame)
    }
    const resume = () => { cancelAnimationFrame(raf); if (visible && onScreen) raf = requestAnimationFrame(frame) }
    const onVis = () => { visible = document.visibilityState === 'visible'; if (!still) resume() }
    document.addEventListener('visibilitychange', onVis)
    const io = new IntersectionObserver(([e]) => { onScreen = e.isIntersecting; if (!still) resume() })
    io.observe(el)
    raf = requestAnimationFrame(frame)
    if (still) onReady?.()

    const onLost = (e: Event) => { e.preventDefault(); onFail?.() }
    renderer.domElement.addEventListener('webglcontextlost', onLost)

    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect(); io.disconnect()
      document.removeEventListener('visibilitychange', onVis)
      renderer.domElement.removeEventListener('webglcontextlost', onLost)
      ;[pGeo, nGeo, lGeo, puGeo, ring.geometry].forEach((x) => x.dispose())
      ;[pMat, nMat, lMat, puMat, ring.material as THREE.Material].forEach((m) => m.dispose())
      sprite.dispose()
      renderer.dispose()
      renderer.domElement.remove()
    }
  }, [lite, onFail, onReady])

  return <div ref={host} className="absolute inset-0" />
}
