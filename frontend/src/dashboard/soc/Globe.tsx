import { useEffect, useRef } from 'react'
import { WORLD } from './world'

// Canvas globe for the SOC view. Land is a dot grid lit from the upper left; arcs carry intelligence from
// where each feed is published into India (our simulated estate); the ring of nodes around the globe is
// the six sectors plus any attacker IPs seen in open alerts. Drag to rotate.

export type Arc = { id: string; from: [number, number]; label: string }
// Malicious infrastructure on the map: where the feeds' bad IPs are registered (count per ~10 km cell).
export type Hotspot = { lat: number; lon: number; count: number; label: string }
export type Satellite = { id: string; label: string; sub: string; weight: number; tone: 'teal' | 'red' | 'amber'; active: boolean }

const D = Math.PI / 180
const HOME: [number, number] = [78.9, 21.5] // India, centre of the simulated estate
const LAND = WORLD.rows.flatMap((row, r) => [...row].flatMap((v, c) => {
  if (v !== '1') return []
  const lon = (-180 + ((c + 0.5) * 360) / WORLD.w) * D
  const lat = (WORLD.lat0 - ((r + 0.5) * (WORLD.lat0 - WORLD.lat1)) / WORLD.h) * D
  return [[Math.cos(lat) * Math.sin(lon), Math.sin(lat), Math.cos(lat) * Math.cos(lon)]]
}))
// Seeded so the star field never jumps between renders.
const STARS = Array.from({ length: 140 }, (_, i) => {
  const a = Math.sin(i * 127.1) * 43758.5453
  const b = Math.sin(i * 311.7) * 24634.6345
  return { x: a - Math.floor(a), y: b - Math.floor(b), s: ((i * 37) % 10) / 10 }
})
const unit = ([lon, lat]: [number, number]) => [Math.cos(lat * D) * Math.sin(lon * D), Math.sin(lat * D), Math.cos(lat * D) * Math.cos(lon * D)]

export function Globe({ arcs, satellites, spin, hotspots = [] }: { arcs: Arc[]; satellites: Satellite[]; spin: 'india' | 'free'; hotspots?: Hotspot[] }) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const data = useRef({ arcs, satellites, spin, hotspots })
  useEffect(() => { data.current = { arcs, satellites, spin, hotspots } }, [arcs, satellites, spin, hotspots])

  useEffect(() => {
    const cv = canvas.current!
    const ctx = cv.getContext('2d')!
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let w = 0
    let h = 0
    let raf = 0
    let lam = HOME[0] * D
    const phi = 14 * D
    let drag: { x: number; lam: number } | null = null
    let manual = 0 // seconds of manual control left before auto spin resumes
    let last = performance.now()
    const t0 = last

    const resize = () => {
      const r = cv.getBoundingClientRect()
      const dpr = Math.min(2, window.devicePixelRatio || 1)
      w = r.width
      h = r.height
      cv.width = Math.round(w * dpr)
      cv.height = Math.round(h * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      if (reduce) draw(0)
    }

    // World → view coordinates for the current rotation (y up, z toward the viewer).
    const view = (v: number[]) => {
      const cl = Math.cos(lam)
      const sl = Math.sin(lam)
      const x = v[0] * cl - v[2] * sl
      const z1 = v[0] * sl + v[2] * cl
      const cp = Math.cos(phi)
      const sp = Math.sin(phi)
      return [x, v[1] * cp - z1 * sp, v[1] * sp + z1 * cp]
    }

    function draw(time: number) {
      const { arcs: A, satellites: S, hotspots: H } = data.current
      // Leave headroom so orbit arcs and labels stay inside the canvas (it sits below the page title).
      const R = Math.min(w * 0.28, h * 0.38)
      const cx = w * 0.5  // centred in the stage
      const cy = h * 0.54
      ctx.clearRect(0, 0, w, h)

      // Stars
      for (const s of STARS) {
        const tw = reduce ? 0.5 : 0.35 + 0.35 * Math.sin(time * 1.3 + s.s * 20)
        ctx.fillStyle = `rgb(170 205 255 / ${0.12 + tw * 0.35 * s.s})`
        ctx.fillRect(s.x * w, s.y * h, 1.2, 1.2)
      }

      // Atmosphere glow behind the sphere
      const halo = ctx.createRadialGradient(cx, cy, R * 0.9, cx, cy, R * 1.32)
      halo.addColorStop(0, 'rgb(61 139 255 / 0.45)')
      halo.addColorStop(0.25, 'rgb(61 139 255 / 0.14)')
      halo.addColorStop(1, 'rgb(61 139 255 / 0)')
      ctx.fillStyle = halo
      ctx.beginPath()
      ctx.arc(cx, cy, R * 1.32, 0, Math.PI * 2)
      ctx.fill()

      // Ocean
      const sea = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.4, R * 0.1, cx, cy, R)
      sea.addColorStop(0, '#123f8a')
      sea.addColorStop(0.55, '#0a2150')
      sea.addColorStop(1, '#020615')
      ctx.fillStyle = sea
      ctx.beginPath()
      ctx.arc(cx, cy, R, 0, Math.PI * 2)
      ctx.fill()

      // Land, lit from the upper left
      const L = [-0.55, 0.6, 0.58]
      const size = Math.max(1.3, R / 150)
      for (const p of LAND) {
        const [x, y, z] = view(p)
        if (z <= 0) continue
        const lit = Math.max(0, x * L[0] + y * L[1] + z * L[2])
        const a = 0.3 + 0.7 * Math.min(1, lit * 1.25) * (0.45 + 0.55 * z)
        ctx.fillStyle = `rgb(${60 + lit * 86} ${130 + lit * 65} ${220 + lit * 35} / ${a})`
        ctx.fillRect(cx + x * R - size / 2, cy - y * R - size / 2, size, size)
      }

      // Rim light
      ctx.save()
      ctx.strokeStyle = 'rgb(146 195 255 / 0.55)'
      ctx.lineWidth = 1.4
      ctx.shadowColor = 'rgb(61 139 255 / 0.9)'
      ctx.shadowBlur = 18
      ctx.beginPath()
      ctx.arc(cx, cy, R, 0, Math.PI * 2)
      ctx.stroke()
      ctx.restore()

      const project = (v: number[]) => {
        const [x, y, z] = view(v)
        return { x: cx + x * R, y: cy - y * R, z, hidden: z < 0 && x * x + y * y < 1 }
      }
      const home = project(unit(HOME))

      // Hotspots: red glows on the surface, size ~ sqrt(count); the 5 largest visible ones are labelled.
      const maxN = Math.max(1, ...H.map((p) => p.count))
      const shown: { x: number; y: number; p: Hotspot }[] = []
      H.forEach((p, i) => {
        const q = project(unit([p.lon, p.lat]))
        if (q.z < 0) return  // far side of the globe
        const r = 1.2 + 5.5 * Math.sqrt(p.count / maxN)
        const pulse = reduce ? 0 : (Math.sin(time * 2 + i) + 1) / 2
        ctx.fillStyle = `rgb(255 96 80 / ${0.12 + 0.12 * pulse})`
        ctx.beginPath(); ctx.arc(q.x, q.y, r * 2.2, 0, Math.PI * 2); ctx.fill()
        ctx.fillStyle = 'rgb(255 120 100 / 0.9)'
        ctx.beginPath(); ctx.arc(q.x, q.y, r * 0.6, 0, Math.PI * 2); ctx.fill()
        if (shown.length < 5 && q.z > 0.25) shown.push({ x: q.x, y: q.y, p })
      })
      ctx.font = '500 10px ui-monospace, SFMono-Regular, monospace'
      shown.forEach(({ x, y, p }) => {
        ctx.fillStyle = 'rgb(255 190 180 / 0.9)'
        ctx.fillText(p.label, x + 8, y + 3)
      })

      // Arcs: great circle from each publisher to India, lifted off the surface.
      A.forEach((arc, i) => {
        const a = unit(arc.from)
        const b = unit(HOME)
        const dot = Math.min(1, Math.max(-1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]))
        const om = Math.acos(dot)
        if (om < 0.02) return
        const pts = Array.from({ length: 49 }, (_, k) => {
          const t = k / 48
          const s1 = Math.sin((1 - t) * om) / Math.sin(om)
          const s2 = Math.sin(t * om) / Math.sin(om)
          const lift = 1 + 0.32 * Math.sin(Math.PI * t) * (om / Math.PI)
          return project([(a[0] * s1 + b[0] * s2) * lift, (a[1] * s1 + b[1] * s2) * lift, (a[2] * s1 + b[2] * s2) * lift])
        })
        ctx.lineWidth = 1
        for (let k = 1; k < pts.length; k++) {
          if (pts[k].hidden || pts[k - 1].hidden) continue
          ctx.strokeStyle = 'rgb(160 200 255 / 0.32)'
          ctx.beginPath()
          ctx.moveTo(pts[k - 1].x, pts[k - 1].y)
          ctx.lineTo(pts[k].x, pts[k].y)
          ctx.stroke()
        }
        // Travelling pulse
        const head = ((time * 0.28 + i * 0.37) % 1) * 48
        for (let k = Math.max(1, Math.floor(head) - 7); k <= Math.floor(head); k++) {
          const p = pts[k]
          const q = pts[k - 1]
          if (!p || !q || p.hidden || q.hidden) continue
          const f = 1 - (head - k) / 8
          ctx.strokeStyle = `rgb(220 235 255 / ${Math.max(0, f)})`
          ctx.lineWidth = 2
          ctx.beginPath()
          ctx.moveTo(q.x, q.y)
          ctx.lineTo(p.x, p.y)
          ctx.stroke()
        }
        const o = pts[0]
        if (!o.hidden) {
          ctx.fillStyle = '#e3efff'
          ctx.beginPath()
          ctx.arc(o.x, o.y, 2.6, 0, Math.PI * 2)
          ctx.fill()
          ctx.font = '500 10px ui-monospace, SFMono-Regular, monospace'
          ctx.fillStyle = 'rgb(205 225 255 / 0.85)'
          ctx.fillText(arc.label, o.x + 6, o.y - 6)
        }
      })

      // Constellation: sectors and attackers orbit the globe, wired to each other and to India.
      const n = S.length
      const nodes = S.map((s, i) => {
        // Sweep from upper right round to the left, leaving the top-left (title) and bottom (ask bar) clear.
        const ang = -Math.PI * 0.36 + (i / Math.max(1, n - 1)) * Math.PI * 1.22 + (reduce ? 0 : Math.sin(time * 0.15) * 0.04)
        const rr = R * (1.2 + 0.08 * Math.sin(i * 2.3))
        return { s, x: Math.min(w - (w < 520 ? 14 : 120), Math.max(w < 520 ? 14 : 120, cx + Math.cos(ang) * rr * 1.05)), y: Math.min(h - 34, Math.max(18, cy + Math.sin(ang) * rr * 0.82)) }
      })
      ctx.lineWidth = 0.8
      nodes.forEach((a, i) => {
        const b = nodes[(i + 1) % n]
        const c = nodes[(i + 2) % n]
        ctx.strokeStyle = 'rgb(146 195 255 / 0.28)'
        if (b && n > 1) { ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke() }
        if (c && n > 3 && i % 2 === 0) { ctx.strokeStyle = 'rgb(146 195 255 / 0.12)'; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(c.x, c.y); ctx.stroke() }
        if (!home.hidden) {
          const red = a.s.tone === 'red'
          ctx.strokeStyle = red ? 'rgb(255 96 80 / 0.55)' : a.s.active ? 'rgb(146 195 255 / 0.42)' : 'rgb(146 195 255 / 0.1)'
          ctx.setLineDash(red ? [4, 4] : [])
          ctx.lineDashOffset = red ? -time * 18 : 0
          ctx.beginPath()
          ctx.moveTo(a.x, a.y)
          ctx.lineTo(home.x, home.y)
          ctx.stroke()
          ctx.setLineDash([])
        }
      })
      ctx.font = '500 10px ui-monospace, SFMono-Regular, monospace'
      for (const { s, x, y } of nodes) {
        const col = s.tone === 'red' ? '255 96 80' : s.tone === 'amber' ? '255 190 110' : '110 170 255'
        const r = 2.5 + s.weight * 4
        ctx.save()
        ctx.shadowColor = `rgb(${col})`
        ctx.shadowBlur = 12
        ctx.fillStyle = `rgb(${col} / ${s.active ? 1 : 0.45})`
        ctx.beginPath()
        ctx.arc(x, y, r, 0, Math.PI * 2)
        ctx.fill()
        ctx.restore()
        if (w < 520) continue // too narrow for labels; the dots and links still show
        const right = x >= cx
        ctx.textAlign = right ? 'left' : 'right'
        ctx.fillStyle = `rgb(225 235 250 / ${s.active ? 0.92 : 0.45})`
        ctx.fillText(s.label, x + (right ? 9 : -9), y - 2)
        ctx.fillStyle = `rgb(${col} / ${s.active ? 0.85 : 0.4})`
        ctx.fillText(s.sub, x + (right ? 9 : -9), y + 10)
        ctx.textAlign = 'left'
      }

      // India marker
      if (!home.hidden) {
        const pulse = reduce ? 0.5 : (time * 0.8) % 1
        ctx.strokeStyle = `rgb(146 195 255 / ${1 - pulse})`
        ctx.lineWidth = 1.2
        ctx.beginPath()
        ctx.arc(home.x, home.y, 4 + pulse * 18, 0, Math.PI * 2)
        ctx.stroke()
        ctx.save()
        ctx.fillStyle = '#eaf3ff'
        ctx.shadowColor = '#6fa8ff'
        ctx.shadowBlur = 16
        ctx.beginPath()
        ctx.arc(home.x, home.y, 3.6, 0, Math.PI * 2)
        ctx.fill()
        ctx.restore()
      }
    }

    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000)
      last = now
      const t = (now - t0) / 1000
      if (!drag) {
        if (manual > 0) manual -= dt
        else if (data.current.spin === 'free') lam += dt * 0.12
        else {
          // Sway gently around India so the estate stays in view.
          const target = HOME[0] * D + Math.sin(t * 0.12) * 0.55
          lam += (target - lam) * Math.min(1, dt * 1.5)
        }
      }
      draw(t)
      raf = requestAnimationFrame(frame)
    }

    const down = (e: PointerEvent) => {
      drag = { x: e.clientX, lam }
      cv.setPointerCapture(e.pointerId)
    }
    const move = (e: PointerEvent) => {
      if (!drag) return
      lam = drag.lam - ((e.clientX - drag.x) / Math.max(1, w)) * Math.PI * 1.4
      if (reduce) draw(0)
    }
    const up = () => {
      drag = null
      manual = 4
    }
    const vis = () => {
      cancelAnimationFrame(raf)
      if (!document.hidden && !reduce) {
        last = performance.now()
        raf = requestAnimationFrame(frame)
      }
    }

    const ro = new ResizeObserver(resize)
    ro.observe(cv)
    resize()
    cv.addEventListener('pointerdown', down)
    cv.addEventListener('pointermove', move)
    cv.addEventListener('pointerup', up)
    cv.addEventListener('pointercancel', up)
    document.addEventListener('visibilitychange', vis)
    if (reduce) draw(0)
    else raf = requestAnimationFrame(frame)
    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
      cv.removeEventListener('pointerdown', down)
      cv.removeEventListener('pointermove', move)
      cv.removeEventListener('pointerup', up)
      cv.removeEventListener('pointercancel', up)
      document.removeEventListener('visibilitychange', vis)
    }
  }, [])

  return (
    <canvas
      ref={canvas}
      className="soc-globe"
      role="img"
      aria-label={`Globe: intelligence arriving in India from ${arcs.length} feed publisher locations; ${hotspots.length} locations where malicious IPs are registered; ${satellites.length} sectors and attacker sources around it. Drag to rotate.`}
    />
  )
}
