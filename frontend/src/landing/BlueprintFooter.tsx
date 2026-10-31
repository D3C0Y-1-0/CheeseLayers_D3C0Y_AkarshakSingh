import { useEffect, useMemo, useRef } from 'react'
import { Link } from 'react-router-dom'
import gsap from 'gsap'

// The wordmark as a technical drawing. Letters are plain polygons on a 300-unit-tall grid,
// so we can draw overshooting construction lines from the same points used to clip the ink.
type Pt = [number, number]
const LETTERS: { w: number; shapes: Pt[][] }[] = [
  { w: 300, shapes: [[[0, 0], [64, 0], [150, 222], [236, 0], [300, 0], [182, 300], [118, 300]]] }, // V
  { w: 230, shapes: [[[0, 0], [230, 0], [230, 52], [56, 52], [56, 122], [210, 122], [210, 174], [56, 174], [56, 248], [230, 248], [230, 300], [0, 300]]] }, // E
  { w: 270, shapes: [[[82, 0], [188, 0], [270, 76], [270, 102], [214, 102], [214, 92], [166, 52], [104, 52], [56, 92], [56, 208], [104, 248], [166, 248], [214, 208], [214, 198], [270, 198], [270, 224], [188, 300], [82, 300], [0, 224], [0, 76]]] }, // C
  { w: 240, shapes: [[[0, 0], [240, 0], [240, 52], [148, 52], [148, 300], [92, 300], [92, 52], [0, 52]]] }, // T
  { w: 262, shapes: [[[0, 0], [176, 0], [250, 60], [250, 124], [206, 166], [262, 300], [200, 300], [146, 180], [56, 180], [56, 300], [0, 300]], [[56, 52], [156, 52], [194, 82], [194, 104], [156, 130], [56, 130]]] }, // R
  { w: 300, shapes: [[[118, 0], [182, 0], [300, 300], [240, 300], [214, 236], [86, 236], [60, 300], [0, 300]], [[106, 186], [194, 186], [150, 72]]] }, // A
]
const GAP = 36
const PAD_X = 26
const PAD_Y = 22
const VIEW_W = LETTERS.reduce((n, l) => n + l.w, 0) + GAP * (LETTERS.length - 1) + PAD_X * 2
const VIEW_H = 300 + PAD_Y * 2

function layout() {
  let x = PAD_X
  return LETTERS.flatMap((l) => {
    const shapes = l.shapes.map((s) => s.map(([px, py]): Pt => [px + x, py + PAD_Y]))
    x += l.w + GAP
    return shapes
  })
}

// Every edge runs a little past its corners, with small crossing ticks, like a drafting sketch.
function draftingLines(shapes: Pt[][]) {
  const OVER = 11
  const TICK = 7
  let d = ''
  for (const s of shapes) {
    s.forEach((a, i) => {
      const b = s[(i + 1) % s.length]
      const dx = b[0] - a[0]
      const dy = b[1] - a[1]
      const len = Math.hypot(dx, dy)
      const ux = dx / len
      const uy = dy / len
      d += `M${(a[0] - ux * OVER).toFixed(1)} ${(a[1] - uy * OVER).toFixed(1)}L${(b[0] + ux * OVER).toFixed(1)} ${(b[1] + uy * OVER).toFixed(1)}`
      // A tick across each long edge, at its midpoint.
      if (len > 110) {
        const mx = (a[0] + b[0]) / 2
        const my = (a[1] + b[1]) / 2
        d += `M${(mx - uy * TICK).toFixed(1)} ${(my + ux * TICK).toFixed(1)}L${(mx + uy * TICK).toFixed(1)} ${(my - ux * TICK).toFixed(1)}`
      }
    })
  }
  return d
}

// Soft random field: it makes the ink's edge wobble and bleed instead of being a clean circle.
function makeNoise(w: number, h: number) {
  const CELL = 9
  const gw = Math.ceil(w / CELL) + 2
  const gh = Math.ceil(h / CELL) + 2
  const grid = Float32Array.from({ length: gw * gh }, () => Math.random())
  const out = new Float32Array(w * h)
  const fine = Float32Array.from({ length: w * h }, () => Math.random())
  for (let y = 0; y < h; y++) {
    const gy = y / CELL
    const y0 = Math.floor(gy)
    let ty = gy - y0
    ty = ty * ty * (3 - 2 * ty)
    for (let x = 0; x < w; x++) {
      const gx = x / CELL
      const x0 = Math.floor(gx)
      let tx = gx - x0
      tx = tx * tx * (3 - 2 * tx)
      const a = grid[y0 * gw + x0]
      const b = grid[y0 * gw + x0 + 1]
      const c = grid[(y0 + 1) * gw + x0]
      const e = grid[(y0 + 1) * gw + x0 + 1]
      out[y * w + x] = (a + (b - a) * tx) * (1 - ty) + (c + (e - c) * tx) * ty + (fine[y * w + x] - 0.5) * 0.06
    }
  }
  return out
}

type Blob = { x: number; y: number; r: number; life: number }

function useInk(shapes: Pt[][]) {
  const box = useRef<HTMLDivElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const cv = canvas.current!
    const el = box.current!
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (reduced) return
    const ctx = cv.getContext('2d')!
    const clip = new Path2D()
    shapes.forEach((s) => {
      s.forEach(([x, y], i) => (i ? clip.lineTo(x, y) : clip.moveTo(x, y)))
      clip.closePath()
    })

    let W = 0, H = 0, unit = 1
    let noise = new Float32Array(0)
    let field = new Float32Array(0)
    let img: ImageData | null = null
    let blobs: Blob[] = []
    let raf = 0
    let last = 0
    let px: number | null = null
    let py = 0

    const resize = () => {
      const b = el.getBoundingClientRect()
      W = Math.max(2, Math.round(b.width / 2))
      H = Math.max(2, Math.round(b.height / 2))
      unit = W / VIEW_W
      cv.width = W
      cv.height = H
      noise = makeNoise(W, H)
      field = new Float32Array(W * H)
      img = ctx.createImageData(W, H)
    }

    const paint = () => {
      field.fill(0)
      for (const s of blobs) {
        const r = s.r * unit
        const x0 = Math.max(0, Math.floor(s.x - r))
        const x1 = Math.min(W - 1, Math.ceil(s.x + r))
        const y0 = Math.max(0, Math.floor(s.y - r))
        const y1 = Math.min(H - 1, Math.ceil(s.y + r))
        const r2 = r * r
        for (let y = y0; y <= y1; y++) {
          for (let x = x0; x <= x1; x++) {
            const d = ((x - s.x) ** 2 + (y - s.y) ** 2) / r2
            if (d < 1) field[y * W + x] += s.life * (1 - d) * (1 - d)
          }
        }
      }
      // Two thresholds give the look in the reference: a solid core with a paler bleed around it.
      const data = img!.data
      for (let i = 0; i < field.length; i++) {
        const v = field[i] * 1.4 + (noise[i] - 0.5) * 0.42
        const p = i * 4
        if (v > 0.62) {
          const edge = Math.min(1, (v - 0.62) / 0.05)
          data[p] = 34 - 28 * edge
          data[p + 1] = 113 - 103 * edge
          data[p + 2] = 227 - 203 * edge
          data[p + 3] = 255
        } else if (v > 0.42) {
          data[p] = 146
          data[p + 1] = 195
          data[p + 2] = 255
          data[p + 3] = 255 * Math.min(1, (v - 0.42) / 0.04)
        } else {
          data[p + 3] = 0
        }
      }
      ctx.setTransform(1, 0, 0, 1, 0, 0)
      ctx.globalCompositeOperation = 'source-over'
      ctx.putImageData(img!, 0, 0)
      // Only the inside of the letters may hold ink.
      ctx.globalCompositeOperation = 'destination-in'
      ctx.setTransform(unit, 0, 0, unit, 0, 0)
      ctx.fill(clip, 'evenodd')
    }

    const tick = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000)
      last = now
      for (const s of blobs) {
        // Ink spreads as it soaks in, then slowly fades.
        s.r += dt * 16
        s.life -= dt * 0.34
      }
      blobs = blobs.filter((s) => s.life > 0.02)
      paint()
      raf = blobs.length ? requestAnimationFrame(tick) : 0
    }
    const wake = () => {
      if (raf) return
      last = performance.now()
      raf = requestAnimationFrame(tick)
    }
    const drop = (x: number, y: number) => {
      blobs.push({ x, y, r: 66 + Math.random() * 26, life: 1 })
      if (blobs.length > 220) blobs.shift()
      wake()
    }
    const trail = (x: number, y: number) => {
      if (px === null) {
        drop(x, y)
      } else {
        const dist = Math.hypot(x - px, y - py)
        const steps = Math.min(10, Math.floor(dist / 6))
        for (let i = 1; i <= steps; i++) drop(px + ((x - px) * i) / steps, py + ((y - py) * i) / steps)
        if (!steps) return
      }
      px = x
      py = y
    }

    const onMove = (e: PointerEvent) => {
      const b = el.getBoundingClientRect()
      trail((e.clientX - b.left) / 2, (e.clientY - b.top) / 2)
    }
    const onLeave = () => { px = null }
    el.addEventListener('pointermove', onMove)
    el.addEventListener('pointerleave', onLeave)
    const ro = new ResizeObserver(resize)
    ro.observe(el)
    resize()

    // One sweep across the letters the first time the footer appears, so people know it reacts.
    let sweep: gsap.core.Tween | null = null
    const io = new IntersectionObserver(([en]) => {
      if (!en.isIntersecting) return
      io.disconnect()
      const pos = { t: 0 }
      sweep = gsap.to(pos, {
        t: 1,
        delay: 0.35,
        duration: 1.5,
        ease: 'power1.inOut',
        onUpdate: () => {
          const y = H * (0.5 + Math.sin(pos.t * 9) * 0.3)
          trail(W * (0.03 + pos.t * 0.94), y)
        },
        onComplete: onLeave,
      })
    }, { threshold: 0.6 })
    io.observe(el)

    return () => {
      cancelAnimationFrame(raf)
      el.removeEventListener('pointermove', onMove)
      el.removeEventListener('pointerleave', onLeave)
      ro.disconnect()
      io.disconnect()
      sweep?.kill()
    }
  }, [shapes])
  return { box, canvas }
}

// Letters roll up on hover, the same mask-roll Heron uses on its footer links.
function RollLink({ to, href, children }: { to?: string; href?: string; children: string }) {
  const onEnter = (e: React.PointerEvent<HTMLElement>) => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    gsap.fromTo(e.currentTarget.querySelectorAll('.fx-char'), { yPercent: 0 }, { yPercent: -100, duration: 0.45, ease: 'power3.inOut', stagger: 0.012, overwrite: true })
  }
  const inner = (
    <>
      <span className="sr-only">{children}</span>
      <span aria-hidden className="fx-chars">
        {children.split('').map((c, i) => <span key={i} className="fx-char" data-c={c}>{c === ' ' ? ' ' : c}</span>)}
      </span>
    </>
  )
  return to
    ? <Link to={to} className="bp-link" onPointerEnter={onEnter}>{inner}</Link>
    : <a href={href} className="bp-link" onPointerEnter={onEnter}>{inner}</a>
}

export function BlueprintFooter() {
  const shapes = useMemo(() => layout(), [])
  const lines = useMemo(() => draftingLines(shapes), [shapes])
  const { box, canvas } = useInk(shapes)

  return (
    <footer className="bp">
      <div className="bp-sheet">
        <span aria-hidden className="bp-rule bp-rule-top" />
        <span aria-hidden className="bp-rule bp-rule-bottom" />
        <span aria-hidden className="bp-cross" style={{ top: 12, left: 12 }} />
        <span aria-hidden className="bp-cross" style={{ top: 12, right: 12 }} />
        <span aria-hidden className="bp-cross" style={{ bottom: 12, left: 12 }} />
        <span aria-hidden className="bp-cross" style={{ bottom: 12, right: 12 }} />

        <div ref={box} className="bp-word" role="img" aria-label="Vectra">
          <canvas ref={canvas} aria-hidden className="absolute inset-0 h-full w-full" />
          <svg viewBox={`0 0 ${VIEW_W} ${VIEW_H}`} aria-hidden className="absolute inset-0 h-full w-full">
            <defs>
              {/* A tiny displacement roughens the lines, so they read as pencil rather than vector. */}
              <filter id="pencil" x="-2%" y="-2%" width="104%" height="104%">
                <feTurbulence type="fractalNoise" baseFrequency="0.55" numOctaves="2" seed="4" />
                <feDisplacementMap in="SourceGraphic" scale="0.8" />
              </filter>
            </defs>
            <path d={lines} fill="none" stroke="#0a1024" strokeWidth="1" vectorEffect="non-scaling-stroke" filter="url(#pencil)" />
          </svg>
        </div>
      </div>

      <div className="bp-bar">
        <p className="bp-note">©2026 Vectra. Built by team Vectra for D3COY 1.0, problem statement 01.</p>
        <nav aria-label="Footer" className="bp-links">
          <RollLink to="/app">Dashboard</RollLink>
          <RollLink href="#score">Risk score</RollLink>
          <RollLink href="#sources">Sources</RollLink>
        </nav>
      </div>
    </footer>
  )
}
