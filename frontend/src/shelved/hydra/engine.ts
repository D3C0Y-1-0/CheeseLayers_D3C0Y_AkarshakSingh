// Canvas scene for the hero: raw fragments cross a scan line and become a linked graph.
// "f" is the axis data flows along and "c" the cross axis. Landscape maps f to x, portrait maps f to y,
// so one set of maths drives both layouts.
import { GRAPH_LABELS, MATCH, RAW_LABELS } from './data'

const OLIVE = '#282C20'
const BONE = '223,225,210'
const MOSS = '182,200,74'
const NEON = '220,255,58'
const PIXEL = '"Geist Pixel"'
const SANS = '"Archivo Variable"'

const ALIVE = 0
const FLYING = 1
const SPENT = 2

type Fragment = {
  x: number; y: number; z: number
  w: number; h: number
  stripes: number
  label: string | null
  state: number
  fade: number
  sf: number; sc: number
  ft: number; dur: number
  node: number
}
type GraphNode = { x: number; y: number; z: number; order: number; hub: boolean; energy: number; f: number; c: number; depth: number }
type Edge = { a: number; b: number; order: number; link: boolean }

const clamp = (v: number, a = 0, b = 1) => Math.min(b, Math.max(a, v))
const seg = (p: number, a: number, b: number) => clamp((p - a) / (b - a))
const ease = (t: number) => t * t * (3 - 2 * t)
const lerp = (a: number, b: number, t: number) => a + (b - a) * t

// Evenly spaced points on a sphere (Fibonacci lattice), so clumps never look accidental.
function spherePoint(i: number, n: number) {
  const y = 1 - (2 * (i + 0.5)) / n
  const r = Math.sqrt(1 - y * y)
  const a = i * 2.399963
  return { x: Math.cos(a) * r, y, z: Math.sin(a) * r }
}

export function createScene(canvas: HTMLCanvasElement, opts: { reduced: boolean }) {
  const ctx = canvas.getContext('2d')!
  let W = 0
  let H = 0
  let portrait = false
  let F = 0, C = 0, lineF = 0, R = 0, gF = 0, gR = 0
  let baseLine = 0, baseG = 0, lineAlpha = 1
  let progress = 0
  let time = 0
  let last = 0
  let raf = 0
  let running = false
  let frags: Fragment[] = []
  let nodes: GraphNode[] = []
  let edges: Edge[] = []

  function build() {
    const count = portrait ? 620 : 1200
    frags = Array.from({ length: count }, (_, i) => {
      const p = spherePoint(i, count)
      const roll = Math.random()
      const big = roll < 0.22
      const unit = R / 260
      return {
        ...p,
        w: (big ? 10 + Math.random() * 20 : 3 + Math.random() * 9) * unit,
        h: (big ? 12 + Math.random() * 24 : 3 + Math.random() * 11) * unit,
        stripes: roll < 0.5 ? 3 + Math.floor(Math.random() * 5) : 0,
        label: null,
        state: ALIVE,
        fade: 1,
        sf: 0, sc: 0, ft: 0, dur: 1, node: 0,
      }
    })
    // Scatter real identifiers through the sphere so the raw side reads as real data.
    RAW_LABELS.forEach((label, i) => {
      frags[Math.floor(((i + 0.5) / RAW_LABELS.length) * frags.length)].label = label
    })

    const nodeCount = portrait ? 110 : 170
    nodes = Array.from({ length: nodeCount }, (_, i) => {
      const p = spherePoint(i, nodeCount)
      return { ...p, order: Math.random(), hub: i % 13 === 0, energy: 0, f: 0, c: 0, depth: 0 }
    })
    const hubs = nodes.map((n, i) => (n.hub ? i : -1)).filter((i) => i >= 0)
    hubs.forEach((h, i) => { nodes[h].order = (i / hubs.length) * 0.35 })
    const edgeCount = portrait ? 170 : 300
    edges = Array.from({ length: edgeCount }, (_, i) => {
      const toHub = Math.random() < 0.55
      const a = toHub ? hubs[Math.floor(Math.random() * hubs.length)] : Math.floor(Math.random() * nodeCount)
      let b = Math.floor(Math.random() * nodeCount)
      if (b === a) b = (b + 1) % nodeCount
      return { a, b, order: i / edgeCount, link: i % 6 === 0 && toHub }
    })
    // Fragments already past the line at load count as spent, so the page opens calm, not in a burst.
    const startF = sphereF(0)
    frags.forEach((fr) => { if (startF + R * fr.x > lineF) fr.state = SPENT })
  }

  function resize() {
    const box = canvas.getBoundingClientRect()
    if (box.width === W && box.height === H && frags.length) return
    W = box.width
    H = box.height
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    canvas.width = Math.round(W * dpr)
    canvas.height = Math.round(H * dpr)
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    portrait = W < 760
    F = portrait ? H : W
    C = portrait ? W : H
    baseLine = lineF = F * (portrait ? 0.3 : 0.38)
    R = portrait ? Math.min(H * 0.2, W * 0.4) : Math.min(W * 0.2, H * 0.44)
    baseG = gF = F * (portrait ? 0.68 : 0.7)
    gR = portrait ? Math.min(H * 0.25, W * 0.44) : Math.min(W * 0.26, H * 0.46)
    build()
    if (opts.reduced) draw(0)
  }

  function sphereF(p: number) {
    return lerp(lineF - R * 0.5, lineF + R * 1.25, ease(seg(p, 0.1, 0.5)))
  }

  const X = (f: number, c: number) => (portrait ? c : f)
  const Y = (f: number, c: number) => (portrait ? f : c)

  function rect(f: number, c: number, w: number, h: number) {
    ctx.fillRect(X(f, c) - w / 2, Y(f, c) - h / 2, w, h)
  }

  function draw(dt: number) {
    const p = progress
    const cMid = C / 2
    ctx.clearRect(0, 0, W, H)

    // Phones have no room beside the line, so once the sphere is spent the graph takes the whole stage.
    const takeover = portrait ? ease(seg(p, 0.46, 0.52)) : 0
    lineF = lerp(baseLine, -2, takeover)
    gF = lerp(baseG, F * 0.5, takeover)
    lineAlpha = 1 - takeover

    const dim = lerp(1, 0.26, ease(seg(p, 0.48, 0.56)))
    const build = lerp(0.6, 1, ease(seg(p, 0.08, 0.42)))
    const linking = ease(seg(p, 0.3, 0.37)) * (1 - ease(seg(p, 0.47, 0.53)))
    const rotG = time * 0.05 + 0.6
    const cg = Math.cos(rotG), sg = Math.sin(rotG)

    // Graph nodes first: fragments in flight need their current position.
    nodes.forEach((n) => {
      const x = n.x * cg - n.z * sg
      const z = n.x * sg + n.z * cg
      n.f = gF + gR * x
      n.c = cMid + gR * n.y
      n.depth = (z + 1) / 2
      n.energy = Math.max(0, n.energy - dt * 1.6)
    })

    ctx.lineWidth = 1
    ctx.strokeStyle = `rgba(${BONE},${0.17 * dim})`
    ctx.beginPath()
    edges.forEach((e) => {
      if (e.order > build) return
      const a = nodes[e.a], b = nodes[e.b]
      if (a.order > build || b.order > build) return
      ctx.moveTo(X(a.f, a.c), Y(a.f, a.c))
      ctx.lineTo(X(b.f, b.c), Y(b.f, b.c))
    })
    ctx.stroke()

    if (linking > 0) {
      ctx.lineWidth = 1.25
      ctx.strokeStyle = `rgba(${MOSS},${0.85 * linking})`
      ctx.beginPath()
      edges.forEach((e) => {
        if (!e.link || e.order > build) return
        const a = nodes[e.a], b = nodes[e.b]
        ctx.moveTo(X(a.f, a.c), Y(a.f, a.c))
        ctx.lineTo(X(b.f, b.c), Y(b.f, b.c))
      })
      ctx.stroke()
    }

    nodes.forEach((n) => {
      if (n.order > build) return
      const size = (n.hub ? 6.5 : 1.6 + n.depth * 1.3) + n.energy * 5
      const colour = n.energy > 0.02 ? MOSS : BONE
      ctx.fillStyle = `rgba(${colour},${(0.3 + 0.7 * n.depth) * dim})`
      rect(n.f, n.c, size, size)
    })

    // Hub labels, visible only while the AI is linking.
    if (linking > 0.01) {
      ctx.font = `12px ${PIXEL}`
      ctx.textBaseline = 'middle'
      let used = 0
      nodes.forEach((n) => {
        if (!n.hub || n.depth < 0.45 || used >= GRAPH_LABELS.length) return
        const label = GRAPH_LABELS[used++]
        const px = X(n.f, n.c) + 9
        const py = Y(n.f, n.c)
        const w = ctx.measureText(label).width
        ctx.fillStyle = `rgba(40,44,32,${0.85 * linking})`
        ctx.fillRect(px - 2, py - 8, w + 4, 16)
        ctx.fillStyle = `rgba(${MOSS},${linking})`
        ctx.fillText(label, px, py)
      })
    }

    // Sphere of raw fragments, and the moment each one crosses the line.
    const rotS = time * 0.12
    const cs = Math.cos(rotS), ss = Math.sin(rotS)
    const sf = sphereF(p)
    const visible = nodes.filter((n) => n.order <= build)
    for (const pass of [0, 1]) {
      for (const fr of frags) {
        const x = fr.x * cs - fr.z * ss
        const z = fr.x * ss + fr.z * cs
        const front = z >= 0
        if (front !== (pass === 1)) continue
        const f = sf + R * x
        const c = cMid + R * fr.y
        const depth = (z + 1) / 2

        if (fr.state === ALIVE && f > lineF) {
          if (opts.reduced) {
            fr.state = SPENT
          } else {
            fr.state = FLYING
            fr.sf = f
            fr.sc = c
            fr.ft = -Math.random() * 0.7 // lingers as debris just past the line
            fr.dur = 0.7 + Math.random() * 0.9
            fr.node = Math.floor(Math.random() * visible.length)
          }
        } else if (fr.state === SPENT && f < lineF) {
          fr.state = ALIVE
          fr.fade = 0
        }

        if (fr.state === ALIVE) {
          fr.fade = Math.min(1, fr.fade + dt * 1.4)
          const a = (0.1 + 0.9 * depth * depth) * fr.fade
          if (fr.label && front) {
            ctx.font = `${Math.max(10, R / 21)}px ${PIXEL}`
            ctx.textBaseline = 'middle'
            const tw = ctx.measureText(fr.label).width
            if (portrait ? f + 8 > lineF || X(f, c) + tw + 4 > W : f + tw + 3 > lineF) continue
            ctx.fillStyle = `rgba(40,44,32,${0.9 * a})`
            ctx.fillRect(X(f, c) - 3, Y(f, c) - 8, tw + 6, 16)
            ctx.fillStyle = `rgba(${NEON},${a})`
            ctx.fillText(fr.label, X(f, c), Y(f, c))
          } else if (fr.stripes) {
            ctx.fillStyle = `rgba(${BONE},${a * 0.85})`
            const row = fr.h / (fr.stripes * 2 - 1)
            for (let s = 0; s < fr.stripes; s++) {
              ctx.fillRect(X(f, c) - fr.w / 2, Y(f, c) - fr.h / 2 + s * row * 2, fr.w, Math.max(1, row))
            }
          } else {
            ctx.fillStyle = `rgba(${BONE},${a})`
            rect(f, c, fr.w, fr.h)
          }
        } else if (fr.state === FLYING) {
          fr.ft += dt / fr.dur
          const node = visible[fr.node % Math.max(1, visible.length)]
          if (!node || fr.ft >= 1) {
            if (node) node.energy = 1
            fr.state = SPENT
            continue
          }
          if (fr.ft < 0) {
            ctx.fillStyle = `rgba(${BONE},${0.45})`
            rect(fr.sf + (-fr.ft) * -6, fr.sc, fr.w * 0.5, fr.h * 0.5)
            continue
          }
          const t = fr.ft * fr.ft * (3 - 2 * fr.ft)
          const tf = lerp(fr.sf, node.f, t)
          const tc = lerp(fr.sc, node.c, t)
          const trail = 0.09
          const bt = Math.max(0, t - trail)
          ctx.strokeStyle = `rgba(${MOSS},${0.55 * (1 - t * 0.5)})`
          ctx.lineWidth = 1
          ctx.beginPath()
          ctx.moveTo(X(lerp(fr.sf, node.f, bt), lerp(fr.sc, node.c, bt)), Y(lerp(fr.sf, node.f, bt), lerp(fr.sc, node.c, bt)))
          ctx.lineTo(X(tf, tc), Y(tf, tc))
          ctx.stroke()
          const s = lerp(Math.min(fr.w, 8), 2, t)
          ctx.fillStyle = `rgba(${BONE},${0.9})`
          rect(tf, tc, s, s)
        }
      }
    }

    drawMatch(p, cMid)
    drawLine()
  }

  // The core demo: advisory, then software, then asset.
  function drawMatch(p: number, cMid: number) {
    const on = ease(seg(p, 0.5, 0.54))
    if (on <= 0) return
    const spots = portrait
      ? [[-0.72, -0.5], [0, 0.08], [0.72, -0.3]]
      : [[-0.72, -0.5], [-0.05, 0.02], [0.62, 0.5]]
    const pts = spots.map(([df, dc]) => ({ f: gF + df * gR, c: cMid + dc * gR }))
    const labels = [
      [MATCH.cve, 'In CISA KEV, EPSS 0.99'],
      [MATCH.product, 'Exact version match'],
      [MATCH.asset, 'Power sector, internet-facing'],
    ]
    const legs = [ease(seg(p, 0.52, 0.58)), ease(seg(p, 0.58, 0.64))]

    ctx.strokeStyle = `rgba(${NEON},1)`
    ctx.lineWidth = 2
    legs.forEach((t, i) => {
      if (t <= 0) return
      const a = pts[i], b = pts[i + 1]
      ctx.beginPath()
      ctx.moveTo(X(a.f, a.c), Y(a.f, a.c))
      ctx.lineTo(X(lerp(a.f, b.f, t), lerp(a.c, b.c, t)), Y(lerp(a.f, b.f, t), lerp(a.c, b.c, t)))
      ctx.stroke()
    })

    const reached = [on, seg(p, 0.57, 0.58), seg(p, 0.63, 0.64)]
    pts.forEach((pt, i) => {
      const a = reached[i]
      if (a <= 0) return
      const px = X(pt.f, pt.c), py = Y(pt.f, pt.c)
      ctx.fillStyle = `rgba(${NEON},${a})`
      ctx.fillRect(px - 7, py - 7, 14, 14)
      ctx.fillStyle = OLIVE
      ctx.fillRect(px - 2, py - 2, 4, 4)

      const [top, sub] = labels[i]
      ctx.textBaseline = 'alphabetic'
      ctx.font = `16px ${PIXEL}`
      const w1 = ctx.measureText(top).width
      ctx.font = `500 13px ${SANS}`
      const w2 = ctx.measureText(sub).width
      const w = Math.max(w1, w2) + 16
      const lx = Math.min(px + 14, W - w - 6)
      const ly = portrait && i === 1 ? py + 12 : py - 56
      ctx.globalAlpha = a
      ctx.fillStyle = OLIVE
      ctx.fillRect(lx, ly, w, 44)
      ctx.strokeStyle = `rgba(${NEON},0.6)`
      ctx.lineWidth = 1
      ctx.strokeRect(lx + 0.5, ly + 0.5, w - 1, 43)
      ctx.fillStyle = `rgb(${NEON})`
      ctx.font = `16px ${PIXEL}`
      ctx.fillText(top, lx + 8, ly + 19)
      ctx.fillStyle = `rgb(${BONE})`
      ctx.font = `500 13px ${SANS}`
      ctx.fillText(sub, lx + 8, ly + 36)
      ctx.globalAlpha = 1
    })

    // The affected asset keeps pinging once matched, so the eye lands on it.
    if (p > 0.64 && !opts.reduced) {
      const t = (time % 1.6) / 1.6
      const last = pts[2]
      const s = 14 + t * 52
      ctx.strokeStyle = `rgba(${NEON},${(1 - t) * 0.8})`
      ctx.lineWidth = 1.5
      ctx.strokeRect(X(last.f, last.c) - s / 2, Y(last.f, last.c) - s / 2, s, s)
    }
  }

  function drawLine() {
    ctx.fillStyle = `rgba(${BONE},${lineAlpha})`
    if (portrait) ctx.fillRect(0, lineF, W, 1)
    else ctx.fillRect(lineF, 0, 1, H)
  }

  function loop(now: number) {
    if (!running) return
    const dt = Math.min(0.05, (now - last) / 1000 || 0)
    last = now
    time += dt
    draw(dt)
    raf = requestAnimationFrame(loop)
  }

  const observer = new ResizeObserver(resize)
  observer.observe(canvas)
  resize()
  // Canvas text does not re-render on its own when a web font arrives.
  document.fonts?.ready.then(() => { if (opts.reduced) draw(0) })

  return {
    setProgress(p: number) {
      progress = p
      if (opts.reduced) draw(0)
    },
    // Called by an IntersectionObserver so the scene uses no CPU once it is off screen.
    setActive(active: boolean) {
      if (opts.reduced || active === running) return
      running = active
      if (active) {
        last = performance.now()
        raf = requestAnimationFrame(loop)
      } else {
        cancelAnimationFrame(raf)
      }
    },
    destroy() {
      running = false
      cancelAnimationFrame(raf)
      observer.disconnect()
    },
  }
}
