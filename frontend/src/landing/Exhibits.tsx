import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import gsap from 'gsap'
import { WALKTHROUGH, riskFactors } from './data'
import events from '../fixtures/events.json'

const clamp = (v: number) => Math.min(1, Math.max(0, v))
const seg = (p: number, a: number, b: number) => clamp((p - a) / (b - a))
const ease = (t: number) => 1 - (1 - t) * (1 - t) * (1 - t)

const byId = (id: string) => events.find((e) => e.event_id === id)!
const clock = (id: string) => byId(id).timestamp.slice(11, 16)
const walk = riskFactors(WALKTHROUGH)
const FACTORS: [string, number, string][] = [
  ['Severity', WALKTHROUGH.cvss / 10, 'CVSS 9.8'],
  ['Exploitation', walk.exploit, 'In KEV'],
  ['Criticality', WALKTHROUGH.criticality / 5, '5 of 5'],
  ['Exposure', walk.exposure, 'Public'],
  ['Match', WALKTHROUGH.confidence, 'Exact'],
]

function ScreenA() {
  return (
    <div className="sc sc-a">
      <p className="sc-head">Vectra<i />Known flaw</p>
      <p className="sc-big mb-[0.6cqw]">{Math.round(walk.score)} of 100, Critical</p>
      <p className="mb-[2.4cqw]">CVE-2024-21762 on PWR-FW-01, FortiOS 7.2.6</p>
      <div className="sc-bars">
        {FACTORS.map(([name, v, note]) => (
          <div key={name} className="sc-bar">
            <span>{name}</span>
            <i><b style={{ width: `${v * 100}%` }} /></i>
            <span className="text-right">{note}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function ScreenB() {
  const rows = [
    ['EVT-0001', '/appointments/upload.php?file=../../tmp/x.php', 'Path traversal at 7x normal request rate'],
    ['EVT-0002', 'php-fpm8.3 spawned /bin/sh', 'A web worker should never start a shell'],
    ['EVT-0003', '203.0.113.250 on port 4444', 'First time this asset has contacted it'],
  ]
  return (
    <div className="sc sc-b">
      <p className="sc-head">Vectra<i />No known CVE</p>
      <p className="sc-big">Suspected activity on HLT-WEB-01</p>
      <div className="sc-chain">
        {rows.map(([id, what, why]) => (
          <div key={id} className="sc-event">
            <span className="text-blue-300 tabular-nums">{clock(id)}</span>
            <span><code>{what}</code><span className="text-grey-300">{why}</span></span>
          </div>
        ))}
      </div>
    </div>
  )
}

// Schematic from what EVT-0005 records: 2,100 requests a minute against a baseline of 300, in the window.
function ScreenC() {
  return (
    <div className="sc sc-c">
      <p className="sc-head">Vectra<i />Approved change</p>
      <p className="sc-big">Not escalated</p>
      <p className="mt-[0.6cqw]">7x traffic on BNK-NET-01, inside window CHG-2026-1031-07</p>
      <svg className="sc-chart" viewBox="0 0 700 170" preserveAspectRatio="none" aria-hidden>
        <rect x="210" y="0" width="280" height="170" fill="#2271e3" opacity="0.1" />
        <path d="M0 150H210V30H490V150H700V170H0Z" fill="#2271e3" opacity="0.28" />
        <path d="M0 150H210V30H490V150H700" fill="none" stroke="#2271e3" strokeWidth="3" vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="sc-axis">
        <span>Baseline 300 a minute</span>
        <span className="flex justify-between"><span>02:00</span><span>2,100 a minute</span><span>04:00</span></span>
      </div>
    </div>
  )
}

const EXHIBITS = [
  {
    name: 'A known flaw',
    body: 'A new KEV entry is checked against your inventory. The vulnerable firewall raises a warning and its patched twin stays quiet, so nobody chases a false match.',
    meta: 'Real CVE, simulated asset',
    href: '/app/incidents/ALR-PWR-FW-01-CVE-2024-21762',
    screen: <ScreenA />,
    label: 'Open the PWR-FW-01 warning',
    // Screens of scrolling, measured from when the section reaches the top of the window.
    in: [-0.55, -0.1],
    out: [0.72, 1.02],
  },
  {
    name: 'No CVE at all',
    body: 'Three sensor events land on one web server within four minutes. No advisory exists, yet together they open an investigation that says what it still cannot prove.',
    meta: 'Simulated sensor events',
    href: '/app/incidents/ALR-BEH-HLT-WEB-01',
    screen: <ScreenB />,
    label: 'Open the HLT-WEB-01 investigation',
    in: [0.9, 1.3],
    out: [1.72, 2.02],
  },
  {
    name: 'False alarm',
    body: 'A 7x traffic spike would normally page someone. An approved change window explains it, so the alert stays low and the reasoning stays on record.',
    meta: 'Simulated sensor events',
    href: '/app/incidents/ALR-BEH-BNK-NET-01',
    screen: <ScreenC />,
    label: 'Open the BNK-NET-01 record',
    in: [1.9, 2.3],
    out: [99, 100],
  },
]
const PINNED = 2.75

export function Exhibits() {
  const section = useRef<HTMLElement>(null)
  const stage = useRef<HTMLDivElement>(null)
  const screens = useRef<HTMLDivElement[]>([])
  const copies = useRef<HTMLDivElement[]>([])
  const tilts = useRef<HTMLAnchorElement[]>([])
  const [reduced] = useState(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches)

  useEffect(() => {
    const update = () => {
      const box = section.current!.getBoundingClientRect()
      const s = -box.top / window.innerHeight
      const wide = window.innerWidth >= 900
      // The floor drifts under the screens and turns a little, as if the camera walks past them.
      stage.current!.style.setProperty('--floor-y', `${s * 220}px`)
      stage.current!.style.setProperty('--floor-z', `${-8 - s * 3}deg`)
      // The floor melts into the page before the section scrolls away, so no edge shows.
      stage.current!.style.setProperty('--ex-end', String(seg(s, PINNED - 0.4, PINNED)))
      EXHIBITS.forEach((ex, i) => {
        const up = reduced ? (s >= ex.in[1] ? 1 : 0) : ease(seg(s, ex.in[0], ex.in[1]))
        const gone = reduced ? (s >= ex.out[1] ? 1 : 0) : seg(s, ex.out[0], ex.out[1])
        const scr = screens.current[i]
        const cp = copies.current[i]
        // Hinged at its foot: it stands up from the floor, and leaves by sliding off along it.
        const yaw = wide ? -9 + (s - ex.in[1]) * 2.6 : 0
        const hinge = (1 - up) * -84
        scr.style.transform = `translate3d(${gone * -34}vw, 0, ${gone * -420}px) rotateY(${yaw}deg) rotateX(${hinge}deg)`
        const shown = Math.min(seg(up, 0.05, 0.4), 1 - seg(gone, 0.45, 1))
        scr.style.opacity = String(shown)
        scr.style.visibility = shown > 0.002 ? 'visible' : 'hidden'
        const copyOn = Math.min(seg(s, ex.in[1] - 0.2, ex.in[1] + 0.02), 1 - seg(gone, 0, 0.5))
        const rise = (1 - copyOn) * (gone > 0 ? -24 : 28)
        cp.style.opacity = String(reduced ? (up && !gone ? 1 : 0) : copyOn)
        cp.style.transform = wide ? `translate3d(0, calc(-50% + ${rise}px), 0)` : `translate3d(0, ${rise}px, 0)`
        cp.style.visibility = copyOn > 0.002 || (reduced && up && !gone) ? 'visible' : 'hidden'
      })
    }
    update()
    window.addEventListener('scroll', update, { passive: true })
    window.addEventListener('resize', update)
    return () => {
      window.removeEventListener('scroll', update)
      window.removeEventListener('resize', update)
    }
  }, [reduced])

  // Hover: the screen leans towards the pointer and lifts off the floor.
  useEffect(() => {
    if (reduced || !window.matchMedia('(hover: hover)').matches) return
    const offs = tilts.current.map((el) => {
      const rx = gsap.quickTo(el, 'rotationX', { duration: 0.7, ease: 'power3.out' })
      const ry = gsap.quickTo(el, 'rotationY', { duration: 0.7, ease: 'power3.out' })
      const lift = gsap.quickTo(el, 'y', { duration: 0.7, ease: 'power3.out' })
      const move = (e: PointerEvent) => {
        const b = el.getBoundingClientRect()
        ry(((e.clientX - b.left) / b.width - 0.5) * 7)
        rx(((e.clientY - b.top) / b.height - 0.5) * -5)
        lift(-10)
      }
      const leave = () => { rx(0); ry(0); lift(0) }
      el.addEventListener('pointermove', move)
      el.addEventListener('pointerleave', leave)
      return () => {
        el.removeEventListener('pointermove', move)
        el.removeEventListener('pointerleave', leave)
        gsap.killTweensOf(el)
      }
    })
    return () => offs.forEach((f) => f())
  }, [reduced])

  return (
    <section ref={section} id="scenarios" className="relative" style={{ height: `${(PINNED + 1) * 100}vh` }}>
      <div ref={stage} className="ex-stage sticky top-0 h-svh overflow-hidden">
        <div aria-hidden className="ex-floor" />
        <div aria-hidden className="ex-end" />
        {EXHIBITS.map((ex, i) => (
          <div key={ex.name}>
            <div ref={(el) => { if (el) screens.current[i] = el }} className="ex-screen">
              <span aria-hidden className="ex-glow" />
              <span aria-hidden className="ex-shadow" />
              <Link ref={(el) => { if (el) tilts.current[i] = el }} to={ex.href} aria-label={ex.label} className="ex-tilt">
                {ex.screen}
              </Link>
            </div>
            <div ref={(el) => { if (el) copies.current[i] = el }} className="ex-copy">
              <h2 className="ex-name text-ink">{ex.name}</h2>
              <p className="ex-body text-muted">{ex.body}</p>
              <p className="text-faint">{ex.meta}</p>
              <Link to={ex.href} className="ex-link text-ink">Open this incident →</Link>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}
