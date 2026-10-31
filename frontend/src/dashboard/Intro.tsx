import { useEffect, useRef } from 'react'
import gsap from 'gsap'

const ARROW = 'M2 2l15 6.4-6.2 2-2.4 6.2z'
const SCALE = 5
const DOT = 7
const SIZE = 20 * SCALE + 14

// Shown once, on the way in from the landing page: a cursor builds itself out of pixels, then types.
export function Intro({ urgent, onDone }: { urgent: number; onDone: () => void }) {
  const root = useRef<HTMLDivElement>(null)
  const pixels = useRef<HTMLCanvasElement>(null)
  const writer = useRef<HTMLDivElement>(null)
  const lineA = useRef<HTMLSpanElement>(null)
  const lineB = useRef<HTMLSpanElement>(null)
  const done = useRef(onDone)
  const message = urgent > 0 ? `${urgent} threat${urgent === 1 ? '' : 's'} need${urgent === 1 ? 's' : ''} you first.` : 'Nothing needs you right now.'

  useEffect(() => {
    const cv = pixels.current!
    const dpr = window.devicePixelRatio || 1
    cv.width = cv.height = SIZE * dpr
    const ctx = cv.getContext('2d')!
    ctx.scale(dpr, dpr)
    const path = new Path2D()
    path.addPath(new Path2D(ARROW), new DOMMatrix().translate(DOT, DOT).scale(SCALE))
    const probe = document.createElement('canvas').getContext('2d')!
    const inside = (x: number, y: number) => probe.isPointInPath(path, x, y)
    const dots: { x: number; y: number; at: number; edge: boolean }[] = []
    for (let y = 0; y < SIZE; y += DOT) {
      for (let x = 0; x < SIZE; x += DOT) {
        if (!inside(x + DOT / 2, y + DOT / 2)) continue
        const edge = [[-DOT, 0], [DOT, 0], [0, -DOT], [0, DOT]].some(([dx, dy]) => !inside(x + DOT / 2 + dx, y + DOT / 2 + dy))
        dots.push({ x, y, at: (Math.hypot(x, y) / SIZE) * 0.45 + Math.random() * 0.12, edge })
      }
    }
    const paint = (t: number) => {
      ctx.clearRect(0, 0, SIZE, SIZE)
      for (const d of dots) {
        const p = Math.min(1, Math.max(0, (t - d.at) / 0.22))
        if (p <= 0) continue
        const e = 1 - (1 - p) ** 3
        const s = DOT * (0.3 + 0.62 * e)
        ctx.fillStyle = d.edge ? `rgb(255 255 255 / ${e})` : `rgb(61 139 255 / ${e})`
        ctx.fillRect(d.x + (DOT - s) / 2, d.y + (DOT - s) / 2, s, s)
      }
    }

    const a = { n: 0 }
    const b = { n: 0 }
    const textA = 'Hi, analyst.'
    const clock = { t: 0 }
    const tl = gsap.timeline({ delay: 0.55, onComplete: () => done.current() })
    tl.to(clock, { t: 0.8, duration: 0.7, ease: 'none', onUpdate: () => paint(clock.t) })
      .to(cv, { opacity: 0, scale: 0.42, duration: 0.3, ease: 'power2.in', transformOrigin: '0 0' })
      .fromTo('.intro-arrow', { opacity: 0, scale: 2.2 }, { opacity: 1, scale: 1, duration: 0.3, ease: 'power3.out', transformOrigin: '0 0' }, '<')
      .fromTo('.intro-tag', { opacity: 0, y: 6 }, { opacity: 1, y: 0, duration: 0.25 }, '<0.1')
      .to(a, { n: textA.length, duration: 0.5, ease: 'none', onUpdate: () => { lineA.current!.textContent = textA.slice(0, Math.round(a.n)) } })
      .to(b, { n: message.length, duration: 0.8, ease: 'none', onUpdate: () => { lineB.current!.textContent = message.slice(0, Math.round(b.n)) } }, '+=0.15')
      .to({}, { duration: 0.55 })
      .to(root.current, { opacity: 0, duration: 0.5, ease: 'power2.inOut' })

    // The cursor follows the end of whatever is being typed.
    const follow = () => {
      // The ticker can fire once more after the greeting unmounts; the refs are gone by then.
      if (!lineA.current || !lineB.current || !writer.current) return
      const active = lineB.current.textContent ? lineB.current : lineA.current
      writer.current!.style.transform = `translate3d(${active.getBoundingClientRect().right + 6}px, ${active.getBoundingClientRect().bottom - 18}px, 0)`
    }
    gsap.ticker.add(follow)

    // Anyone in a hurry can click or press a key to go straight to the board.
    const skip = () => tl.progress(1)
    window.addEventListener('pointerdown', skip)
    window.addEventListener('keydown', skip)
    return () => {
      gsap.ticker.remove(follow)
      window.removeEventListener('pointerdown', skip)
      window.removeEventListener('keydown', skip)
      tl.kill()
    }
  }, [message])

  return (
    <div ref={root} className="intro" role="status" aria-label={`Hi, analyst. ${message}`}>
      <p aria-hidden className="intro-text"><span ref={lineA} className="block min-h-[1em] w-fit" /><span ref={lineB} className="block min-h-[1em] w-fit" /></p>
      <div ref={writer} aria-hidden className="intro-writer">
        <canvas ref={pixels} style={{ width: SIZE, height: SIZE }} className="absolute top-0 left-0" />
        <svg viewBox="0 0 20 20" className="intro-arrow" style={{ opacity: 0 }}><path d={ARROW} /></svg>
        <span className="intro-tag" style={{ opacity: 0 }}>VECTRA</span>
      </div>
    </div>
  )
}
