// Shelved for now: the HydraDB-style scan-line scene. Not imported anywhere. To bring it back, render
// ThreatStage in App.tsx and add its fonts and colour tokens (olive, bone, moss, neon, font-pixel) to index.css.
import { useEffect, useRef, useState } from 'react'
import { MATCH, STEPS, WALKTHROUGH, riskFactors, riskLevel } from './data'
import { createScene } from './engine'
import { Mark } from '../../landing/Mark'

const GLYPHS = '#%/\\01<>=+-_:'

// Headline text "decodes" when a scroll step changes: raw characters resolve into the sentence.
function Decode({ text, reduced }: { text: string; reduced: boolean }) {
  const [shown, setShown] = useState(text)
  useEffect(() => {
    if (reduced) return
    let raf = 0
    const start = performance.now()
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / 520)
      const settled = Math.floor(t * text.length)
      setShown(
        text
          .split('')
          .map((ch, i) => (i < settled || ch === ' ' ? ch : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]))
          .join(''),
      )
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [text, reduced])
  return <span className="block whitespace-pre">{reduced ? text : shown}</span>
}

const { score, exploit, exposure } = riskFactors(WALKTHROUGH)
const FACTORS = [
  { name: 'Severity', value: 'CVSS 10.0', fill: WALKTHROUGH.cvss / 10 },
  { name: 'Exploitation', value: `In KEV, ${exploit.toFixed(2)}`, fill: exploit },
  { name: 'Criticality', value: `${WALKTHROUGH.criticality} of 5`, fill: WALKTHROUGH.criticality / 5 },
  { name: 'Exposure', value: `Public, ${exposure.toFixed(2)}`, fill: exposure },
  { name: 'Confidence', value: `Exact, ${WALKTHROUGH.confidence.toFixed(2)}`, fill: WALKTHROUGH.confidence },
]
const ADVISORY = [
  ['Flaw', 'Command injection in GlobalProtect'],
  ['Product', 'Palo Alto Networks PAN-OS'],
  ['Affected', '11.1 below 11.1.2-h3'],
  ['Status', 'Exploited in the wild, in CISA KEV'],
]
const INVENTORY = [
  ['Role', 'Substation remote-access gateway'],
  ['Software', 'PAN-OS 11.1.2'],
  ['Exposure', 'Internet-facing'],
  ['Criticality', '4 of 5'],
]
const ACTIONS = [
  `Patch ${MATCH.asset} to PAN-OS ${MATCH.fixed}`,
  'Check the GlobalProtect logs for signs of compromise',
  'Look for T1190, exploit of a public-facing application',
]

const seg = (p: number, a: number, b: number) => Math.min(1, Math.max(0, (p - a) / (b - a)))

function Facts({ rows }: { rows: string[][] }) {
  return (
    <dl className="flex min-h-0 flex-1 flex-col text-[0.9375rem] leading-snug">
      {rows.map(([k, v]) => (
        <div key={k} className="grid flex-1 grid-cols-[5.5rem_1fr] items-center gap-2 border-t border-rule px-5">
          <dt className="text-bone/70">{k}</dt>
          <dd className="text-bone">{v}</dd>
        </div>
      ))}
    </dl>
  )
}

export default function ThreatStage() {
  const wrap = useRef<HTMLElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  const scenery = useRef<HTMLDivElement>(null)
  const scoreEl = useRef<HTMLSpanElement>(null)
  const [step, setStep] = useState(0)
  const [reduced] = useState(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches)

  useEffect(() => {
    const scene = createScene(canvas.current!, { reduced })
    const io = new IntersectionObserver(([e]) => scene.setActive(e.isIntersecting))
    io.observe(wrap.current!)

    const onScroll = () => {
      const box = wrap.current!.getBoundingClientRect()
      const p = seg(-box.top, 0, box.height - window.innerHeight)
      scene.setProgress(p)

      let current = 0
      STEPS.forEach((s, i) => { if (p >= s.at) current = i })
      setStep(current)

      // Panel state is written straight to CSS variables: no React re-render per scroll tick.
      const el = scenery.current!
      const alertIn = seg(p, 0.66, 0.69)
      el.style.setProperty('--match', String(Math.min(seg(p, 0.5, 0.53), 1 - alertIn)))
      el.style.setProperty('--inv', String(seg(p, 0.56, 0.59)))
      el.style.setProperty('--verdict', String(seg(p, 0.62, 0.65)))
      el.style.setProperty('--in', String(alertIn))
      // Must match the engine: on phones the line and mark leave as the graph takes the stage.
      el.style.setProperty('--mark', String(window.innerWidth < 760 ? 1 - seg(p, 0.46, 0.52) : 1))
      el.style.setProperty('--fill', String(seg(p, 0.69, 0.84)))
      el.style.setProperty('--acts', String(seg(p, 0.85, 0.9)))
      scoreEl.current!.textContent = String(Math.round(score * seg(p, 0.69, 0.84)))
    }
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll)
    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
      io.disconnect()
      scene.destroy()
    }
  }, [reduced])

  const s = STEPS[step]

  return (
    <section ref={wrap} id="how" aria-label="How a warning is made" className="relative h-[460vh]">
      {/* Screen readers get the whole walkthrough as text, since the scene itself is decorative. */}
      <div className="sr-only">
        <h1>{STEPS[0].title.join(' ')}</h1>
        <p>{STEPS[0].body}</p>
        <ol>
          {STEPS.slice(1).map((x) => (
            <li key={x.at}>{x.title.join(' ')} {x.body}</li>
          ))}
        </ol>
      </div>

      <div className="sticky top-0 flex h-svh flex-col pt-[var(--nav)]">
        <div aria-hidden className="stage-head grid gap-x-10 gap-y-2 border-b border-rule px-5 py-4 lg:grid-cols-[minmax(0,1fr)_24vw] lg:items-end">
          <div className="stage-title font-pixel text-bone">
            <Decode text={s.title[0]} reduced={reduced} />
            <Decode text={s.title[1]} reduced={reduced} />
          </div>
          <p className="max-w-[46ch] text-[0.9375rem] leading-snug text-bone/80">{s.body}</p>
        </div>

        <div ref={scenery} className="relative min-h-0 flex-1">
          <canvas ref={canvas} aria-hidden className="absolute inset-0 h-full w-full" />

          {/* Our mark sits on the scan line: the point where raw data gets read. */}
          <div aria-hidden className="scan-mark absolute z-20 grid size-[1.875rem] place-items-center border border-bone bg-olive text-neon" style={{ opacity: 'var(--mark, 1)' }}>
            <Mark className="size-3.5" />
          </div>

          {/* Left of the line: the two facts being compared, advisory against inventory. */}
          <div aria-hidden className="side-panel match-panel pointer-events-none absolute z-10 bg-olive" style={{ opacity: 'var(--match, 0)' }}>
            <div className="flex min-h-0 flex-1 flex-col border-b border-rule">
              <p className="match-head px-5 pt-2.5 pb-1.5 text-sm text-bone/70">What the advisory says</p>
              <p className="match-name px-5 pb-2 font-pixel text-neon">{MATCH.cve}</p>
              <Facts rows={ADVISORY} />
            </div>
            <div className="flex min-h-0 flex-1 flex-col" style={{ opacity: 'var(--inv, 0)' }}>
              <p className="match-head px-5 pt-2.5 pb-1.5 text-sm text-bone/70">What your inventory says</p>
              <p className="match-name px-5 pb-2 font-pixel text-neon">{MATCH.asset}</p>
              <Facts rows={INVENTORY} />
            </div>
            <p className="bg-neon px-5 py-2 font-semibold text-olive" style={{ opacity: 'var(--verdict, 0)' }}>
              Same product, affected version, exposed.
            </p>
          </div>

          {/* The finished warning. */}
          <div aria-hidden className="side-panel alert-panel pointer-events-none absolute z-10 bg-olive" style={{ opacity: 'var(--in, 0)' }}>
            <div className="flex items-end justify-between gap-4 border-b border-rule px-5 py-2.5">
              <div className="min-w-0">
                <div className="mb-1 flex flex-wrap items-center gap-2 text-sm">
                  <span className="bg-neon px-1.5 py-px font-semibold text-olive">{riskLevel(score)}</span>
                  <span className="text-bone/70">Simulated asset</span>
                </div>
                <p className="alert-title font-semibold leading-tight text-bone">
                  PAN-OS command injection on {MATCH.asset}
                </p>
              </div>
              <span ref={scoreEl} className="alert-score font-pixel leading-[0.85] text-neon">0</span>
            </div>

            <dl className="flex min-h-0 flex-1 flex-col border-b border-rule">
              {FACTORS.map((f) => (
                <div key={f.name} className="alert-row grid flex-1 grid-cols-[6rem_1fr_6.25rem] items-center gap-3 px-5 text-sm">
                  <dt className="text-bone">{f.name}</dt>
                  <dd className="h-1.5 bg-bone/15">
                    <div className="h-full origin-left bg-moss" style={{ transform: `scaleX(calc(var(--fill, 0) * ${f.fill}))` }} />
                  </dd>
                  <dd className="text-right text-bone/80 tabular-nums">{f.value}</dd>
                </div>
              ))}
            </dl>

            <div className="alert-brief flex flex-col gap-2 px-5 py-3 text-[0.9375rem] leading-snug" style={{ opacity: 'var(--acts, 0)' }}>
              <p className="text-bone/90">
                <span className="text-moss">AI summary. </span>
                {MATCH.asset} runs an affected PAN-OS version with GlobalProtect open to the internet, and attackers are already using this flaw. A breach here is a path towards the grid control network.
              </p>
              <ul>
                {ACTIONS.map((a) => (
                  <li key={a} className="flex gap-2 py-0.5 text-bone">
                    <span className="mt-[0.4em] size-1.5 shrink-0 bg-neon" />
                    {a}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
