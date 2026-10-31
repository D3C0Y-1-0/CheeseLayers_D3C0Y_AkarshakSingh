import { useEffect, useRef, useState } from 'react'
import { MATCH, PRODUCT, WALKTHROUGH, riskFactors, riskLevel } from './data'
import { CARDS_OUT, DROP_START, GATHER_END, HALO_AT, HOLD_END, LIGHT_AT, PIN_END, PROOF_OUT, PLAN_AT, TILES, createOrbit } from './orbit'
import { FxButton } from './FxButton'

const seg = (p: number, a: number, b: number) => Math.min(1, Math.max(0, (p - a) / (b - a)))

const iconFor = (label: string) => TILES.find((t) => t.label === label)!.icon

// Four short lines, not two long ones: the text has to fit inside the ring of tiles.
const STATEMENT: { text: string; mark?: boolean; br?: boolean }[] = [
  { text: 'A' }, { text: 'warning' }, { text: 'after' }, { text: 'the' }, { text: 'breach', br: true },
  { text: 'is' }, { text: 'a' }, { text: 'report.', mark: true, br: true },
  { text: 'A' }, { text: 'warning' }, { text: 'before', mark: true }, { text: 'it', br: true },
  { text: 'is' }, { text: 'a' }, { text: 'patch.', mark: true },
]

const CARDS = [
  {
    title: 'Threat intelligence',
    body: 'Collects advisories, vulnerability databases and indicator feeds, then puts them all in one format.',
    tags: ['CERT-In', 'CISA KEV', 'abuse.ch'],
    icon: iconFor('Threat feeds'),
    href: '#sources',
  },
  {
    title: 'AI analysis',
    body: 'Flags suspicious behaviour even with no known CVE, then explains it using only the stored evidence.',
    tags: ['Shadow Watch', 'Investigation agent', 'ATT&CK'],
    icon: iconFor('Correlation'),
    href: '#scenarios',
  },
  {
    title: 'Ranked warnings',
    body: 'Scores each threat against the systems you run, then says what to patch, block or check.',
    tags: ['Risk score', 'Asset match', 'Mitigation'],
    icon: iconFor('Early warning'),
    href: '#score',
  },
]
const CARD_TIMES = [[PLAN_AT, PLAN_AT + 0.32], [PLAN_AT + 0.24, PLAN_AT + 0.56], [PLAN_AT + 0.48, PLAN_AT + 0.8]]

const score = Math.round(riskFactors(WALKTHROUGH).score)
const PROOF = [
  { words: ['One', 'advisory.'] },
  { words: ['One', 'system', 'you', 'run.'] },
  { words: ['One', 'warning', 'in', 'time.'], blue: true },
]
const PROOF_COUNT = PROOF.reduce((n, l) => n + l.words.length, 0)
// Positions on the version track, in percent. Schematic: spaced to read, not to scale.
const V = { a1: 36, b0: 52, b1: 66, hit: 31, safe: 92 }

export default function Hero() {
  let proofIndex = 0
  const wrap = useRef<HTMLElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  const stage = useRef<HTMLDivElement>(null)
  const chip = useRef<HTMLDivElement>(null)
  const chipLabel = useRef<HTMLSpanElement>(null)
  const words = useRef<HTMLSpanElement[]>([])
  const cards = useRef<HTMLElement[]>([])
  const proofWords = useRef<HTMLSpanElement[]>([])
  const proofCard = useRef<HTMLElement>(null)
  // If WebGL is unavailable the copy still stands on a plain gradient, so the page never breaks.
  const [noWebgl, setNoWebgl] = useState(false)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let orbit: ReturnType<typeof createOrbit> | null = null
    try {
      orbit = createOrbit(canvas.current!, {
        reduced,
        chip: chip.current!,
        chipLabel: chipLabel.current!,
        hubPoint: () => {
          for (const el of document.querySelectorAll('[data-hub]')) {
            const b = el.getBoundingClientRect()
            if (b.width > 0) return { x: b.left + b.width / 2, y: b.top + b.height / 2 }
          }
          return null
        },
      })
      requestAnimationFrame(() => setReady(true))
    } catch {
      queueMicrotask(() => setNoWebgl(true))
    }
    // Letters have different built-in side gaps, so the T, the s and the A would not line up.
    // Each line is nudged by its first letter's real gap, measured from the font itself.
    const alignInk = () => {
      const ctx = document.createElement('canvas').getContext('2d')!
      wrap.current?.querySelectorAll<HTMLElement>('.ink-align').forEach((line) => {
        const st = getComputedStyle(line)
        ctx.font = `${st.fontWeight} ${st.fontSize} ${st.fontFamily}`
        line.style.marginLeft = `${ctx.measureText(line.textContent ?? '').actualBoundingBoxLeft / parseFloat(st.fontSize)}em`
      })
    }
    document.fonts.ready.then(alignInk)

    const io = new IntersectionObserver(([e]) => orbit?.setActive(e.isIntersecting))
    io.observe(wrap.current!)

    const onScroll = () => {
      const box = wrap.current!.getBoundingClientRect()
      const vh = window.innerHeight
      const s = Math.max(0, -box.top) / vh
      orbit?.setScroll(Math.max(0, -box.top))
      const el = stage.current!

      const heroOut = seg(s, HOLD_END - 0.15, HOLD_END + 0.2)
      el.style.setProperty('--hero', String(1 - heroOut))
      el.style.setProperty('--hero-y', `${heroOut * -40}px`)
      el.dataset.about = heroOut > 0.5 ? 'on' : 'off'

      const aboutIn = seg(s, HALO_AT - 0.4, HALO_AT)
      const aboutOut = seg(s, HALO_AT + 0.35, HALO_AT + 0.55)
      el.style.setProperty('--about', String(aboutIn * (1 - aboutOut)))
      el.style.setProperty('--about-y', `${(1 - aboutIn) * 28 - aboutOut * 28}px`)

      // The floor melts into the page colour, so the white stage and the white page below read as one.
      el.style.setProperty('--seam', String(seg(s, LIGHT_AT - 0.25, LIGHT_AT)))
      // Once the sky is white it stays white: the nav and the rest of the page all follow.
      document.documentElement.dataset.stage = s > CARDS_OUT + 0.6 ? 'light' : 'dark'

      // The proof chapter: words sharpen in turn, the card rises, then it all lifts away for the diagram.
      const proofOut = seg(s, PROOF_OUT, PROOF_OUT + 0.32)
      el.style.setProperty('--proof', String(1 - proofOut))
      el.style.setProperty('--proof-y', `${proofOut * -60}px`)
      el.style.setProperty('--veil', String(seg(s, GATHER_END - 0.15, PIN_END - 0.03)))
      proofWords.current.forEach((w, i) => {
        if (!w) return
        const at = LIGHT_AT - 0.3 + (i / PROOF_COUNT) * 0.42
        const on = seg(s, at, at + 0.12)
        w.style.opacity = String(on)
        w.style.filter = on >= 1 ? 'none' : `blur(${(1 - on) * 10}px)`
      })
      const cardIn = seg(s, LIGHT_AT - 0.02, LIGHT_AT + 0.24)
      const proof = proofCard.current!
      proof.style.opacity = String(cardIn)
      proof.style.setProperty('--track', String(seg(s, LIGHT_AT + 0.05, LIGHT_AT + 0.5)))
      proof.style.transform = `translate3d(0, ${(1 - cardIn) * (2 - cardIn) * 56}px, 0)`
      proof.style.pointerEvents = cardIn > 0.9 && proofOut < 0.1 ? 'auto' : 'none'
      proof.style.visibility = cardIn > 0 ? 'visible' : 'hidden'

      // Each word sharpens out of a blur in turn, then key words fill with blue.
      const writeStart = HALO_AT + 0.5
      const writeSpan = DROP_START - writeStart - 0.1
      const statementOut = seg(s, DROP_START, DROP_START + 0.2)
      el.style.setProperty('--statement', String(1 - statementOut))
      words.current.forEach((w, i) => {
        if (!w) return
        const at = writeStart + (i / STATEMENT.length) * writeSpan
        const on = seg(s, at, at + writeSpan * 0.16)
        w.style.opacity = String(on)
        w.style.filter = on >= 1 ? 'none' : `blur(${(1 - on) * 10}px)`
        w.style.setProperty('--mark', String(seg(s, at + writeSpan * 0.1, at + writeSpan * 0.24)))
      })

      // Cards rise in one at a time.
      cards.current.forEach((c, i) => {
        if (!c) return
        const leaving = seg(s, CARDS_OUT, CARDS_OUT + 0.22)
        const on = seg(s, CARD_TIMES[i][0], CARD_TIMES[i][1]) * (1 - leaving)
        const e = 1 - (1 - on) * (1 - on)
        c.style.opacity = String(on)
        c.style.transform = `translate3d(0, ${leaving > 0 ? leaving * -56 : (1 - e) * 72}px, 0)`
        c.style.pointerEvents = on > 0.9 ? 'auto' : 'none'
        // Hidden cards must not catch keyboard focus.
        c.style.visibility = on > 0 ? 'visible' : 'hidden'
      })
    }
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll)
    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
      io.disconnect()
      orbit?.destroy()
      delete document.documentElement.dataset.stage
    }
  }, [])

  return (
    <section ref={wrap} id="top" className="relative" style={{ height: `${(PIN_END + 1) * 100}vh` }}>
      {/* In-page links stop where the warning card has settled, not at the start of the fade. */}
      <span id="warning" aria-hidden className="absolute" style={{ top: `${(LIGHT_AT + 0.42) * 100}vh` }} />
      <div ref={stage} className={`sticky top-0 h-svh overflow-hidden ${noWebgl ? 'hero-fallback' : ''}`}>
        <canvas ref={canvas} aria-hidden className={`hero-canvas absolute inset-0 h-full w-full ${ready ? 'is-ready' : ''}`} />

        <div aria-hidden className="hero-veil pointer-events-none absolute inset-0" />

        <div className="hero-copy absolute">
          <div>
            <p className="hero-slogan ink-align">AI early warning for national cyber defence</p>
            <h1 className="hero-title text-white"><span className="ink-align block">Threats,</span><span className="ink-align block">seen early.</span></h1>
          </div>
          <div className="hero-side">
            <p>{PRODUCT} reads threat feeds, matches them to the systems you run, and warns your team before an attacker gets there.</p>
            <div className="flex flex-wrap gap-2">
              <FxButton to="/app" arrow>Open dashboard</FxButton>
              <FxButton href="#warning" variant="line">See a warning</FxButton>
            </div>
          </div>
        </div>

        <div className="about-copy absolute inset-0 grid place-content-center px-6 text-center">
          <h2 className="about-title text-white">Every feed read.<br />Every warning explained.</h2>
          <p className="mx-auto mt-3 max-w-[42ch] text-[1.125rem] leading-snug text-grey-200">
            Advisories, vulnerability databases, indicator feeds and logs become one ranked list, with a score, a reason and a fix for each threat.
          </p>
        </div>

        <div className="statement-copy absolute inset-0 grid place-content-center px-6 text-center" style={{ opacity: 'var(--statement, 1)' }}>
          <p className="statement-text text-white">
            {STATEMENT.map((w, i) => (
              <span key={i}>
                <span ref={(el) => { if (el) words.current[i] = el }} className={`word ${w.mark ? 'word-mark' : ''}`}>{w.text}</span>
                {w.br ? <br /> : ' '}
              </span>
            ))}
          </p>
        </div>

        <div className="pointer-events-none absolute inset-0 grid place-items-center px-5 pt-[var(--nav)] lg:px-[9vw]">
          <div className="card-row">
            {CARDS.map((c, i) => (
              <article key={c.title} ref={(el) => { if (el) cards.current[i] = el }} className="feature-card" style={{ opacity: 0 }}>
                <div className="feature-visual">
                  <span className="feature-tile">
                    <svg viewBox="0 0 24 24" aria-hidden className="size-8" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d={c.icon} /></svg>
                  </span>
                </div>
                <div className="grid content-start gap-2 px-3.5">
                  <h3 className="text-[clamp(1.5rem,2.2vw,2.125rem)] leading-[1.1] font-normal tracking-[-0.03em]">{c.title}</h3>
                  <p className="text-[1.0625rem] leading-snug text-grey-500">{c.body}</p>
                </div>
                <ul className="feature-tags flex flex-wrap gap-1.5 px-3.5">
                  {c.tags.map((t) => <li key={t}>{t}</li>)}
                </ul>
                <a className="feature-more" href={c.href}>
                  Learn more
                  <svg viewBox="0 0 16 16" aria-hidden className="size-3.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M2 8h11M9 4l4 4-4 4" /></svg>
                </a>
              </article>
            ))}
          </div>
        </div>


        {/* Scenario A, on the white stage. The anchor sits at the moment the card has settled. */}
        <div className="proof-copy pointer-events-none absolute inset-0 grid content-center justify-items-center gap-[2.4vh] px-5 pt-[var(--nav)]">
          <h2 className="proof-title text-center">
            {PROOF.map((line, l) => (
              <span key={l} className={`block ${line.blue ? 'text-blue-fill' : 'text-black'}`}>
                {line.words.map((w) => {
                  const i = proofIndex++
                  return <span key={i}><span ref={(el) => { if (el) proofWords.current[i] = el }} className="word">{w}</span>{' '}</span>
                })}
              </span>
            ))}
          </h2>
          <article ref={proofCard} className="proof-card" style={{ opacity: 0 }}>
            <div className="flex items-end justify-between gap-6">
              <div className="min-w-0">
                <h3 className="proof-card-title">{MATCH.cve}</h3>
                <p className="mt-1 text-grey-200">FortiOS SSL-VPN flaw, exploited in the wild</p>
              </div>
              <p className="proof-verdict"><span className="proof-score">{score}</span>{riskLevel(score)}</p>
            </div>

            {/* The actual decision: where each firewall's version sits against the affected ranges. */}
            <div className="vtrack" role="img" aria-label="FortiOS versions 7.2.0 to below 7.2.7 and 7.4.0 to below 7.4.3 are affected. PWR-FW-01 runs 7.2.6, inside the range, and raises an alert. PWR-FW-02 runs 7.4.11, outside it, and raises none.">
              <span className="vt-pin vt-pin-hit" style={{ left: `${V.hit}%` }}><b>PWR-FW-01</b> runs 7.2.6</span>
              <span className="vt-pin vt-pin-safe" style={{ left: `${V.safe}%` }}><b>PWR-FW-02</b> runs 7.4.11</span>
              <span className="vt-line" />
              <span className="vt-band" style={{ left: 0, width: `${V.a1}%` }} />
              <span className="vt-band" style={{ left: `${V.b0}%`, width: `${V.b1 - V.b0}%` }} />
              <span className="vt-dot vt-dot-hit" style={{ left: `${V.hit}%` }} />
              <span className="vt-dot vt-dot-safe" style={{ left: `${V.safe}%` }} />
              {[[0, '7.2.0'], [V.a1, '7.2.7'], [V.b0, '7.4.0'], [V.b1, '7.4.3']].map(([x, t]) => (
                <span key={t} className={`vt-tick ${x === 0 ? 'vt-tick-first' : ''}`} style={{ left: `${x}%` }}>{t}</span>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
              <FxButton to="/app/incidents/ALR-D6B33680" arrow>Open this warning</FxButton>
              <p className="text-grey-200">Upgrade PWR-FW-01 to {MATCH.fixed} or later. PWR-FW-02 raises no alert.</p>
            </div>
          </article>
        </div>


        <div aria-hidden className="hero-veil-end pointer-events-none absolute inset-0" />

        {/* Follows the hovered tile. Placed by the scene, so it updates without React renders. */}
        <div ref={chip} aria-hidden className="pointer-events-none absolute top-0 left-0 z-10 opacity-0 will-change-transform">
          <span ref={chipLabel} className="chip">Mitigation</span>
        </div>
      </div>
    </section>
  )
}
