import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import gsap from 'gsap'
import { FxButton } from './FxButton'
import { Mark } from './Mark'
import alerts from '../fixtures/alerts_mock.json'
import threats from '../fixtures/threats_snapshot.json'

// The three questions the problem statement says an analyst needs answered.
const STEPS = [
  { q: 'What is happening?', a: 'Every feed lands in one list, with exploitation signals beside severity, so new threats are easy to spot.' },
  { q: 'Which assets are at risk?', a: 'Each threat is matched to your inventory by product and version, then ranked by what it could do to you.' },
  { q: 'What should we do first?', a: 'Each warning explains itself in plain language and says exactly what to patch, block or check.' },
]
const CYCLE = 7

const label = (p: string) => p[0].toUpperCase() + p.slice(1)
const feed = threats.filter((t) => t.cve_id && t.severity).slice(0, 5)
const atRisk = alerts.filter((a) => a.kind === 'vulnerability' && a.risk_score !== null && a.risk_score > 25)
const lead = alerts[0]

function Feed() {
  return (
    <ul>
      {feed.map((t) => (
        <li key={t.threat_id} className="pv-row pv-row-feed pv-rise">
          <span className="min-w-0"><b className="pv-id">{t.cve_id}</b><span className="pv-sub truncate">{t.title.split(': ').pop()}</span></span>
          <span className="pv-hide-sm text-grey-300">{t.kev_listed ? 'In CISA KEV' : 'Not in KEV'}</span>
          <span className={`sev sev-${t.severity}`}>{label(t.severity as string)}</span>
        </li>
      ))}
    </ul>
  )
}

function Assets() {
  return (
    <ul>
      {atRisk.map((a) => (
        <li key={a.alert_id} className="pv-row pv-row-assets pv-rise">
          <span className="pv-score">{a.risk_score}</span>
          <span className="min-w-0"><b className="pv-id">{a.asset_ids[0]}</b><span className="pv-sub truncate">{a.threat_ids[0]}</span></span>
          <span className={`sev sev-${a.priority}`}>{label(a.priority)}</span>
        </li>
      ))}
      <li className="pv-row pv-row-assets pv-rise">
        <span className="pv-score text-grey-400">0</span>
        <span className="min-w-0"><b className="pv-id">PWR-FW-02</b><span className="pv-sub">Patched twin, no match</span></span>
        <span className="sev sev-low">No alert</span>
      </li>
    </ul>
  )
}

function Plan() {
  return (
    <div className="grid gap-4 p-5">
      <div className="pv-rise">
        <p className="mb-1 text-blue-300">Why this needs attention</p>
        <p className="text-[1.125rem] leading-snug text-white">{lead.reasons.join('. ')}.</p>
      </div>
      <div className="pv-rise">
        <p className="mb-1.5 text-blue-300">Do this first</p>
        <ul className="grid gap-1.5">
          {lead.recommended_actions.map((x) => (
            <li key={x} className="flex gap-2.5 text-white"><span aria-hidden className="mt-[0.5em] size-1.5 shrink-0 bg-blue" />{x}</li>
          ))}
        </ul>
      </div>
      <p className="pv-rise text-grey-300">Still unverified: {lead.limitations[0].toLowerCase()}.</p>
    </div>
  )
}

export function Preview() {
  const section = useRef<HTMLElement>(null)
  const screen = useRef<HTMLDivElement>(null)
  const bar = useRef<HTMLSpanElement>(null)
  const [active, setActive] = useState(0)
  const [auto, setAuto] = useState(true)
  const [inView, setInView] = useState(false)
  const [reduced] = useState(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches)

  // The window starts tilted back and lies flat as it rises into view. Nothing pins, so no extra scroll.
  useEffect(() => {
    const el = section.current!
    const update = () => {
      const box = el.getBoundingClientRect()
      const vh = window.innerHeight
      const p = reduced ? 1 : Math.min(1, Math.max(0, (vh - box.top - vh * 0.1) / (vh * 0.75)))
      el.style.setProperty('--tilt', p.toFixed(3))
    }
    update()
    window.addEventListener('scroll', update, { passive: true })
    window.addEventListener('resize', update)
    const io = new IntersectionObserver(([e]) => setInView(e.isIntersecting), { threshold: 0.45 })
    io.observe(el)
    return () => {
      window.removeEventListener('scroll', update)
      window.removeEventListener('resize', update)
      io.disconnect()
    }
  }, [reduced])

  // Moves through the questions on its own until someone picks one.
  useEffect(() => {
    if (!auto || !inView || reduced) return
    const tween = gsap.fromTo(bar.current, { scaleX: 0 }, {
      scaleX: 1,
      duration: CYCLE,
      ease: 'none',
      onComplete: () => setActive((a) => (a + 1) % STEPS.length),
    })
    return () => { tween.kill() }
  }, [active, auto, inView, reduced])

  useLayoutEffect(() => {
    if (reduced) return
    const ctx = gsap.context(() => {
      gsap.from('.pv-rise', { y: 18, opacity: 0, duration: 0.55, ease: 'power3.out', stagger: 0.06 })
    }, screen)
    return () => ctx.revert()
  }, [active, reduced])

  return (
    <section ref={section} id="dashboard" className="scroll-mt-[var(--nav)] grid items-center gap-x-12 gap-y-8 px-5 py-14 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.75fr)] lg:px-8">
      <div>
        <h2 className="section-title mb-6 text-ink">One screen for the three questions that matter</h2>
        <div role="tablist" aria-label="Analyst questions" className="mb-7 border-t border-rule">
          {STEPS.map((s, i) => (
            <div key={s.q} className="relative border-b border-rule">
              <button type="button" role="tab" aria-selected={i === active} className={`pv-tab ${i === active ? 'is-on' : ''}`} onClick={() => { setActive(i); setAuto(false) }}>
                {s.q}
              </button>
              <div className={`pv-answer ${i === active ? 'is-on' : ''}`}><div className="min-h-0 overflow-hidden"><p className="pb-4 leading-snug text-muted">{s.a}</p></div></div>
              {i === active && auto && !reduced && <span ref={bar} aria-hidden className="pv-progress" />}
            </div>
          ))}
        </div>
        <FxButton to="/app" arrow>Open dashboard</FxButton>
      </div>

      <div className="pv-stage">
        <div className="pv-window">
          <div className="pv-chrome">
            <span className="flex shrink-0 items-center gap-2 font-medium text-white"><Mark className="size-4 text-blue" />Vectra</span>
            <span className="min-w-0 truncate text-grey-300">{['Threat Intelligence', 'Asset Inventory', 'Incident PWR-FW-01'][active]}</span>
            <span className="pv-sample">Sample data</span>
          </div>
          <div ref={screen} key={active} role="tabpanel" className="pv-screen">
            {active === 0 && <Feed />}
            {active === 1 && <Assets />}
            {active === 2 && <Plan />}
          </div>
        </div>
      </div>
    </section>
  )
}
