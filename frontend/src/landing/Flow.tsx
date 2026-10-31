import { useEffect, useRef, useState } from 'react'
import { Activity, Bell, Crosshair, Database, FileText, Gauge, ListChecks, ScanSearch, ShieldAlert, Sparkles, type LucideIcon } from 'lucide-react'
import { Mark } from './Mark'
import { PRODUCT } from './data'

const clamp = (v: number) => Math.min(1, Math.max(0, v))
const seg = (p: number, a: number, b: number) => clamp((p - a) / (b - a))

// Geometry in the diagram's own 1264 x 440 units.
const MID = 220
const PILL_W = 176
const ROWS = [34, 100, 340, 406]
const LEFT_EDGE = 380
const RIGHT_EDGE = 884
const IN: { label: string; icon: LucideIcon }[] = [
  { label: 'NVD', icon: Database },
  { label: 'CISA KEV', icon: ShieldAlert },
  { label: 'CERT-In', icon: FileText },
  { label: 'Sensor events', icon: Activity },
]
const OUT: { label: string; icon: LucideIcon }[] = [
  { label: 'Risk scores', icon: Gauge },
  { label: 'Early warnings', icon: Bell },
  { label: 'Fix actions', icon: ListChecks },
  { label: 'Evidence trail', icon: ScanSearch },
]
const CORE: { label: string; icon: LucideIcon }[] = [
  { label: 'Match', icon: Crosshair },
  { label: 'Score', icon: Gauge },
  { label: 'Explain', icon: Sparkles },
]

const pct = (v: number, of: number) => `${(v / of) * 100}%`
const inPath = (y: number) => `M${PILL_W} ${y} C${PILL_W + 120} ${y} ${LEFT_EDGE - 130} ${MID} ${LEFT_EDGE} ${MID}`
const outPath = (y: number) => `M${RIGHT_EDGE} ${MID} C${RIGHT_EDGE + 130} ${MID} ${1264 - PILL_W - 120} ${y} ${1264 - PILL_W} ${y}`

function Pill({ label, icon: Icon, style }: { label: string; icon: LucideIcon; style?: React.CSSProperties }) {
  return <div className="flow-pill" style={style}><Icon aria-hidden />{label}</div>
}

function Pulse({ path, delay }: { path: string; delay: number }) {
  return (
    <circle r="3.5" fill="#2271e3">
      <animateMotion dur="3.2s" begin={`${delay}s`} repeatCount="indefinite" path={path} keyPoints="0;1;1" keyTimes="0;0.6;1" calcMode="linear" />
      <animate attributeName="opacity" dur="3.2s" begin={`${delay}s`} repeatCount="indefinite" values="0;1;1;0;0" keyTimes="0;0.05;0.55;0.6;1" />
    </circle>
  )
}

export function Flow() {
  const section = useRef<HTMLElement>(null)
  const [reduced] = useState(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches)

  useEffect(() => {
    const el = section.current!
    const set = (k: string, v: number) => el.style.setProperty(k, v.toFixed(3))
    // No pinning here, so this adds no scroll length: the diagram assembles as it rises into view.
    const update = () => {
      const box = el.getBoundingClientRect()
      const vh = window.innerHeight
      // Timed against the stage above: this section slides over it while the tiles pour into the hub,
      // the hub lights up as they land, then the lines draw outward from it in both directions.
      // The drawing finishes while pinned, then HOLD screens of scrolling leave the whole diagram in place.
      const p = reduced ? 1 : seg(vh - box.top, vh * 0.2, vh * 1.6)
      set('--t', seg(p, 0, 0.22))
      set('--core', seg(p, 0.4, 0.48))
      set('--line-in', seg(p, 0.46, 0.72) - 1)
      set('--pills-in', seg(p, 0.6, 0.78))
      set('--line-out', 1 - seg(p, 0.54, 0.84))
      set('--pills-out', seg(p, 0.74, 1))
      el.dataset.live = p >= 0.98 ? 'on' : 'off'
    }
    update()
    window.addEventListener('scroll', update, { passive: true })
    window.addEventListener('resize', update)
    return () => {
      window.removeEventListener('scroll', update)
      window.removeEventListener('resize', update)
    }
  }, [reduced])

  return (
    <section ref={section} className="flow-wrap">
      <span id="how" aria-hidden className="absolute" style={{ top: '60vh' }} />
      <div className="flow-pin">
      <div className="mx-auto mb-[clamp(1rem,3.5vh,2.5rem)] max-w-[44rem] text-center" style={{ opacity: 'var(--t, 1)', transform: 'translateY(calc((1 - var(--t, 1)) * 24px))' }}>
        <h2 className="section-title mb-4 text-ink">{PRODUCT} sits between the feeds and your analysts</h2>
        <p className="text-[1.0625rem] leading-snug text-muted">
          It collects every advisory and sensor event, checks them against the systems you run, and hands your team only the warnings that apply, with the evidence attached.
        </p>
      </div>

      <div className="flow" aria-label="Threat feeds and sensor events flow into Vectra, which matches, scores and explains them, then outputs scores, warnings, fixes and evidence.">
        <div className="flow-glow" style={{ opacity: 'var(--core, 1)' }} />

        <svg viewBox="0 0 1264 440" className="absolute inset-0 h-full w-full overflow-visible" aria-hidden>
          {ROWS.map((y) => <path key={y} className="flow-line" d={inPath(y)} pathLength={1} style={{ strokeDashoffset: 'var(--line-in, 0)' }} />)}
          <g style={{ opacity: 'var(--core, 1)' }}>
            <path className="flow-line" style={{ strokeDasharray: 'none' }} d={`M474 ${MID} H512 M752 ${MID} H790`} />
          </g>
          {ROWS.map((y) => <path key={y} className="flow-line" d={outPath(y)} pathLength={1} style={{ strokeDashoffset: 'var(--line-out, 0)' }} />)}
          {!reduced && (
            <g className="flow-pulses">
              {ROWS.map((y, i) => <Pulse key={y} path={inPath(y)} delay={i * 0.8} />)}
              {ROWS.map((y, i) => <Pulse key={y} path={outPath(y)} delay={1.6 + i * 0.8} />)}
            </g>
          )}
        </svg>

        {IN.map((n, i) => (
          <Pill key={n.label} {...n} style={{ left: 0, top: pct(ROWS[i], 440), opacity: 'var(--pills-in, 1)', translate: 'calc((1 - var(--pills-in, 1)) * -36px) 0' }} />
        ))}
        {OUT.map((n, i) => (
          <Pill key={n.label} {...n} style={{ right: 0, top: pct(ROWS[i], 440), opacity: 'var(--pills-out, 1)', translate: 'calc((1 - var(--pills-out, 1)) * 36px) 0' }} />
        ))}

        <div style={{ opacity: 'var(--core, 1)' }}>
          <div className="flow-box" style={{ left: pct(LEFT_EDGE, 1264) }}><span className="flow-tile"><Mark className="size-[2.6cqw]" /></span></div>
          <div data-hub className="flow-box" style={{ left: pct(512, 1264) }}>
            {CORE.map(({ label, icon: Icon }) => <span key={label} className="flow-tile" title={label}><Icon aria-hidden strokeWidth={1.5} /></span>)}
          </div>
          <div className="flow-box" style={{ left: pct(790, 1264) }}><span className="flow-tile"><Mark className="size-[2.6cqw]" /></span></div>
          <span className="flow-label" style={{ left: pct(427, 1264) }}>Collect</span>
          <span className="flow-label" style={{ left: pct(632, 1264) }}>Match, score, explain</span>
          <span className="flow-label" style={{ left: pct(837, 1264) }}>Warn</span>
        </div>
      </div>

      {/* Phones get the same three stages stacked. */}
      <div className="flow-phone" style={{ opacity: 'var(--t, 1)' }}>
        <div className="flex flex-wrap justify-center gap-2">{IN.map((n) => <Pill key={n.label} {...n} />)}</div>
        <span aria-hidden className="h-6 w-px bg-blue-fill/40" />
        <div data-hub className="flow-box">{CORE.map(({ label, icon: Icon }) => <span key={label} className="flow-tile" title={label}><Icon aria-hidden strokeWidth={1.5} /></span>)}</div>
        <span className="text-sm text-muted">Match, score, explain</span>
        <span aria-hidden className="h-6 w-px bg-blue-fill/40" />
        <div className="flex flex-wrap justify-center gap-2">{OUT.map((n) => <Pill key={n.label} {...n} />)}</div>
      </div>
      </div>
    </section>
  )
}
