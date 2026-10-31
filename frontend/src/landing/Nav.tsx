import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import gsap from 'gsap'
import { ChevronDown, Gauge, Radar, ScanSearch, ShieldCheck, type LucideIcon } from 'lucide-react'
import { FxButton } from './FxButton'
import { Mark } from './Mark'
import { PRODUCT } from './data'

type Item = { title: string; body: string; to?: string; href?: string }
type Menu = {
  label: string
  group: string
  items: Item[]
  feature: { icon: LucideIcon; kicker: string; title: string; body: string; cta: string; to?: string; href?: string }
}

// One menu per objective in the problem statement, in the order an analyst meets them.
const MENUS: Menu[] = [
  {
    label: 'Intelligence',
    group: 'Threat intelligence aggregation',
    items: [
      { title: 'Trusted feeds', body: 'NVD, CISA KEV and FIRST EPSS, joined on the CVE ID with their source dates kept.', href: '#sources' },
      { title: 'Public advisories', body: 'CERT-In advisories written for Indian organisations, read alongside global feeds.', to: '/app/threats' },
      { title: 'Vulnerability data', body: 'Severity, affected versions and exploit signals for every CVE we track.', to: '/app/threats' },
      { title: 'Security logs', body: 'Simulated login, firewall and process events from sensors on your assets.', href: '#scenarios' },
    ],
    feature: { icon: Radar, kicker: 'In the current snapshot', title: '19,695 threat records', body: 'Raw reports from every feed, consolidated into one format.', cta: 'Browse the feed', to: '/app/threats' },
  },
  {
    label: 'Analysis',
    group: 'AI-based threat analysis',
    items: [
      { title: 'Suspicious indicators', body: 'Shadow Watch flags behaviour worth a look, even when no CVE or advisory exists.', href: '#scenarios' },
      { title: 'Attack patterns', body: 'Related events on one asset are linked by time and type into a single investigation.', href: '#scenarios' },
      { title: 'Threat relationships', body: 'Each threat maps to MITRE ATT&CK, so analysts see the technique behind it.', to: '/app/threats' },
    ],
    feature: { icon: ScanSearch, kicker: 'Investigation agent', title: 'Explains from evidence', body: 'AI writes the summary using stored evidence only, and lists what it could not verify.', cta: 'See an investigation', to: '/app/incidents/ALR-BBA4D249' },
  },
  {
    label: 'Warnings',
    group: 'Early warning and risk prioritisation',
    items: [
      { title: 'Early warnings', body: 'Raised on severity, confidence and relevance to the systems you actually run.', href: '#warning' },
      { title: 'Risk ranking', body: 'Exploitability, asset criticality, exposure and evidence, with every factor visible.', href: '#score' },
      { title: 'False alarm control', body: 'Approved maintenance and other context stop harmless spikes from escalating.', href: '#scenarios' },
    ],
    feature: { icon: Gauge, kicker: 'Critical, 98 of 100', title: 'CVE-2024-21762 on PWR-FW-01', body: 'A real exploited flaw matched to a simulated grid firewall.', cta: 'Open this warning', to: '/app/incidents/ALR-D6B33680' },
  },
  {
    label: 'Response',
    group: 'Actionable recommendations',
    items: [
      { title: 'Patch', body: 'The exact fixed version for the affected system, not a generic reminder to update.', to: '/app/incidents/ALR-D6B33680' },
      { title: 'Block', body: 'Outbound destinations and indicators to stop while the investigation runs.', to: '/app/incidents/ALR-BBA4D249' },
      { title: 'Investigate', body: 'Which host to check, what evidence backs it and what is still unknown.', to: '/app/incidents' },
    ],
    feature: { icon: ShieldCheck, kicker: 'Threat dashboard', title: 'Active threats in one place', body: 'Risk levels, affected technologies and alerts for your SOC team.', cta: 'Open dashboard', to: '/app' },
  },
]

function Go({ to, href, className, onClick, children }: { to?: string; href?: string; className?: string; onClick: () => void; children: React.ReactNode }) {
  return to
    ? <Link to={to} className={className} onClick={onClick}>{children}</Link>
    : <a href={href} className={className} onClick={onClick}>{children}</a>
}

export function Nav() {
  const header = useRef<HTMLElement>(null)
  const panel = useRef<HTMLDivElement>(null)
  const scrim = useRef<HTMLDivElement>(null)
  const slider = useRef<HTMLSpanElement>(null)
  const triggers = useRef<HTMLButtonElement[]>([])
  const closeTimer = useRef(0)
  const [active, setActive] = useState<number | null>(null)
  const [shown, setShown] = useState(0)
  const [solid, setSolid] = useState(false)
  const [reduced] = useState(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches)

  useEffect(() => {
    const update = () => setSolid(window.scrollY > document.getElementById('top')!.offsetHeight - window.innerHeight)
    update()
    window.addEventListener('scroll', update, { passive: true })
    window.addEventListener('resize', update)
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setActive(null)
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('scroll', update)
      window.removeEventListener('resize', update)
      window.removeEventListener('keydown', onKey)
      clearTimeout(closeTimer.current)
    }
  }, [])

  const open = (i: number) => {
    clearTimeout(closeTimer.current)
    setActive(i)
    setShown(i)
  }
  const close = () => {
    clearTimeout(closeTimer.current)
    closeTimer.current = window.setTimeout(() => setActive(null), 140)
  }
  const shut = () => {
    clearTimeout(closeTimer.current)
    setActive(null)
  }

  // Panel unrolls, a line slides between the menu names, and the page dims behind it.
  useLayoutEffect(() => {
    const d = reduced ? 0 : 1
    const isOpen = active !== null
    gsap.to(panel.current, { height: isOpen ? 'auto' : 0, duration: 0.5 * d, ease: 'power4.out', overwrite: true })
    gsap.to(scrim.current, { autoAlpha: isOpen ? 1 : 0, duration: 0.35 * d, overwrite: true })
    const line = slider.current!
    if (isOpen) {
      const btn = triggers.current[active!]
      const wasHidden = gsap.getProperty(line, 'opacity') === 0
      const pos = { x: btn.offsetLeft, width: btn.offsetWidth }
      if (wasHidden) gsap.set(line, pos)
      gsap.to(line, { ...pos, opacity: 1, duration: 0.45 * d, ease: 'power3.out', overwrite: true })
    } else {
      gsap.to(line, { opacity: 0, duration: 0.2 * d, overwrite: true })
    }
  }, [active, reduced])

  // New contents rise in one after another when the menu changes.
  useLayoutEffect(() => {
    if (active === null || reduced) return
    const ctx = gsap.context(() => {
      gsap.from('.mega-rise', { y: 16, opacity: 0, duration: 0.5, ease: 'power3.out', stagger: 0.045 })
    }, panel)
    return () => ctx.revert()
  }, [shown, active === null, reduced]) // eslint-disable-line react-hooks/exhaustive-deps

  const m = MENUS[shown]
  const FeatureIcon = m.feature.icon

  return (
    <>
      <div ref={scrim} aria-hidden className="nav-scrim" />
      <header ref={header} onPointerLeave={close} onPointerEnter={() => clearTimeout(closeTimer.current)} className={`nav ${solid ? 'nav-solid' : ''} ${active !== null ? 'nav-open' : ''} fixed inset-x-0 top-0 z-30`}>
        <div className="flex h-[var(--nav)] items-center justify-between px-5 lg:px-8">
          <a href="#top" className="nav-brand">
            <Mark className="size-7 text-blue" />
            {PRODUCT}
          </a>
          <nav aria-label="Main" className="relative hidden h-full items-stretch lg:flex">
            {MENUS.map((x, i) => (
              <button
                key={x.label}
                ref={(el) => { if (el) triggers.current[i] = el }}
                type="button"
                aria-expanded={active === i}
                aria-controls="mega"
                className="nav-item"
                onPointerEnter={(e) => { if (e.pointerType === 'mouse') open(i) }}
                onClick={() => (active === i ? shut() : open(i))}
              >
                {x.label}
                <ChevronDown aria-hidden className={`size-[1.1rem] transition-transform duration-300 ${active === i ? 'rotate-180' : ''}`} />
              </button>
            ))}
            <span ref={slider} aria-hidden className="nav-slider" />
          </nav>
          <FxButton to="/app" className="nav-cta">Open dashboard</FxButton>
        </div>

        <div ref={panel} id="mega" className="mega" inert={active === null}>
          <div className="mega-inner">
            <div className="min-w-0">
              <p className="mega-rise mega-group">{m.group}</p>
              <div className="grid grid-cols-2 gap-x-10 gap-y-1">
                {m.items.map((it) => (
                  <Go key={it.title} to={it.to} href={it.href} onClick={shut} className="mega-rise mega-link">
                    <span className="mega-title">{it.title}</span>
                    <span className="mega-body">{it.body}</span>
                  </Go>
                ))}
              </div>
            </div>
            <Go to={m.feature.to} href={m.feature.href} onClick={shut} className="mega-rise mega-feature">
              <span className="mega-tile"><FeatureIcon aria-hidden strokeWidth={1.5} className="size-9" /></span>
              <span className="min-w-0">
                <span className="mega-group block">{m.feature.kicker}</span>
                <span className="mega-feature-title">{m.feature.title}</span>
                <span className="mega-body mb-3">{m.feature.body}</span>
                <span className="mega-cta">{m.feature.cta}<span aria-hidden className="mega-cta-arrow">→</span></span>
              </span>
            </Go>
          </div>
        </div>
      </header>
    </>
  )
}
