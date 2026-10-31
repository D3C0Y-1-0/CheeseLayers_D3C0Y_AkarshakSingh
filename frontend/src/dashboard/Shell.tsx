import { useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { Activity, Boxes, ChartNoAxesCombined, LayoutDashboard, Network, Radar, Siren } from 'lucide-react'
import { Mark } from '../landing/Mark'
import './dashboard.css'

const NAV = [
  { to: '/app', end: true, label: 'Command Center', icon: LayoutDashboard },
  { to: '/app/threats', label: 'Threat Intelligence', icon: Radar },
  { to: '/app/assets', label: 'Asset Inventory', icon: Boxes },
  { to: '/app/incidents', label: 'Incidents', icon: Siren },
  { to: '/app/signals', label: 'Early warnings', icon: Activity },
  { to: '/app/campaigns', label: 'Campaigns', icon: Network },
  { to: '/app/analytics', label: 'Exposure & impact', icon: ChartNoAxesCombined },
]

export default function Shell() {
  const { pathname } = useLocation()
  const [online, setOnline] = useState<boolean | null>(null)
  const [demo, setDemo] = useState(false)
  const [cloud, setCloud] = useState(false)

  useEffect(() => {
    window.scrollTo(0, 0)
  }, [pathname])

  useEffect(() => {
    const check = () => fetch('/health', { signal: AbortSignal.timeout(2500) })
      .then(async (r) => { if (!r.ok) throw new Error('unavailable'); const h = await r.json(); setOnline(h.status === 'ok'); setDemo(h.demo_mode === true); setCloud(h.llm?.cloud_enabled === true) })
      .catch(() => setOnline(false))
    check()
    const t = setInterval(check, 5000)
    return () => clearInterval(t)
  }, [])

  return (
    <div className="dash">
      <aside className="dash-side">
        <Link to="/" className="flex items-center gap-2 px-4 pt-4 pb-5 font-display text-xl font-medium text-white">
          <Mark className="size-5 text-blue" />
          Vectra
        </Link>
        <nav aria-label="Dashboard" className="grid gap-px">
          {NAV.map(({ to, end, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={end} aria-label={label} title={label} className={({ isActive }) => `dash-nav ${isActive ? 'is-on' : ''}`}>
              <Icon aria-hidden className="size-4" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="min-w-0">
        {online && demo && <p className="border-b border-rule px-5 py-2 text-xs text-grey-300">Offline-safe demo · cached public intelligence · simulated assets and behaviour · {cloud ? 'cloud LLM enabled (opt-in), output grounding-checked' : 'cloud LLM off: template or cached AI text'}</p>}
        {online === false && (
          <p role="status" className="dash-banner">
            Backend not connected. Showing bundled sample data: real feed records, simulated assets and hand-built sample alerts.
          </p>
        )}
        <main className="dash-main">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
