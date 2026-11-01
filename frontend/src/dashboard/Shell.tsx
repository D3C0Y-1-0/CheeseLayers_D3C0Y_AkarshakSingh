import { useEffect } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { Activity, Boxes, ChartNoAxesCombined, Crosshair, Earth, LayoutDashboard, Network, Radar, Siren } from 'lucide-react'
import { Mark } from '../landing/Mark'
import { useHealth } from './api'
import { JourneyRail } from './Visuals'
import UpdateNotice from './UpdateNotice'
import './dashboard.css'
import './visuals.css'

const NAV = [
  { to: '/app', end: true, label: 'Command Center', icon: LayoutDashboard },
  { to: '/app/soc', label: 'Security Operations', icon: Earth },
  { to: '/app/threats', label: 'Threat Intelligence', icon: Radar },
  { to: '/app/assets', label: 'Asset Inventory', icon: Boxes },
  { to: '/app/incidents', label: 'Incidents', icon: Siren },
  { to: '/app/attack-lab', label: 'Attack simulation', icon: Crosshair },
  { to: '/app/signals', label: 'Early warnings', icon: Activity },
  { to: '/app/campaigns', label: 'Campaigns', icon: Network },
  { to: '/app/analytics', label: 'Exposure & impact', icon: ChartNoAxesCombined },
]

export default function Shell() {
  const { pathname } = useLocation()
  const health = useHealth()
  const online = health.mode === 'live' && !health.error
  const local = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(window.location.hostname)
  const stage = pathname.includes('/analytics') ? 4 : pathname.includes('/assets') ? 1 : pathname.includes('/attack-lab') ? 2 : pathname.includes('/incidents') ? 3 : 0

  useEffect(() => {
    window.scrollTo(0, 0)
  }, [pathname])

  return (
    <div className="dash glass">
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
        <div className="sidebar-foot">INDIA-FOCUSED EARLY WARNING<br />Intelligence → service impact
          {local && <a href="/lab" target="_blank" rel="noreferrer">Open owned live lab ↗</a>}
        </div>
      </aside>
      <div className="min-w-0">
        {health.mode !== 'loading' && !online && (
          <p role="status" className="dash-banner">
            Connection interrupted. Panels label bundled samples or the last backend data received. Mutating controls require a connection.
          </p>
        )}
        <main className="dash-main">
          <div className="dash-context"><span>Vectra / Analyst workspace / IST</span><span className={`connection-chip ${online ? '' : 'is-offline'}`}><i aria-hidden />{online ? health.data.demo_mode ? 'API connected · cache mode' : 'API connected' : health.mode === 'loading' ? 'Connecting' : 'Connection unavailable'}</span></div>
          <UpdateNotice />
          {pathname !== '/app/soc' && <div className="dash-story"><JourneyRail active={stage} items={[
            { label: 'Intelligence', detail: 'What is known?', to: '/app/threats' },
            { label: 'Exposure', detail: 'What do we run?', to: '/app/assets' },
            { label: 'Detection', detail: 'What was observed?', to: '/app/attack-lab' },
            { label: 'Investigation', detail: 'What supports it?', to: '/app/incidents' },
            { label: 'Impact', detail: 'What changes risk?', to: '/app/analytics' },
          ]} /></div>}
          <Outlet />
        </main>
      </div>
    </div>
  )
}
