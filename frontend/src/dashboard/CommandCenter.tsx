import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { getJson, notifyRefresh, parseList, post, toTitle, useAlerts, useHealth, useOverview, when, type Alert, type DemoResult } from './api'
import { Intro } from './Intro'
import { DataNotice, Empty, PageHead, Panel, PriorityBadge } from './ui'

const RANK = { critical: 0, high: 1, medium: 2, low: 3 }
const day = (d: string) => d ? new Date(d).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', timeZone: 'UTC' }) : 'no records'

const SIMS = [
  { label: 'Inject known CVE', path: '/api/demo/inject-cve', body: { fixture_id: 'CVE-2024-21762' } },
  { label: 'Inject suspicious behaviour', path: '/api/demo/inject-behaviour', body: { scenario: 'no_cve_suspicious_chain' } },
  { label: 'Inject benign maintenance', path: '/api/demo/inject-behaviour', body: { scenario: 'benign_maintenance' } },
  { label: 'Missing telemetry', path: '/api/demo/inject-behaviour', body: { scenario: 'missing_telemetry' } },
]

// These always call the real backend. They never fake a result in the browser.
function SimControls() {
  const health = useHealth()
  const enabled = health.mode === 'live' && health.data.demo_mode
  const [state, setState] = useState<{ busy?: string; msg?: string; bad?: boolean; ids?: string[] }>({})
  const run = async (s: (typeof SIMS)[number]) => {
    setState({ busy: s.label })
    try {
      const result = await post(s.path, s.body) as DemoResult
      if (s.path.endsWith('inject-behaviour')) {
        setState({ ids: result.alert_ids, msg: result.findings.length
          ? `${result.findings.length} evidence-linked findings stored; ${result.alert_ids.length} incident(s) available.`
          : `${result.evidence.length} maintenance observations retained. No suspicious rule fired; no incident escalated.` })
      } else {
        const alerts = parseList<Alert>(await getJson('/api/alerts'))
        setState({ msg: 'Known CVE matched against the simulated inventory.', ids: alerts.filter((a) => a.threat_ids.includes('CVE-2024-21762')).map((a) => a.alert_id) })
      }
      notifyRefresh()
    } catch (e) {
      setState({ msg: e instanceof Error ? e.message : 'Could not run the scenario.', bad: true })
    }
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      {SIMS.map((s) => (
        <button key={s.label} type="button" className="btn-line" disabled={!enabled || !!state.busy} onClick={() => run(s)}>
          {state.busy === s.label ? 'Sending' : s.label}
        </button>
      ))}
      <button type="button" className="btn-line" disabled={!enabled || !!state.busy} onClick={async () => {
        setState({ busy: 'reset' })
        try { await post('/api/demo/reset-alerts'); setState({ msg: 'Demo alerts and sensor events reset. Feed data is retained.' }); notifyRefresh() }
        catch (e) { setState({ msg: e instanceof Error ? e.message : 'Reset failed', bad: true }) }
      }}>Reset demo alerts</button>
      {!enabled && <p className="w-full text-grey-300">Demo controls require a connected backend in demo mode.</p>}
      {state.msg && <p role="status" className={`w-full text-[0.9375rem] ${state.bad ? 'text-sev-high' : 'text-grey-200'}`}>{state.msg}</p>}
      {!!state.ids?.length && <div className="flex w-full flex-wrap gap-3">{state.ids.map((id) => <Link key={id} className="text-blue-300 underline" to={`/app/incidents/${id}`}>Open {id}</Link>)}</div>}
    </div>
  )
}

type TipProps = { active?: boolean; payload?: { payload: { date: string; count: number } }[] }
function Tip({ active, payload }: TipProps) {
  if (!active || !payload?.length) return null
  const { date, count } = payload[0].payload
  return <div className="chart-tip"><b>{count.toLocaleString('en-IN')}</b> new records<br />{day(date)}</div>
}

export default function CommandCenter() {
  const overview = useOverview()
  const alerts = useAlerts()
  const location = useLocation()
  const navigate = useNavigate()
  // The greeting plays only on arrival from the landing page's "Open dashboard".
  const [intro, setIntro] = useState(() => (location.state as { greet?: boolean } | null)?.greet === true && !window.matchMedia('(prefers-reduced-motion: reduce)').matches)

  const open = alerts.data.filter((a) => a.status !== 'resolved')
  const urgent = open.filter((a) => a.priority === 'critical' || a.priority === 'high')
  const matched = new Set(open.flatMap((a) => a.threat_ids))
  const affected = new Set(open.flatMap((a) => a.asset_ids))
  const top = [...open].sort((a, b) => RANK[a.priority] - RANK[b.priority] || (b.risk_score ?? -1) - (a.risk_score ?? -1)).slice(0, 6)
  const o = overview.data

  const tiles = [
    { label: 'Threats received', value: o.threats_received.toLocaleString('en-IN'), to: '/app/threats' },
    { label: 'Matched vulnerabilities', value: matched.size, to: '/app/threats' },
    { label: 'Affected assets', value: affected.size, to: '/app/assets' },
    { label: 'Critical and high', value: urgent.length, to: '/app/incidents', hot: urgent.length > 0 },
  ]

  const finish = () => {
    setIntro(false)
    // Forget the greeting, so a refresh goes straight to the dashboard.
    navigate('.', { replace: true, state: null })
  }

  return (
    <>
      {intro && <Intro urgent={urgent.length} onDone={finish} />}

      <PageHead title="Command Center">
        <SimControls />
      </PageHead>
      <DataNotice mode={overview.mode} error={overview.error} />

      <div className="tiles mb-3">
        {tiles.map((t) => (
          <Link key={t.label} to={t.to} className={`tile ${t.hot ? 'is-hot' : ''}`}>
            <span className="tile-value">{t.value}</span>
            <span className="text-grey-200">{t.label}</span>
          </Link>
        ))}
      </div>

      <div className="grid gap-3 xl:grid-cols-[1.4fr_1fr]">
        <Panel title="Top investigations">
          {top.length === 0 ? <Empty>No open investigations. New alerts appear here within 3 seconds.</Empty> : (
            <ul>
              {top.map((a) => (
                <li key={a.alert_id}>
                  <Link to={`/app/incidents/${encodeURIComponent(a.alert_id)}`} className="row-link grid grid-cols-[5.75rem_1fr_auto] items-center gap-3">
                    <PriorityBadge priority={a.priority} />
                    <span className="min-w-0 truncate text-white">{toTitle(a)}</span>
                    <span className="text-right text-grey-200 tabular-nums">{a.asset_ids[0]}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Advisories by publication date · last 14 days">
          <div role="img" aria-label={`Bar chart of new threat records per day from ${day(o.trend[0]?.date ?? '')}. Highest day: ${Math.max(0, ...o.trend.map((t) => t.count))}.`} className="h-[15.5rem] px-2 pb-2">
            {o.trend.length === 0 ? <Empty>No dated publications in this window.</Empty> : <ResponsiveContainer width="100%" height="100%">
              <BarChart data={o.trend} margin={{ top: 8, right: 8, left: 0, bottom: 0 }} barCategoryGap={3}>
                <XAxis dataKey="date" tickFormatter={day} tick={{ fill: '#b6bac2', fontSize: 12 }} tickLine={false} axisLine={{ stroke: 'rgb(217 220 225 / 0.2)' }} minTickGap={28} />
                <YAxis tick={{ fill: '#b6bac2', fontSize: 12 }} tickLine={false} axisLine={false} width={38} />
                <Tooltip content={<Tip />} cursor={{ fill: 'rgb(146 195 255 / 0.1)' }} />
                <Bar dataKey="count" fill="#3d8bff" radius={[4, 4, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>}
          </div>
        </Panel>

        <Panel title="Source health" className="xl:col-span-2">
          <div className="overflow-x-auto"><table className="dash-table">
            <thead><tr><th>Source</th><th className="num">Records</th><th>Last successful collection</th><th>State</th></tr></thead>
            <tbody>
              {o.sources.map((s) => (
                <tr key={s.source}>
                  <td className="text-white">{s.name}</td>
                  <td className="num">{s.records?.toLocaleString('en-IN') ?? 'Unknown'}</td>
                  <td>{when(s.newest_record)}</td>
                  <td>{s.status === 'cached' ? 'From cached snapshot' : s.status}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </Panel>
      </div>
    </>
  )
}
