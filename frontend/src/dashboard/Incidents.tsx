import { useState } from 'react'
import { Link } from 'react-router-dom'
import { toTitle, useAlerts, when } from './api'
import { Empty, PageHead, Panel, PriorityBadge, Provenance } from './ui'

const RANK = { critical: 0, high: 1, medium: 2, low: 3 }
const STATUS = { new: 'New', ack: 'Acknowledged', resolved: 'Resolved' }

export default function Incidents() {
  const { data: alerts, error, mode } = useAlerts()
  const [kind, setKind] = useState('all')
  const rows = alerts
    .filter((a) => kind === 'all' || a.kind === kind)
    .sort((a, b) => RANK[a.priority] - RANK[b.priority] || (b.risk_score ?? -1) - (a.risk_score ?? -1))

  return (
    <>
      <PageHead title="Incidents">
        <div role="group" aria-label="Filter by type" className="flex gap-px bg-rule p-px">
          {[['all', 'All'], ['vulnerability', 'Known vulnerability'], ['behaviour', 'Behaviour, no CVE']].map(([v, label]) => (
            <button key={v} type="button" aria-pressed={kind === v} onClick={() => setKind(v)} className={`seg ${kind === v ? 'seg-on' : ''}`}>{label}</button>
          ))}
        </div>
      </PageHead>
      {error && mode === 'live' && <p role="status" className="mb-3 text-sev-high">{error}</p>}
      <Panel>
        {rows.length === 0 ? <Empty>No incidents of this type yet.</Empty> : (
          <ul>
            {rows.map((a) => (
              <li key={a.alert_id}>
                <Link to={`/app/incidents/${encodeURIComponent(a.alert_id)}`} className="row-link grid items-center gap-x-4 gap-y-1 md:grid-cols-[5.75rem_3rem_1fr_auto_6.5rem]">
                  <PriorityBadge priority={a.priority} />
                  <span className="font-display text-xl font-light text-white tabular-nums">{a.risk_score ?? <span className="text-grey-400">n/a</span>}</span>
                  <span className="min-w-0">
                    <span className="block truncate text-white">{toTitle(a)}</span>
                    <span className="block truncate text-[0.875rem] text-grey-300">{a.asset_ids.join(', ')}, {when(a.created_at)}</span>
                  </span>
                  <Provenance alert={a} />
                  <span className="text-grey-200 md:text-right">{STATUS[a.status]}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  )
}
