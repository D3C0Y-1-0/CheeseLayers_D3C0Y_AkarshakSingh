import { useState } from 'react'
import { Link } from 'react-router-dom'
import { toTitle, useAlerts, when } from './api'
import { DataNotice, Empty, PageHead, Panel, PriorityBadge, Provenance, TargetCell } from './ui'
import { Breakdown, StatCards } from './Visuals'

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
          {[['all', 'All'], ['vulnerability', 'Known vulnerability'], ['behaviour', 'Behavioural detection']].map(([v, label]) => (
            <button key={v} type="button" aria-pressed={kind === v} onClick={() => setKind(v)} className={`seg ${kind === v ? 'seg-on' : ''}`}>{label}</button>
          ))}
        </div>
      </PageHead>
      <DataNotice mode={mode} error={error} />
      <StatCards items={[
        { label: 'In this view', value: rows.length, detail: 'Includes resolved incidents' },
        { label: 'Need attention', value: rows.filter(a => a.status !== 'resolved').length, detail: 'Open incidents', tone: 'amber' },
        { label: 'Critical / high', value: rows.filter(a => a.status !== 'resolved' && ['high', 'critical'].includes(a.priority)).length, detail: 'Open priority queue', tone: 'red' },
        { label: 'Resolved', value: rows.filter(a => a.status === 'resolved').length, detail: 'Recorded lifecycle state', tone: 'teal' },
      ]} />
      <Panel title="Incident lifecycle in this view" className="mb-4"><div className="visual-panel-pad"><Breakdown rows={[
        { label: 'New', value: rows.filter(a => a.status === 'new').length, tone: 'amber' },
        { label: 'Acknowledged / in review', value: rows.filter(a => a.status === 'ack').length },
        { label: 'Resolved', value: rows.filter(a => a.status === 'resolved').length, tone: 'teal' },
      ]} /></div></Panel>
      <Panel>
        {rows.length === 0 ? <Empty>No incidents of this type yet.</Empty> : (
          <ul>
            {rows.map((a) => (
              <li key={a.alert_id}>
                <Link to={`/app/incidents/${encodeURIComponent(a.alert_id)}`} className="row-link grid items-center gap-x-4 gap-y-1 md:grid-cols-[5.75rem_3rem_1fr_auto_7.5rem_6.5rem]">
                  <PriorityBadge priority={a.priority} />
                  <span className="text-xl text-white tabular-nums">{a.risk_score === null ? <span className="text-grey-400">n/a</span> : Math.round(a.risk_score)}</span>
                  <span className="min-w-0">
                    <span className="block truncate text-white">{toTitle(a)}</span>
                    <span className="block truncate text-[0.875rem] text-grey-300">{a.asset_ids.join(', ') || 'No asset'}, {when(a.created_at)}{a.suppressed ? ', not escalated' : ''}</span>
                  </span>
                  <Provenance alert={a} />
                  <span className="text-grey-200"><TargetCell alert={a} /></span>
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
