import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAlerts, useAssets } from './api'
import { DataNotice, Empty, PageHead, Panel, PriorityBadge, Unknown } from './ui'

const RANK = { critical: 0, high: 1, medium: 2, low: 3 }

export default function Assets() {
  const { data: assets, mode, error } = useAssets()
  const { data: alerts } = useAlerts()
  const [sector, setSector] = useState('all')
  const [query, setQuery] = useState('')

  const worst = useMemo(() => {
    const map = new Map<string, typeof alerts>()
    alerts.filter((a) => a.status !== 'resolved').forEach((a) => a.asset_ids.forEach((id) => map.set(id, [...(map.get(id) ?? []), a])))
    map.forEach((list) => list.sort((a, b) => RANK[a.priority] - RANK[b.priority]))
    return map
  }, [alerts])

  const q = query.trim().toLowerCase()
  const rows = assets
    .filter((a) => sector === 'all' || a.sector === sector)
    .filter((a) => !q || [a.asset_id, a.hostname, a.organisation, a.role, ...a.software.map((s) => s.product)].join(' ').toLowerCase().includes(q))
    .sort((a, b) => (worst.has(b.asset_id) ? 1 : 0) - (worst.has(a.asset_id) ? 1 : 0) || b.criticality - a.criticality)

  return (
    <>
      <PageHead title="Asset Inventory">
        <div className="flex flex-wrap items-center gap-2">
          <input type="search" aria-label="Search assets" placeholder="Search assets or software" className="dash-select w-56" value={query} onChange={(e) => setQuery(e.target.value)} />
          <select aria-label="Filter by sector" className="dash-select capitalize" value={sector} onChange={(e) => setSector(e.target.value)}>
            <option value="all">All sectors</option>
            {[...new Set(assets.map((a) => a.sector))].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </PageHead>
      <DataNotice mode={mode} error={error} />
      <Panel>
        {rows.length === 0 ? <Empty>No assets match this search.</Empty> : (
          <div className="overflow-x-auto">
            <table className="dash-table">
              <thead><tr><th>Asset</th><th>Organisation and sector</th><th>Software</th><th className="num">Criticality</th><th>Exposure</th><th className="num">Vulnerabilities</th><th>Investigation</th></tr></thead>
              <tbody>
                {rows.map((a) => {
                  const list = worst.get(a.asset_id) ?? []
                  return (
                    <tr key={a.asset_id}>
                      <td><span className="block font-medium whitespace-nowrap text-white">{a.asset_id}</span><span className="block text-[0.875rem] text-grey-300">{a.role}</span></td>
                      <td><span className="block text-white">{a.organisation}</span><span className="block text-[0.875rem] capitalize text-grey-300">{a.sector}</span></td>
                      <td>{a.software.map((s) => <span key={s.product} className="block whitespace-nowrap">{s.product.replaceAll('_', ' ')} {s.version ?? <Unknown />}</span>)}</td>
                      <td className="num">{a.criticality} of 5</td>
                      <td className="whitespace-nowrap">{a.internet_facing ? <b className="font-medium text-white">Internet-facing</b> : 'Internal'}</td>
                      <td className="num">{list.filter((x) => x.kind === 'vulnerability').length}</td>
                      <td>{list[0]
                        ? <Link to={`/app/incidents/${encodeURIComponent(list[0].alert_id)}`} className="inline-block hover:underline"><PriorityBadge priority={list[0].priority} /></Link>
                        : 'None open'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="border-t border-rule px-4 py-2 text-[0.875rem] text-grey-300">All {assets.length} assets are simulated. Organisation names start with "Sim".</p>
      </Panel>
    </>
  )
}
