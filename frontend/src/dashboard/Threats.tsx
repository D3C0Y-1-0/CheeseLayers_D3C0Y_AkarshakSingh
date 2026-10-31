import { useMemo, useState } from 'react'
import { useAlerts, useThreats, when } from './api'
import { Empty, PageHead, Panel, SeverityBadge, Unknown } from './ui'

const SOURCE_NAMES: Record<string, string> = { 'nvd+kev': 'NVD + KEV', nvd: 'NVD', kev: 'CISA KEV', certin: 'CERT-In', otx: 'AlienVault OTX', netrax_synthetic: 'Demo fixture' }
const name = (s: string) => SOURCE_NAMES[s] ?? s

export default function Threats() {
  const { data: threats, mode } = useThreats()
  const { data: alerts } = useAlerts()
  const [source, setSource] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [relevant, setRelevant] = useState(false)

  const affected = useMemo(() => {
    const map = new Map<string, Set<string>>()
    alerts.forEach((a) => a.threat_ids.forEach((t) => {
      if (!map.has(t)) map.set(t, new Set())
      a.asset_ids.forEach((id) => map.get(t)!.add(id))
    }))
    return map
  }, [alerts])

  const sources = [...new Set(threats.map((t) => t.source))]
  const rows = threats
    .filter((t) => source === 'all' || t.source === source)
    .filter((t) => severity === 'all' || (severity === 'unknown' ? !t.severity : t.severity === severity))
    .filter((t) => !relevant || affected.has(t.threat_id))
    .sort((a, b) => (affected.get(b.threat_id)?.size ?? 0) - (affected.get(a.threat_id)?.size ?? 0))

  return (
    <>
      <PageHead title="Threat Intelligence">
        <div className="flex flex-wrap items-center gap-2">
          <select aria-label="Filter by source" className="dash-select" value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="all">All sources</option>
            {sources.map((s) => <option key={s} value={s}>{name(s)}</option>)}
          </select>
          <select aria-label="Filter by severity" className="dash-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">All severities</option>
            {['critical', 'high', 'medium', 'low', 'unknown'].map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </select>
          <label className="flex items-center gap-2 text-[0.9375rem] text-white">
            <input type="checkbox" checked={relevant} onChange={(e) => setRelevant(e.target.checked)} className="accent-blue" />
            Affects our assets
          </label>
        </div>
      </PageHead>
      <Panel>
        {rows.length === 0 ? <Empty>No threats match these filters. Clear a filter to see more.</Empty> : (
          <div className="overflow-x-auto">
            <table className="dash-table">
              <thead><tr><th>Threat</th><th>Source</th><th>Severity</th><th className="num">CVSS</th><th>KEV</th><th className="num">EPSS</th><th className="num">Affected assets</th><th>Published</th></tr></thead>
              <tbody>
                {rows.map((t) => (
                  <tr key={t.threat_id}>
                    <td className="max-w-[26rem]">
                      <span className="block font-medium text-white">{t.cve_id ?? t.threat_id}</span>
                      <span className="block truncate text-[0.875rem] text-grey-300">{t.title}</span>
                    </td>
                    <td className="whitespace-nowrap">{name(t.source)}{t.is_simulated && <span className="tag ml-1.5">Simulated</span>}</td>
                    <td><SeverityBadge severity={t.severity} /></td>
                    <td className="num">{t.cvss ?? <Unknown />}</td>
                    <td>{t.kev_listed === null ? <Unknown /> : t.kev_listed ? <b className="font-medium text-white">Listed</b> : 'Not listed'}</td>
                    <td className="num">{t.epss === null ? <Unknown /> : `${(t.epss * 100).toFixed(1)}%`}</td>
                    <td className="num">{affected.get(t.threat_id)?.size ?? 'None matched'}</td>
                    <td className="whitespace-nowrap">{when(t.published_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {mode === 'sample' && <p className="border-t border-rule px-4 py-2 text-[0.875rem] text-grey-300">Showing a {threats.length}-record sample of the cached feeds.</p>}
      </Panel>
    </>
  )
}
