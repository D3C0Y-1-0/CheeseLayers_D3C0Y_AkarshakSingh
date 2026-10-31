import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { fixtures, useAlerts, useData, useOverview, when, type Threat } from './api'
import { DataNotice, Empty, PageHead, Panel, safeReference, SeverityBadge, Unknown } from './ui'

const SOURCE_NAMES: Record<string, string> = { 'nvd+kev': 'NVD + KEV', nvd: 'NVD', kev: 'CISA KEV', certin: 'CERT-In', otx: 'AlienVault OTX', netrax_synthetic: 'Demo fixture' }
const name = (s: string) => SOURCE_NAMES[s] ?? s
type ThreatPage = { items: Threat[]; total: number; page: number; pages: number }
const sample: ThreatPage = { items: fixtures.threats, total: fixtures.threats.length, page: 1, pages: 1 }

function ThreatDetail({ threat, connected, close }: { threat: Threat; connected: boolean; close: () => void }) {
  const record = useData<Threat & { raw_payloads?: { path: string; sha256: string | null }[] }>(
    `/api/threats/${encodeURIComponent(threat.threat_id)}`, threat, (j) => j as Threat)
  return <Panel title={threat.title} className="mb-3"><div className="space-y-3 p-4">
    <button type="button" className="btn-line" onClick={close}>Close details</button>
    <p className="text-white">{threat.description ?? 'Description is not available.'}</p>
    <p>Retrieved {when(threat.retrieved_at)} · {threat.is_simulated ? 'Synthetic threat fixture' : 'Public intelligence record'}</p>
    <p>ATT&amp;CK techniques: {threat.attack_techniques.length ? threat.attack_techniques.join(', ') : 'No verified mapping supplied'}</p>
    <ul className="space-y-1">{threat.references.filter(safeReference).map((url) => <li key={url} className="break-all"><a className="text-blue-300 underline" href={url} target="_blank" rel="noreferrer">{url}</a></li>)}</ul>
    {!!record.data.raw_payloads?.length && <details><summary className="cursor-pointer text-blue-300">Raw payload provenance</summary><ul className="mt-3 space-y-2 text-xs">{record.data.raw_payloads.map((r) => <li key={r.path} className="break-all">{r.path} · {r.sha256 ? `SHA-256: ${r.sha256}` : 'Original raw file absent; hash not verified'}</li>)}</ul></details>}
    {connected && <a className="btn-line inline-block" download={`netrax-${threat.threat_id}.json`} href={`/api/export/stix?threat_id=${encodeURIComponent(threat.threat_id)}`}>Export STIX 2.1</a>}
  </div></Panel>
}

export default function Threats() {
  const [search] = useSearchParams()
  const [query, setQuery] = useState(search.get('search') ?? '')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<Threat | null>(null)
  const overview = useOverview()
  const { data: alerts } = useAlerts()
  const [source, setSource] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [relevant, setRelevant] = useState(false)
  const args = new URLSearchParams({ page: String(page), page_size: '50' })
  if (source !== 'all') args.set('source', source)
  if (severity !== 'all') args.set('severity', severity)
  if (relevant) args.set('relevant', 'true')
  if (query.trim().length >= 2) args.set('q', query.trim())
  const feed = useData<ThreatPage>(`/api/threats?${args}`, sample, (j) => j as ThreatPage)
  const { items: threats, total, pages } = feed.data
  const mode = feed.mode

  const affected = useMemo(() => {
    const map = new Map<string, Set<string>>()
    alerts.forEach((a) => a.threat_ids.forEach((t) => {
      if (!map.has(t)) map.set(t, new Set())
      a.asset_ids.forEach((id) => map.get(t)!.add(id))
    }))
    return map
  }, [alerts])

  const sources = [...new Set([...overview.data.sources.map((s) => s.source), ...threats.map((t) => t.source)])]
  const rows = threats
    .filter((t) => source === 'all' || t.source === source)
    .filter((t) => severity === 'all' || (severity === 'unknown' ? !t.severity : t.severity === severity))
    .filter((t) => !relevant || affected.has(t.threat_id))
    .sort((a, b) => (affected.get(b.threat_id)?.size ?? 0) - (affected.get(a.threat_id)?.size ?? 0))

  return (
    <>
      <PageHead title="Threat Intelligence">
        <div className="flex flex-wrap items-center gap-2">
          <input type="search" className="dash-select" aria-label="Search threats" placeholder="Search CVE or product" value={query} onChange={(e) => { setQuery(e.target.value); setPage(1) }} />
          <select aria-label="Filter by source" className="dash-select" value={source} onChange={(e) => { setSource(e.target.value); setPage(1) }}>
            <option value="all">All sources</option>
            {sources.map((s) => <option key={s} value={s}>{name(s)}</option>)}
          </select>
          <select aria-label="Filter by severity" className="dash-select" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }}>
            <option value="all">All severities</option>
            {['critical', 'high', 'medium', 'low', 'unknown'].map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </select>
          <label className="flex items-center gap-2 text-[0.9375rem] text-white">
            <input type="checkbox" checked={relevant} onChange={(e) => { setRelevant(e.target.checked); setPage(1) }} className="accent-blue" />
            Affects our assets
          </label>
        </div>
      </PageHead>
      <DataNotice mode={feed.mode} error={feed.error} />
      <p className="mb-3">{total.toLocaleString('en-IN')} matching records · Page {page} of {Math.max(1, pages)}</p>
      {selected && <ThreatDetail key={selected.threat_id} threat={selected} connected={mode === 'live'} close={() => setSelected(null)} />}
      <Panel>
        {rows.length === 0 ? <Empty>No threats match these filters. Clear a filter to see more.</Empty> : (
          <div className="overflow-x-auto">
            <table className="dash-table">
              <thead><tr><th>Threat</th><th>Source</th><th>Severity</th><th className="num">CVSS</th><th>KEV</th><th className="num">EPSS</th><th className="num">Affected assets</th><th>Published</th></tr></thead>
              <tbody>
                {rows.map((t) => (
                  <tr key={t.threat_id}>
                    <td className="max-w-[26rem]">
                      <button type="button" className="block font-medium text-blue-300 underline" onClick={() => setSelected(t)}>{t.cve_id ?? t.threat_id}</button>
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
      <div className="mt-3 flex gap-3"><button type="button" className="btn-line" disabled={page <= 1 || mode !== 'live'} onClick={() => setPage((p) => p - 1)}>Previous page</button><button type="button" className="btn-line" disabled={page >= pages || mode !== 'live'} onClick={() => setPage((p) => p + 1)}>Next page</button></div>
    </>
  )
}
