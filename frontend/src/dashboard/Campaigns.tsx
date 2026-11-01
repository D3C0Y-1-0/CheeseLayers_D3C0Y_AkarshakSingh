import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useData, when } from './api'
import { DataNotice, Empty, PageHead, Panel, SeverityBadge } from './ui'
import { Breakdown, DetailFold, Distribution, StatCards } from './Visuals'

type Reason = { type: string; key: string; count: number; text: string }
export type Campaign = { campaign_id: string; title: string; kind?: 'campaign' | 'patch_batch'; size: number; threat_ids: string[]; sources: Record<string, number>
  link_reasons: Reason[]; first_seen: string | null; last_seen: string | null; growth_7d: { last_7d: number; prev_7d: number; ratio: number | null }
  is_emerging: boolean; kev_listed_members: number; affected_asset_ids: string[]; affected_asset_count: number; top_recommended_action: string; is_simulated: boolean }
type Member = { threat_id: string; title: string; source: string; severity: string | null; kev_listed: boolean | null; published_at: string | null; is_simulated: boolean; shared_keys: string[] }
type List = { as_of: string | null; total: number; emerging_total: number; items: Campaign[]; meta: { threats_in_scope: number; method: string; skipped_generic_keys_total: number } }
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`
const KIND = (c: Campaign) => c.kind === 'patch_batch' ? <span className="tag whitespace-nowrap" title="Most members were published on one day by one vendor: a release batch, not attacker activity">Vendor patch batch</span> : c.is_emerging ? <span className="tag">Emerging</span> : <span className="text-grey-400">Stable</span>
const blank: List = { as_of: null, total: 0, emerging_total: 0, items: [], meta: { threats_in_scope: 0, method: '', skipped_generic_keys_total: 0 } }

function Detail({ id }: { id: string }) {
  const d = useData<(Campaign & { members: Member[] }) | null>(`/api/campaigns/${encodeURIComponent(id)}`, null, (j) => j as Campaign & { members: Member[] })
  const c = d.data
  if (!c) return <Panel title="Campaign"><DataNotice mode={d.mode} error={d.error} /><Empty>Loading campaign…</Empty></Panel>
  return <Panel title={c.title}><div className="grid gap-3 p-4">
    <div className="flex flex-wrap gap-2">{c.kind === 'patch_batch' ? <span className="tag">Vendor patch batch: one vendor's same-day release, not attacker activity</span> : c.is_emerging && <span className="tag">Emerging</span>}<span className="tag">{plural(c.size, 'threat', 'threats')}</span><span className="tag">{c.kev_listed_members} KEV-listed</span>{Object.entries(c.sources).map(([s, n]) => <span key={s} className="tag">{s}: {n}</span>)}</div>
    <div className="visual-panel-grid"><Breakdown caption="Member records by canonical source" rows={Object.entries(c.sources).map(([label,value])=>({label,value}))} /><DetailFold title="Shared evidence and grouping explanation" open><ul>{c.link_reasons.map(r=><li key={r.type+r.key}>{r.text}</li>)}</ul></DetailFold></div>
    <p>Seen {when(c.first_seen)} to {when(c.last_seen)} · last 7 days: {c.growth_7d.last_7d} new (previous 7: {c.growth_7d.prev_7d})</p>
    <p className="text-white">{c.top_recommended_action}</p>
    {c.affected_asset_ids.length > 0 && <p>Matched assets (simulated inventory): {c.affected_asset_ids.join(', ')}</p>}
    <div className="overflow-x-auto"><table className="dash-table"><thead><tr><th>Threat</th><th>Source</th><th>Severity</th><th>KEV</th><th>Published</th><th>Shared with group</th></tr></thead><tbody>
      {c.members.map((m) => <tr key={m.threat_id}><td className="max-w-[22rem]"><Link className="text-blue-300 underline" to={`/app/threats?search=${encodeURIComponent(m.threat_id)}`}>{m.threat_id}</Link><span className="block truncate text-[0.875rem] text-grey-300" title={m.title}>{m.title}</span></td><td>{m.source}{m.is_simulated && <span className="tag ml-1.5">Simulated</span>}</td><td><SeverityBadge severity={m.severity} /></td><td>{m.kev_listed === null ? 'Unknown' : m.kev_listed ? 'Listed' : 'No'}</td><td className="whitespace-nowrap">{when(m.published_at)}</td><td className="min-w-[12rem] break-words text-xs">{m.shared_keys.length ? m.shared_keys.join(' · ') : 'similar description text'}</td></tr>)}
    </tbody></table></div>
  </div></Panel>
}

export default function Campaigns() {
  const [params, setParams] = useSearchParams()
  const [emerging, setEmerging] = useState(false)
  const list = useData<List>(`/api/campaigns?limit=200${emerging ? '&emerging=true' : ''}`, blank, (j) => j as List)
  const selected = params.get('id')
  return <>
    <PageHead title="Emerging campaigns">
      <label className="flex items-center gap-2 text-[0.9375rem] text-white"><input type="checkbox" className="accent-blue" checked={emerging} onChange={(e) => setEmerging(e.target.checked)} />Emerging only</label>
    </PageHead>
    <DataNotice mode={list.mode} error={list.error} />
    <StatCards items={[
      { label:'Groups in view',value:list.data.items.length,detail:'Returned by this filtered request' },
      { label:'Emerging in view',value:list.data.items.filter(c=>c.is_emerging&&c.kind!=='patch_batch').length,tone:'teal' },
      { label:'Asset-linked groups',value:list.data.items.filter(c=>c.affected_asset_count>0).length,tone:'amber' },
      { label:'Unique matched assets',value:new Set(list.data.items.flatMap(c=>c.affected_asset_ids)).size,detail:'Across groups in this view' },
    ]} />
    <Panel title="Group composition" className="mb-4"><div className="visual-panel-pad"><Distribution label="listed groups" rows={[
      {label:'Vendor patch batches',value:list.data.items.filter(c=>c.kind==='patch_batch').length,tone:'amber'},
      {label:'Emerging associations',value:list.data.items.filter(c=>c.kind!=='patch_batch'&&c.is_emerging).length,tone:'teal'},
      {label:'Other associations',value:list.data.items.filter(c=>c.kind!=='patch_batch'&&!c.is_emerging).length},
    ]} caption="Shared indicators or text connect these records. A group does not prove a common attacker." /></div></Panel>
    {selected && <div className="mb-3"><button type="button" className="btn-line mb-2" onClick={() => setParams({})}>Close campaign</button><Detail key={selected} id={selected} /></div>}
    <Panel>{list.data.items.length === 0 ? <Empty>No campaigns available.</Empty> : <ul>{list.data.items.map((c) => (
      <li key={c.campaign_id}><button type="button" onClick={() => setParams({ id: c.campaign_id })} className="row-link grid w-full items-center gap-x-4 gap-y-1 text-left md:grid-cols-[9.5rem_minmax(0,1fr)_auto_9rem]">
        <span>{KIND(c)}</span>
        <span className="min-w-0"><span className="line-clamp-2 break-words text-white" title={c.title}>{c.title}</span><span className="block break-words text-[0.875rem] text-grey-300">{c.link_reasons.slice(0, 2).map((r) => r.text).join(' · ')}</span></span>
        <span className="whitespace-nowrap text-grey-200">{plural(c.size, 'threat', 'threats')} · +{c.growth_7d.last_7d} in 7d</span>
        <span className="whitespace-nowrap md:text-right">{c.affected_asset_count ? `${plural(c.affected_asset_count, 'asset', 'assets')} exposed` : 'No asset match'}</span>
      </button></li>))}</ul>}
    </Panel>
    {list.data.meta.method && <details className="mt-3"><summary className="cursor-pointer text-blue-300">How campaigns are formed</summary><p className="mt-2 text-sm">{list.data.meta.method} {list.data.meta.skipped_generic_keys_total} generic keys were ignored.</p></details>}
  </>
}
