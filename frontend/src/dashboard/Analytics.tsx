import { useState } from 'react'
import { Link } from 'react-router-dom'
import { post, useData, type Threat } from './api'
import { DataNotice, Empty, PageHead, Panel, safeReference } from './ui'

type Sector = { sector: string; label: string; total_assets: number; confirmed_affected_assets: number;
  needs_verification_assets: number; active_incidents: number; weighted_sector_risk_score: number; top_threat_ids: string[] }
type Posture = { sectors: Sector[]; data_classification: string; formula: string }
type Impact = { before_affected_count: number; after_affected_count: number; modelled_exposure_reduction_pct: number;
  data_classification: string; notes: string[]; transitions: { asset_id: string; summary: string }[] }
type Cohort = { population: number; flagged_before_kev: number; pct_flagged_before_kev: number; median_lead_days: number | null }
type Lead = { population: number; flagged_before_kev: number; cohorts: { new_cves?: Cohort }; methodology: string[]; limitations: string[] }
type India = { certin_advisories: Threat[]; otx_pulses: Threat[]; ransomware_victims_total: number;
  ransomware_by_sector: Record<string, number>; ransomware_by_group: Record<string, number> }
const blankPosture: Posture = { sectors: [], data_classification: '', formula: '' }
const blankLead: Lead = { population: 0, flagged_before_kev: 0, cohorts: {}, methodology: [], limitations: [] }
const blankIndia: India = { certin_advisories: [], otx_pulses: [], ransomware_victims_total: 0, ransomware_by_sector: {}, ransomware_by_group: {} }

export default function Analytics() {
  const posture = useData<Posture>('/api/sectors/posture', blankPosture, (j) => j as Posture, 5000)
  const lead = useData<Lead>('/api/insights/lead-time?days=90', blankLead, (j) => j as Lead)
  const india = useData<India>('/api/insights/india?limit=5', blankIndia, (j) => j as India)
  const [threat, setThreat] = useState('CVE-2024-21762')
  const [version, setVersion] = useState('7.4.11')
  const [state, setState] = useState<{ busy?: boolean; impact?: Impact; error?: string }>({})
  const cohort = lead.data.cohorts.new_cves
  const simulate = async () => {
    setState({ busy: true })
    try { setState({ impact: await post('/api/simulation/patch-impact', { threat_id: threat, patched_version: version }) as Impact }) }
    catch (e) { setState({ error: e instanceof Error ? e.message : 'Simulation unavailable' }) }
  }
  return <>
    <PageHead title="Exposure & impact" />
    <DataNotice mode={posture.mode} error={posture.error} />
    <p className="mb-4">Sector posture uses the simulated inventory. What-if results do not modify assets, apply patches or change alerts.</p>
    <Panel title="Simulated sector exposure"><div className="overflow-auto"><table className="dash-table"><thead><tr><th>Sector</th><th>Assets</th><th>Confirmed affected</th><th>Needs verification</th><th>Incidents</th><th>Weighted score</th></tr></thead><tbody>{posture.data.sectors.map((s) => <tr key={s.sector}><td className="text-white">{s.label}</td><td>{s.total_assets}</td><td>{s.confirmed_affected_assets}</td><td>{s.needs_verification_assets}</td><td>{s.active_incidents}</td><td><div className="flex min-w-36 items-center gap-2"><span className="h-2 flex-1 bg-white/10"><span className="block h-full bg-blue" style={{ width: `${s.weighted_sector_risk_score}%` }} /></span>{s.weighted_sector_risk_score}</div></td></tr>)}</tbody></table></div><p className="p-4 text-sm">{posture.data.formula}</p></Panel>
    <div className="mt-4 grid items-start gap-4 xl:grid-cols-2">
      <Panel title="What if we patched?"><div className="space-y-3 p-4">
        <label className="grid gap-1">Threat ID<input className="dash-select" value={threat} onChange={(e) => setThreat(e.target.value)} /></label>
        <label className="grid gap-1">Proposed installed version<input className="dash-select" value={version} onChange={(e) => setVersion(e.target.value)} /></label>
        <button type="button" className="btn-line" disabled={state.busy || posture.mode !== 'live' || !version.trim() || !threat.trim()} onClick={simulate}>{state.busy ? 'Modelling…' : 'Model patch impact'}</button>
        <p className="text-sm">This models one CVE’s affected range. It does not establish that a version is free of every vulnerability.</p>
        {state.error && <p role="alert" className="text-sev-high">{state.error}</p>}
        {state.impact && <div role="status" className="space-y-3"><p className="text-white">{state.impact.before_affected_count} → {state.impact.after_affected_count} affected assets · {state.impact.modelled_exposure_reduction_pct}% modelled exposure reduction</p><p className="text-sm">{state.impact.data_classification}</p><ul className="list-inside list-disc space-y-2">{state.impact.transitions.map((t) => <li key={t.asset_id}>{t.summary}</li>)}</ul>{state.impact.notes.map((n) => <p key={n}>{n}</p>)}</div>}
      </div></Panel>
      <Panel title="Early-warning lead-time · 90 days"><div className="space-y-3 p-4">
        <DataNotice mode={lead.mode} error={lead.error} />
        {cohort ? <><p className="font-display text-3xl text-white">{cohort.flagged_before_kev} / {cohort.population}</p><p>Newly published CVEs flagged before KEV confirmation ({cohort.pct_flagged_before_kev}%). Median lead: {cohort.median_lead_days ?? 'unknown'} days among flagged cases.</p><p className="text-sm">New CVEs are the relevant cohort; old vulnerabilities with years-old public exploits can inflate aggregate lead time.</p></> : <Empty>No evaluated cohort available.</Empty>}
        <details><summary className="cursor-pointer text-blue-300">Method and limitations</summary><ul className="mt-3 list-inside list-disc space-y-2">{[...lead.data.methodology, ...lead.data.limitations].map((n) => <li key={n}>{n}</li>)}</ul></details>
      </div></Panel>
      <Panel title="India-focused intelligence" className="xl:col-span-2"><div className="space-y-4 p-4">
        <DataNotice mode={india.mode} error={india.error} />
        <p>{india.mode === 'live' ? india.data.ransomware_victims_total : '—'} public ransomware victim records in the cached dataset. These are source reports, not evidence of compromise in our simulated organisation.</p>
        <div className="grid gap-4 lg:grid-cols-2">{[['CERT-In advisories', india.data.certin_advisories], ['India-related OTX campaigns', india.data.otx_pulses]].map(([heading, records]) => <div key={heading as string}><h3 className="mb-3 text-white">{heading as string}</h3><ul className="space-y-3">{(records as Threat[]).map((t) => <li key={t.threat_id}><Link className="text-blue-300 underline" to={`/app/threats?search=${encodeURIComponent(t.threat_id)}`}>{t.title}</Link>{t.references.filter(safeReference).slice(0, 1).map((r) => <a key={r} className="mt-1 block break-all text-xs" target="_blank" rel="noreferrer" href={r}>{r}</a>)}</li>)}</ul></div>)}</div>
      </div></Panel>
    </div>
  </>
}
