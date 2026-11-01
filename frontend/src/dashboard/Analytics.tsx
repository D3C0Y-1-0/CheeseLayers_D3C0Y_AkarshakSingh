import { useState } from 'react'
import { Link } from 'react-router-dom'
import { post, useData, type Threat } from './api'
import { DataNotice, Empty, PageHead, Panel, safeReference } from './ui'
import { Breakdown, DetailFold, Distribution, StatCards } from './Visuals'

type Sector = { sector: string; label: string; total_assets: number; confirmed_affected_assets: number;
  needs_verification_assets: number; active_incidents: number; weighted_sector_risk_score: number; top_threat_ids: string[] }
type Posture = { sectors: Sector[]; data_classification: string; formula: string }
type Impact = { before_affected_count: number; after_affected_count: number; modelled_exposure_reduction_pct: number;
  data_classification: string; notes: string[]; transitions: { asset_id: string; summary: string }[] }
type Cohort = { population: number; flagged_before_kev: number; pct_flagged_before_kev: number; median_lead_days: number | null }
type Lead = { population: number; flagged_before_kev: number; cohorts: { new_cves?: Cohort }; methodology: string[]; limitations: string[] }
type India = { certin_advisories: Threat[]; otx_pulses: Threat[]; ransomware_victims_total: number;
  ransomware_by_sector: Record<string, number>; ransomware_by_group: Record<string, number> }
type TimelineEvent = { date: string; event: string; detail: string | null; signal: string | null; before_kev: boolean; days_before_kev: number }
type Example = { example: string; cve_id: string; title: string; lead_days: number | null; first_signal: string | null; explanation: string; timeline: TimelineEvent[] }
const EXAMPLE_LABEL: Record<string, string> = { largest_lead: 'Largest lead', near_zero_lead: 'Near-zero lead', miss: 'Missed case' }

function LeadTimelines() {
  const ex = useData<{ examples: Example[]; note: string }>('/api/insights/lead-time/examples?days=90', { examples: [], note: '' }, j => j as { examples: Example[]; note: string })
  return <Panel title="Early-warning examples · strengths and misses" className="xl:col-span-2"><div className="p-4">
    <DataNotice mode={ex.mode} error={ex.error} />
    {!ex.data.examples.length ? <Empty>No dated examples in this evaluation window.</Empty> : <div className="grid gap-4 lg:grid-cols-3">{ex.data.examples.map(e => {
      const dates = e.timeline.map(t => Date.parse(t.date)).filter(Number.isFinite)
      const minimum = Math.min(...dates), span = Math.max(...dates) - minimum
      return <article className="timeline-card" key={e.example}>
        <div className="timeline-card-head"><span className="tag">{EXAMPLE_LABEL[e.example] ?? e.example}</span><strong>{e.lead_days === null ? 'No flag' : `${e.lead_days}d`}</strong></div>
        <Link className="text-blue-300" to={`/app/threats?search=${encodeURIComponent(e.cve_id)}`}>{e.cve_id}</Link>
        <p className="visual-caption mt-2 line-clamp-2">{e.explanation}</p>
        <div className="dated-track" role="img" aria-label={e.timeline.map(t => `${t.date}: ${t.event}`).join('; ')}>{e.timeline.map((t, i) => <i aria-hidden key={i} title={`${t.date}: ${t.event}`} style={{ left: `${span > 0 && Number.isFinite(Date.parse(t.date)) ? (Date.parse(t.date) - minimum) / span * 100 : 50}%`, background: /KEV/.test(t.event) ? '#ff8598' : t.before_kev && t.signal ? '#55d9ba' : '#8592ad' }} />)}</div>
        <p className="visual-caption">{e.timeline[0]?.date ?? 'Unknown'} → {e.timeline[e.timeline.length - 1]?.date ?? 'Unknown'}</p>
        <DetailFold title="Inspect original dated sequence"><p>{e.explanation}</p>{e.timeline.map((t, i) => <div className="evidence-event" key={i}><time>{t.date}{t.before_kev && t.days_before_kev > 0 ? ` · ${t.days_before_kev}d before KEV` : ''}</time><p>{t.event}</p>{t.detail && <small>{t.detail}</small>}</div>)}</DetailFold>
      </article>
    })}</div>}
    {ex.data.note && <p className="visual-caption mt-4">{ex.data.note}</p>}
  </div></Panel>
}

const blankPosture: Posture = { sectors: [], data_classification: '', formula: '' }
const blankLead: Lead = { population: 0, flagged_before_kev: 0, cohorts: {}, methodology: [], limitations: [] }
const blankIndia: India = { certin_advisories: [], otx_pulses: [], ransomware_victims_total: 0, ransomware_by_sector: {}, ransomware_by_group: {} }

export default function Analytics() {
  const posture = useData<Posture>('/api/sectors/posture', blankPosture, j => j as Posture, 5000)
  const lead = useData<Lead>('/api/insights/lead-time?days=90', blankLead, j => j as Lead)
  const india = useData<India>('/api/insights/india?limit=5', blankIndia, j => j as India)
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
    <p className="page-lead">Compare service exposure, model a patch decision and inspect the evidence behind early-warning claims.</p>
    <DataNotice mode={posture.mode} error={posture.error} />
    <Panel title="Sector exposure · simulated inventory" className="mb-4">
      <div className="sector-card-grid">{posture.data.sectors.map(s => <article className="sector-card" key={s.sector}>
        <header><span>{s.label}</span><b>{s.weighted_sector_risk_score.toFixed(1)} / 100</b></header>
        <Breakdown maximum={Math.max(1, s.total_assets)} rows={[
          { label: 'Confirmed affected', value: s.confirmed_affected_assets, tone: 'red' },
          { label: 'Needs verification', value: s.needs_verification_assets, tone: 'amber' },
        ]} /><footer><span>{s.total_assets} assets</span><span>{s.active_incidents} open incidents</span></footer>
      </article>)}</div>
      {!posture.data.sectors.length && <Empty>No sector posture available.</Empty>}
      <DetailFold title="Score formula and classification"><p>{posture.data.data_classification}</p><p>{posture.data.formula}</p></DetailFold>
    </Panel>
    <div className="grid items-start gap-4 xl:grid-cols-2">
      <Panel title="Patch impact · what-if model"><div className="p-4 grid gap-3">
        <div className="grid gap-3 sm:grid-cols-2"><label className="grid gap-1 text-sm">Threat ID<input className="dash-select" value={threat} onChange={e => setThreat(e.target.value)} /></label>
          <label className="grid gap-1 text-sm">Proposed installed version<input className="dash-select" value={version} onChange={e => setVersion(e.target.value)} /></label></div>
        <button type="button" className="btn-line w-fit" disabled={state.busy || posture.mode !== 'live' || !version.trim() || !threat.trim()} onClick={simulate}>{state.busy ? 'Modelling…' : 'Compare before / after'}</button>
        <p className="visual-caption">Read-only model for this CVE. Actual lab replacement and verification are separate controls.</p>
        {state.error && <p role="alert" className="text-sev-high">{state.error}</p>}
        {state.impact && <div role="status" className="grid gap-3">
          <div className="impact-compare"><div><strong>{state.impact.before_affected_count}</strong><small>Affected before</small></div><span aria-hidden>→</span><div><strong>{state.impact.after_affected_count}</strong><small>Affected after</small></div></div>
          <p className="text-white">{state.impact.modelled_exposure_reduction_pct}% modelled exposure reduction</p>
          <DetailFold title="Asset transitions and modelling limits"><p>{state.impact.data_classification}</p><ul>{state.impact.transitions.map(t => <li key={t.asset_id}>{t.summary}</li>)}</ul>{state.impact.notes.map(n => <p key={n}>{n}</p>)}</DetailFold>
        </div>}
      </div></Panel>
      <Panel title="Early-warning evidence · 90-day backtest"><div className="p-4 grid gap-4">
        <DataNotice mode={lead.mode} error={lead.error} />
        {cohort ? <><Distribution label="new CVEs" rows={[
          { label: 'Flagged before KEV', value: cohort.flagged_before_kev, tone: 'teal' },
          { label: 'Not flagged before KEV', value: Math.max(0, cohort.population - cohort.flagged_before_kev), tone: 'muted' },
        ]} caption="New-CVE cohort; before KEV confirmation does not mean before the first attack." />
          <StatCards items={[{ label: 'Coverage', value: `${cohort.pct_flagged_before_kev}%`, detail: 'Within this evaluated cohort' }, { label: 'Median lead', value: cohort.median_lead_days === null ? 'Unknown' : `${cohort.median_lead_days} days`, detail: 'Among flagged cases only', tone: 'teal' }]} />
        </> : <Empty>No evaluated new-CVE cohort available.</Empty>}
        <DetailFold title="Method, source availability and limitations"><ul>{[...lead.data.methodology, ...lead.data.limitations].map(n => <li key={n}>{n}</li>)}</ul></DetailFold>
      </div></Panel>
      <LeadTimelines />
      <Panel title="India-focused intelligence" className="xl:col-span-2"><div className="p-4">
        <DataNotice mode={india.mode} error={india.error} />
        <StatCards items={[
          { label: 'Public victim records', value: india.mode === 'live' ? india.data.ransomware_victims_total : 'Unavailable', detail: 'Cached source reports; not our targets', tone: 'amber' },
          { label: 'CERT-In in this view', value: india.mode === 'live' ? india.data.certin_advisories.length : 'Unavailable', detail: 'Returned advisory references', tone: 'teal' },
          { label: 'India-related OTX', value: india.mode === 'live' ? india.data.otx_pulses.length : 'Unavailable', detail: 'Returned campaign references' },
        ]} />
        <div className="visual-panel-grid"><Breakdown caption="Public ransomware records by reported sector" rows={Object.entries(india.data.ransomware_by_sector).sort((a,b) => b[1]-a[1]).slice(0,6).map(([label,value]) => ({label:label||'Unknown sector',value,tone:'amber'}))} />
          <Breakdown caption="Public records by reported ransomware group" rows={Object.entries(india.data.ransomware_by_group).sort((a,b) => b[1]-a[1]).slice(0,6).map(([label,value]) => ({label:label||'Unknown group',value}))} /></div>
        <DetailFold title="CERT-In advisories and India-related campaign references"><div className="grid gap-4 lg:grid-cols-2">{[['CERT-In advisories', india.data.certin_advisories], ['India-related OTX campaigns', india.data.otx_pulses]].map(([heading, records]) => <div key={heading as string}><h3 className="mb-3 text-white">{heading as string}</h3><ul>{(records as Threat[]).map(t => <li key={t.threat_id}><Link className="text-blue-300" to={`/app/threats?search=${encodeURIComponent(t.threat_id)}`}>{t.title}</Link>{t.references.filter(safeReference).slice(0,1).map(r => <a key={r} className="block text-xs text-grey-300" href={r} target="_blank" rel="noreferrer">Read original source ↗</a>)}</li>)}</ul></div>)}</div></DetailFold>
      </div></Panel>
    </div>
  </>
}
