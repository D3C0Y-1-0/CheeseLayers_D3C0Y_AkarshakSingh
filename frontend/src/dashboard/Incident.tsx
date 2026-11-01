import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Sparkles } from 'lucide-react'
import { fixtures, notifyRefresh, parseList, post, toTitle, useData, when, type Alert, type Report, type StoredEvent } from './api'
import { ThreatAiSummary } from './AiSummary'
import { CertInDraft } from './CertInDraft'
import { MlExplanation } from './MlExplain'
import { AiBadge, TargetCell, DataNotice, Empty, PageHead, Panel, PriorityBadge, Provenance, safeReference } from './ui'
import { DetailFold, JourneyRail, ScoreGauge, StatCards } from './Visuals'

const STAGES = ['detected', 'investigating', 'confirmed', 'action_required', 'mitigated', 'closed']
const detail = (json: unknown) => json as Alert

function RiskBreakdown({ alert }: { alert: Alert }) {
  const scores = [['Vulnerability priority', alert.vulnerability_priority_score], ['Behavioural suspicion', alert.behavioural_suspicion_score],
    ['Evidence confidence', alert.evidence_confidence_score]] as const
  return <Panel title="Why this priority">
    <div className="flex items-end gap-3 p-4"><span className="font-display text-5xl text-white">{alert.risk_score ?? 'Unknown'}</span><span>incident priority score / 100</span></div>
    <div className="visual-score-grid">{scores.map(([name, value], i) => <ScoreGauge key={name} label={name} value={value} tone={i === 0 ? 'amber' : i === 1 ? 'red' : 'teal'} />)}</div>
    <p className="visual-caption px-4 pb-4">Three separate measures. Evidence confidence and priority are not probabilities of attack.</p>
    {alert.score_factors && <details className="border-t border-rule p-4"><summary className="cursor-pointer text-blue-300">Scoring inputs and contributions</summary><pre className="mt-3 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(alert.score_factors, null, 2)}</pre></details>}
  </Panel>
}

function EvidenceTimeline({ alert }: { alert: Alert }) {
  const source = useData<StoredEvent[]>(`/api/alerts/${encodeURIComponent(alert.alert_id)}/evidence`, [], parseList<StoredEvent>, 5000)
  const [limit, setLimit] = useState(8)
  const visible = alert.timeline.slice(-limit)
  return <Panel title="Evidence timeline">
    {source.error && <p className="p-4 text-sev-high">Stored event detail is unavailable. {source.error}</p>}
    <p className="visual-caption px-4 pt-4">Latest {Math.min(limit, alert.timeline.length)} of {alert.timeline.length} timeline entries · sensor details bounded by the evidence API.</p>
    <ol className="m-4">{visible.map((t, index) => {
      const event = source.data.find((e) => e.event_id === t.ref)
      const status = event?.details.response_status ?? event?.details.observed_status
      return <li key={`${t.at}-${index}`} className="evidence-event">
        <time dateTime={t.at}>{when(t.at)} IST</time>
        <p>{t.event}</p>
        <div className="evidence-meta">{event && <span>{event.event_type}</span>}{event?.rule_id && <span>{event.rule_id}</span>}{status !== undefined && <span>HTTP {String(status)}</span>}{event?.details.src_ip ? <span>Observed peer {String(event.details.src_ip)}</span> : null}</div>
        {event && <details className="mt-2"><summary className="cursor-pointer text-sm text-blue-300">Stored sensor evidence</summary>
          <p className="mt-2 text-sm">{event.source_sensor} · {event.is_simulated ? 'Simulated' : 'Source telemetry'}</p>
          {event.normalized_event && <p className="break-all text-xs">Source: {event.normalized_event.source} · Raw: {event.normalized_event.raw_ref}</p>}
          {event.shadow_findings?.map((f) => <p key={f.finding_id} className="my-2 text-sm text-white">{f.detector_id} · {f.confidence} confidence · {f.reason}</p>)}
          <pre className="mt-2 overflow-auto whitespace-pre-wrap bg-black/30 p-3 text-xs">{JSON.stringify(event.details, null, 2)}</pre>
        </details>}
        {t.ref && <span className="block truncate text-[10px] text-grey-400" title={t.ref}>{t.ref}</span>}
      </li>
    })}</ol>
    {limit < alert.timeline.length && <button type="button" className="btn-line m-4" onClick={() => setLimit(n => n + 24)}>Show earlier entries ({alert.timeline.length - limit} remaining)</button>}
    {!alert.timeline.length && <Empty>No sensor observations recorded for this vulnerability exposure.</Empty>}
  </Panel>
}

function AgentExplanation({ alert, enabled, onReport }: { alert: Alert; enabled: boolean; onReport: (r: Report | null) => void }) {
  const [state, setState] = useState<{ busy?: boolean; report?: Report; error?: string }>({})
  const [evidenceOnly, setEvidenceOnly] = useState(true)
  const run = async () => {
    setState({ busy: true })
    onReport(null)
    try {
      const report = await post(`/api/alerts/${encodeURIComponent(alert.alert_id)}/investigate?evidence_only=${evidenceOnly}`) as Report
      setState({ report }); onReport(report)
    } catch (e) { setState({ error: e instanceof Error ? e.message : 'Investigation unavailable' }) }
  }
  const r = state.report
  return <Panel title="SOC investigation (AI)"><div className="p-4"><label className="mb-3 flex items-center gap-2 text-xs"><input type="checkbox" checked={evidenceOnly} disabled={state.busy} onChange={e=>{setEvidenceOnly(e.target.checked);setState({});onReport(null)}} />Evidence only (no LLM or model cache)</label>
    <button type="button" className="btn" disabled={!enabled || state.busy} onClick={run}><Sparkles aria-hidden className="size-4" />{state.busy ? 'Investigating…' : r ? 'Refresh investigation' : 'Investigate incident'}</button>
    {state.error && <p role="alert" className="mt-3 text-sev-high">{state.error}. Stored reasons and evidence remain available below.</p>}
    {r && <div className="mt-4 grid gap-3 leading-snug">
      <AiBadge generatedBy={r.generated_by} validation={r.validation} fallbackReason={r.fallback_reason} />
      <div className="flex flex-wrap gap-2"><span className="tag">{r.assessment.replaceAll('_', ' ')}</span><span className="tag">{r.integration_status}</span></div>
      <StatCards items={[{ label: 'Cited observations', value: r.evidence_ids.length }, { label: 'Assets in scope', value: r.asset_ids?.length ?? alert.asset_ids.length, tone: 'teal' }, { label: 'Source references', value: r.references.length }]} />
      <p className="text-white line-clamp-3">{r.summary}</p>
      <DetailFold title="Full explanation, visibility gaps and citations"><p>{r.summary}</p><p>{r.why_relevant}</p><ul>{r.limitations.map(s => <li key={s}>{s}</li>)}</ul><p className="break-all mt-3 text-xs">Evidence: {r.evidence_ids.join(', ') || 'No behavioural telemetry supplied'}</p></DetailFold>
      <p className="visual-caption">Review steps require analyst approval. Executed lab responses have a separate action ledger.</p>
    </div>}
  </div></Panel>
}

export default function Incident() {
  const { id = '' } = useParams()
  const sample = fixtures.alerts.find((a) => a.alert_id === id)
  const incident = useData<Alert | undefined>(`/api/alerts/${encodeURIComponent(id)}`, sample, detail, 5000)
  const [ack, setAck] = useState<{ busy?: boolean; error?: string }>({})
  const [report, setReport] = useState<Report | null>(null)
  const alert = incident.data
  if (!alert) return <><DataNotice mode={incident.mode} error={incident.error} /><Panel><Empty>Incident not available. <Link className="text-blue-300 underline" to="/app/incidents">Back to incidents</Link></Empty></Panel></>
  const linkedAssets = alert.assets ?? fixtures.assets.filter((a) => alert.asset_ids.includes(a.asset_id))
  const refs = [...new Set([...(report?.incident_id === id ? report.references : []), ...(alert.threats ?? []).flatMap((t) => t.references ?? [])])].filter(safeReference)
  const actions = report?.incident_id === id ? report.recommended_actions : alert.recommended_actions ?? []
  const current = alert.lifecycle_status ?? (alert.status === 'new' ? 'detected' : 'investigating')
  const next = STAGES[STAGES.indexOf(current) + 1]
  const acknowledge = async () => {
    setAck({ busy: true })
    try { await post(`/api/alerts/${encodeURIComponent(id)}/acknowledge`, { reason: 'Analyst review in dashboard' }); setAck({}); notifyRefresh() }
    catch (e) { setAck({ error: e instanceof Error ? e.message : 'Could not save lifecycle change' }) }
  }
  return <>
    <Link to="/app/incidents" className="mb-3 inline-flex items-center gap-2 text-blue-300"><ArrowLeft className="size-4" />Incidents</Link>
    <PageHead title={toTitle(alert)}>{next && <button type="button" className="btn-line" disabled={ack.busy || incident.mode !== 'live' || !!incident.error} onClick={acknowledge}>{ack.busy ? 'Saving…' : current === 'detected' ? 'Acknowledge' : `Mark ${next.replaceAll('_', ' ')}`}</button>}</PageHead>
    <DataNotice mode={incident.mode} error={incident.error} />
    <div className="mb-4 flex flex-wrap items-center gap-2"><PriorityBadge priority={alert.priority} /><Provenance alert={alert} /><span className="tag">{current.replaceAll('_', ' ')}</span>{alert.remediation_target_at && <span className="tag" title={alert.remediation_policy}>Remediation target: <TargetCell alert={alert} /> ({alert.remediation_policy})</span>}{alert.match_detail && <span className="tag">{alert.match_detail.replaceAll('_', ' ')}</span>}{ack.error && <p role="alert" className="text-sev-high">{ack.error}</p>}</div>
    <div className="mb-4"><JourneyRail active={STAGES.indexOf(current)} items={STAGES.map(label => ({ label: label.replaceAll('_', ' ') }))} /></div>
    <div className="grid items-start gap-3 lg:grid-cols-2"><div className="grid gap-3">
      <RiskBreakdown alert={alert} />
      <Panel title="Proposed investigation and remediation">{actions.length ? <ul className="list-inside list-disc space-y-2 p-4 text-white">{actions.map((a) => <li key={a}>{a}</li>)}</ul> : <Empty>Run an investigation to receive evidence-grounded review steps.</Empty>}</Panel>
      <Panel title="Affected assets"><ul>{linkedAssets.map((a) => <li key={a.asset_id} className="border-b border-rule p-4 last:border-0"><b className="text-white">{a.asset_id} · {a.hostname}</b><p>{a.role} · {a.internet_facing ? 'Internet-facing' : 'Internal'} · Criticality {a.criticality}/5</p><p>{a.software.map((s) => `${s.product} ${s.version ?? 'version unknown'}`).join(', ')}</p></li>)}</ul>{!linkedAssets.length && <Empty>Asset attribution is unknown.</Empty>}</Panel>
      {refs.length > 0 && <Panel title="Source references"><ul className="space-y-2 p-4">{refs.map((r) => <li key={r} className="break-all"><a href={r} target="_blank" rel="noreferrer" className="text-blue-300 underline">{r}</a></li>)}</ul></Panel>}
    </div><div className="grid gap-3">
      {alert.kind === 'behaviour' && incident.mode === 'live' && <MlExplanation key={`ml-${id}`} alertId={id} />}
      <AgentExplanation key={id} alert={alert} enabled={incident.mode === 'live' && !incident.error} onReport={setReport} />
      <CertInDraft key={`c-${id}`} alertId={id} enabled={incident.mode === 'live' && !incident.error} />
      {alert.kind === 'vulnerability' && alert.threat_ids[0] && <ThreatAiSummary key={`t-${id}`} threatId={alert.threat_ids[0]} enabled={incident.mode === 'live'} title={`Threat summary (AI) · ${alert.threat_ids[0]}`} />}
      <Panel title="Decision evidence"><div className="p-4 grid gap-3"><p className="text-white">{alert.reasons[0] ?? 'No explanation recorded.'}</p><span className="visual-caption">{alert.reasons.length} recorded reasons · {alert.limitations.length} limitations</span></div><DetailFold title="All scoring reasons and limitations"><ul>{alert.reasons.map(r => <li key={r}>{r}</li>)}</ul><ul className="mt-4">{alert.limitations.map(l => <li key={l}>{l}</li>)}</ul></DetailFold></Panel>
      <EvidenceTimeline key={id} alert={alert} />
    </div></div>
  </>
}
