import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Sparkles } from 'lucide-react'
import { fixtures, notifyRefresh, parseList, post, toTitle, useData, when, type Alert, type Report, type StoredEvent } from './api'
import { ThreatAiSummary } from './AiSummary'
import { CertInDraft } from './CertInDraft'
import { AiBadge, TargetCell, DataNotice, Empty, PageHead, Panel, PriorityBadge, Provenance, safeReference, Unknown } from './ui'

const STAGES = ['detected', 'investigating', 'confirmed', 'action_required', 'mitigated', 'closed']
const detail = (json: unknown) => json as Alert

function RiskBreakdown({ alert }: { alert: Alert }) {
  const scores = [['Vulnerability priority', alert.vulnerability_priority_score], ['Behavioural suspicion', alert.behavioural_suspicion_score],
    ['Evidence confidence', alert.evidence_confidence_score]] as const
  return <Panel title="Why this priority">
    <div className="flex items-end gap-3 p-4"><span className="font-display text-5xl text-white">{alert.risk_score ?? 'Unknown'}</span><span>incident priority score / 100</span></div>
    <dl className="grid gap-3 p-4">{scores.map(([name, value]) => <div key={name} className="flex justify-between gap-3"><dt>{name}</dt><dd className="text-white">{value ?? <Unknown />}</dd></div>)}</dl>
    {alert.score_factors && <details className="border-t border-rule p-4"><summary className="cursor-pointer text-blue-300">Scoring inputs and contributions</summary><pre className="mt-3 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(alert.score_factors, null, 2)}</pre></details>}
  </Panel>
}

function EvidenceTimeline({ alert }: { alert: Alert }) {
  const source = useData<StoredEvent[]>(`/api/alerts/${encodeURIComponent(alert.alert_id)}/evidence`, [], parseList<StoredEvent>)
  return <Panel title="Evidence timeline">
    {source.error && <p className="p-4 text-sev-high">Stored event detail is unavailable. {source.error}</p>}
    <ol className="m-4 border-l border-blue-300/40">{alert.timeline.map((t, index) => {
      const event = source.data.find((e) => e.event_id === t.ref)
      return <li key={`${t.at}-${index}`} className="relative py-2 pl-5">
        <span aria-hidden className="absolute top-4 -left-1 size-2 bg-blue" />
        <span className="block break-all text-xs text-grey-300">{when(t.at)}{t.ref && ` · ${t.ref}`}</span>
        <span className="block text-white">{t.event}</span>
        {event && <details className="mt-2"><summary className="cursor-pointer text-sm text-blue-300">Stored sensor evidence</summary>
          <p className="mt-2 text-sm">{event.source_sensor} · {event.is_simulated ? 'Simulated' : 'Source telemetry'}</p>
          {event.normalized_event && <p className="break-all text-xs">Source: {event.normalized_event.source} · Raw: {event.normalized_event.raw_ref}</p>}
          {event.shadow_findings?.map((f) => <p key={f.finding_id} className="my-2 text-sm text-white">{f.detector_id} · {f.confidence} confidence · {f.reason}</p>)}
          <pre className="mt-2 overflow-auto whitespace-pre-wrap bg-black/30 p-3 text-xs">{JSON.stringify(event.details, null, 2)}</pre>
        </details>}
      </li>
    })}</ol>
    {!alert.timeline.length && <Empty>No sensor observations recorded for this vulnerability exposure.</Empty>}
  </Panel>
}

function AgentExplanation({ alert, enabled, onReport }: { alert: Alert; enabled: boolean; onReport: (r: Report) => void }) {
  const [state, setState] = useState<{ busy?: boolean; report?: Report; error?: string }>({})
  const run = async () => {
    setState({ busy: true })
    try {
      const report = await post(`/api/alerts/${encodeURIComponent(alert.alert_id)}/investigate`) as Report
      setState({ report }); onReport(report)
    } catch (e) { setState({ error: e instanceof Error ? e.message : 'Investigation unavailable' }) }
  }
  const r = state.report
  return <Panel title="SOC investigation (AI)"><div className="p-4">
    <button type="button" className="btn" disabled={!enabled || state.busy} onClick={run}><Sparkles aria-hidden className="size-4" />{state.busy ? 'Investigating…' : r ? 'Refresh investigation' : 'Investigate incident'}</button>
    {state.error && <p role="alert" className="mt-3 text-sev-high">{state.error}. Stored reasons and evidence remain available below.</p>}
    {r && <div className="mt-4 grid gap-3 leading-snug">
      <AiBadge generatedBy={r.generated_by} validation={r.validation} fallbackReason={r.fallback_reason} />
      <div className="flex flex-wrap gap-2"><span className="tag">{r.assessment.replaceAll('_', ' ')}</span><span className="tag">{r.integration_status}</span></div>
      <p className="text-white">{r.summary}</p><p>{r.why_relevant}</p>
      <div><h3 className="mb-2 text-white">Limitations and visibility gaps</h3><ul className="list-inside list-disc space-y-1">{r.limitations.map((s) => <li key={s}>{s}</li>)}</ul></div>
      <p className="break-all text-xs">Evidence cited: {r.evidence_ids.length ? r.evidence_ids.join(', ') : 'No behavioural telemetry supplied'}</p>
      <p className="text-sm">Proposed actions require analyst review. No action has been executed.</p>
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
    <div className="grid items-start gap-3 lg:grid-cols-2"><div className="grid gap-3">
      <RiskBreakdown alert={alert} />
      <Panel title="Proposed investigation and remediation">{actions.length ? <ul className="list-inside list-disc space-y-2 p-4 text-white">{actions.map((a) => <li key={a}>{a}</li>)}</ul> : <Empty>Run an investigation to receive evidence-grounded review steps.</Empty>}</Panel>
      <Panel title="Affected assets"><ul>{linkedAssets.map((a) => <li key={a.asset_id} className="border-b border-rule p-4 last:border-0"><b className="text-white">{a.asset_id} · {a.hostname}</b><p>{a.role} · {a.internet_facing ? 'Internet-facing' : 'Internal'} · Criticality {a.criticality}/5</p><p>{a.software.map((s) => `${s.product} ${s.version ?? 'version unknown'}`).join(', ')}</p></li>)}</ul>{!linkedAssets.length && <Empty>Asset attribution is unknown.</Empty>}</Panel>
      {refs.length > 0 && <Panel title="Source references"><ul className="space-y-2 p-4">{refs.map((r) => <li key={r} className="break-all"><a href={r} target="_blank" rel="noreferrer" className="text-blue-300 underline">{r}</a></li>)}</ul></Panel>}
    </div><div className="grid gap-3">
      <AgentExplanation key={id} alert={alert} enabled={incident.mode === 'live' && !incident.error} onReport={setReport} />
      <CertInDraft key={`c-${id}`} alertId={id} enabled={incident.mode === 'live' && !incident.error} />
      {alert.kind === 'vulnerability' && alert.threat_ids[0] && <ThreatAiSummary key={`t-${id}`} threatId={alert.threat_ids[0]} enabled={incident.mode === 'live'} title={`Threat summary (AI) · ${alert.threat_ids[0]}`} />}
      <Panel title="Reasons and limits"><div className="space-y-3 p-4"><ul className="list-inside list-disc space-y-1 text-white">{alert.reasons.map((r) => <li key={r}>{r}</li>)}</ul><ul className="space-y-1">{alert.limitations.map((l) => <li key={l}>{l}</li>)}</ul></div></Panel>
      <EvidenceTimeline key={id} alert={alert} />
    </div></div>
  </>
}
