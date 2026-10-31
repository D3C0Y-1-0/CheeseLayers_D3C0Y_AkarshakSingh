import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Sparkles } from 'lucide-react'
import { fixtures, post, toTitle, useAlerts, useAssets, useThreats, when, type Alert } from './api'
import { Empty, PageHead, Panel, PriorityBadge, Provenance, Unknown } from './ui'

const FACTORS = [
  ['severity', 'Severity'],
  ['exploitation', 'Exploitation'],
  ['criticality', 'Criticality'],
  ['exposure', 'Exposure'],
  ['confidence', 'Match confidence'],
] as const

function RiskBreakdown({ alert }: { alert: Alert }) {
  return (
    <Panel title="Why this priority">
      <div className="flex items-end gap-3 px-4 pt-3">
        <span className="font-display text-[3.75rem] leading-[0.9] font-light text-white tabular-nums">{alert.risk_score ?? 'n/a'}</span>
        <span className="pb-1 text-grey-300">{alert.risk_score === null ? 'Behaviour alerts have no vulnerability score' : 'of 100'}</span>
      </div>
      <dl className="px-4 py-3">
        {FACTORS.map(([key, label]) => {
          const v = alert.factors[key]
          return (
            <div key={key} className="grid grid-cols-[8.5rem_1fr_3.5rem] items-center gap-3 py-1.5">
              <dt className="text-grey-200">{label}</dt>
              <dd className="h-1.5 bg-white/10">{v !== null && <div className="h-full bg-blue" style={{ width: `${v * 100}%` }} />}</dd>
              <dd className="text-right tabular-nums">{v === null ? <Unknown /> : v.toFixed(2)}</dd>
            </div>
          )
        })}
      </dl>
    </Panel>
  )
}

function EvidenceTimeline({ alert }: { alert: Alert }) {
  const [open, setOpen] = useState<string | null>(null)
  return (
    <Panel title="Evidence timeline">
      <ol className="m-4 border-l border-blue-300/40">
        {alert.timeline.map((t) => {
          const event = fixtures.events.find((e) => e.event_id === t.ref)
          return (
            <li key={t.at + t.event} className="relative py-2 pl-5">
              <span aria-hidden className="absolute top-[1.05rem] -left-[4px] size-[7px] bg-blue" />
              <span className="block text-[0.875rem] text-grey-300 tabular-nums">{when(t.at)}{t.ref && `, ${t.ref}`}</span>
              <span className="block text-white">{t.event}</span>
              {event && (
                <button type="button" aria-expanded={open === t.ref} className="text-[0.875rem] text-blue-300 hover:underline" onClick={() => setOpen(open === t.ref ? null : t.ref)}>
                  {open === t.ref ? 'Hide raw event' : 'Show raw event'}
                </button>
              )}
              {event && open === t.ref && <pre className="mt-2 overflow-x-auto bg-black/40 p-2 text-[0.8125rem] leading-snug text-grey-200">{JSON.stringify(event.details, null, 2)}</pre>}
            </li>
          )
        })}
      </ol>
    </Panel>
  )
}

type Report = { summary?: string; assessment?: string; evidence_ids?: string[]; why_relevant?: string; missing_evidence?: string[]; recommended_actions?: string[]; references?: string[] }

// Asks Member 4's agent. If it fails, shows a plain summary built from stored fields and says so.
function AgentExplanation({ alert }: { alert: Alert }) {
  const [state, setState] = useState<{ busy?: boolean; report?: Report; fallback?: boolean }>({})
  const run = async () => {
    setState({ busy: true })
    try {
      setState({ report: await post(`/api/alerts/${encodeURIComponent(alert.alert_id)}/investigate`) })
    } catch {
      setState({ fallback: true, report: {
        summary: `${alert.reasons.join('. ')}.`,
        missing_evidence: alert.limitations,
        evidence_ids: alert.evidence_ids,
      } })
    }
  }
  const r = state.report
  return (
    <Panel title="AI investigation">
      <div className="p-4">
        {!r && (
          <button type="button" className="btn" disabled={state.busy} onClick={run}>
            <Sparkles aria-hidden className="size-4" />
            {state.busy ? 'Investigating' : 'Investigate with AI'}
          </button>
        )}
        {state.fallback && <p role="status" className="mb-2 text-[0.9375rem] text-sev-high">The AI agent did not respond. This summary comes from stored evidence only, with no AI.</p>}
        {r && (
          <div className="grid gap-3 leading-snug">
            {r.assessment && <p><span className="tag">{r.assessment.replaceAll('_', ' ')}</span></p>}
            {r.summary && <p className="text-white">{r.summary}</p>}
            {r.why_relevant && <p className="text-grey-200">{r.why_relevant}</p>}
            {!!r.missing_evidence?.length && <div><h3 className="mb-1 font-sans text-[0.9375rem] font-medium text-white">Missing or unverified</h3><ul className="list-inside list-disc text-grey-200">{r.missing_evidence.map((m) => <li key={m}>{m}</li>)}</ul></div>}
            {!!r.evidence_ids?.length && <p className="text-[0.875rem] text-grey-300">Evidence used: {r.evidence_ids.join(', ')}</p>}
          </div>
        )}
      </div>
    </Panel>
  )
}

export default function Incident() {
  const { id } = useParams()
  const { data: alerts, mode, reload } = useAlerts()
  const { data: assets } = useAssets()
  const { data: threats } = useThreats()
  const [ack, setAck] = useState<{ busy?: boolean; msg?: string }>({})
  const alert = alerts.find((a) => a.alert_id === id)

  if (!alert) {
    return mode === 'loading' ? null : <Panel><Empty>This incident does not exist. <Link className="text-blue-300 underline" to="/app/incidents">Back to incidents</Link></Empty></Panel>
  }

  const linkedAssets = assets.filter((a) => alert.asset_ids.includes(a.asset_id))
  const linkedThreats = threats.filter((t) => alert.threat_ids.includes(t.threat_id))
  const actions = alert.recommended_actions ?? []
  const refs = linkedThreats.flatMap((t) => t.references).slice(0, 4)

  const acknowledge = async () => {
    setAck({ busy: true })
    try {
      await post(`/api/alerts/${encodeURIComponent(alert.alert_id)}/acknowledge`)
      setAck({})
      reload()
    } catch {
      setAck({ msg: 'Could not save: the backend is not responding. Nothing was changed.' })
    }
  }

  return (
    <>
      <Link to="/app/incidents" className="mb-3 inline-flex items-center gap-1.5 text-[0.9375rem] text-grey-200 hover:text-white"><ArrowLeft aria-hidden className="size-4" />Incidents</Link>
      <PageHead title={toTitle(alert)}>
        <div className="flex flex-wrap items-center gap-2">
          {alert.status === 'new'
            ? <button type="button" className="btn-line" disabled={ack.busy} onClick={acknowledge}>{ack.busy ? 'Saving' : 'Acknowledge'}</button>
            : <span className="tag">{alert.status === 'ack' ? 'Acknowledged' : 'Resolved'}</span>}
        </div>
      </PageHead>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <PriorityBadge priority={alert.priority} />
        <Provenance alert={alert} />
        {alert.match_status && <span className="tag">Match: {alert.match_status.replaceAll('_', ' ')}</span>}
        {ack.msg && <p role="status" className="text-[0.9375rem] text-sev-high">{ack.msg}</p>}
      </div>

      <div className="grid items-start gap-3 lg:grid-cols-[1fr_1fr]">
        <div className="grid gap-3">
          <RiskBreakdown alert={alert} />
          <Panel title="Recommended actions">
            {actions.length === 0 ? <Empty>No actions recorded yet. Run the AI investigation.</Empty> : (
              <ul className="p-4">{actions.map((a) => <li key={a} className="flex gap-2 py-1 text-white"><span aria-hidden className="mt-[0.5em] size-1.5 shrink-0 bg-blue" />{a}</li>)}</ul>
            )}
          </Panel>
          <Panel title="Affected assets">
            <ul>
              {linkedAssets.map((a) => (
                <li key={a.asset_id} className="border-b border-rule px-4 py-2.5 last:border-b-0">
                  <span className="block text-white">{a.asset_id}, {a.hostname}</span>
                  <span className="block text-[0.9375rem] text-grey-300">{a.role}. {a.software.map((s) => `${s.product.replaceAll('_', ' ')} ${s.version ?? 'version unknown'}`).join(', ')}. Criticality {a.criticality} of 5, {a.internet_facing ? 'internet-facing' : 'internal'}.</span>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
        <div className="grid gap-3">
          <AgentExplanation key={alert.alert_id} alert={alert} />
          <Panel title="Reasons and limits">
            <div className="grid gap-3 p-4 leading-snug">
              <ul className="grid gap-1 text-white">{alert.reasons.map((r) => <li key={r} className="flex gap-2"><span aria-hidden className="mt-[0.5em] size-1.5 shrink-0 bg-blue" />{r}</li>)}</ul>
              {alert.limitations.length > 0 && <div><h3 className="mb-1 font-sans text-[0.9375rem] font-medium text-white">What we could not verify</h3><ul className="grid gap-1 text-grey-200">{alert.limitations.map((l) => <li key={l}>{l}</li>)}</ul></div>}
            </div>
          </Panel>
          <EvidenceTimeline alert={alert} />
          {refs.length > 0 && (
            <Panel title="Source references">
              <ul className="p-4 text-[0.9375rem]">{refs.map((r) => <li key={r} className="truncate py-0.5"><a className="text-blue-300 hover:underline" href={r} target="_blank" rel="noreferrer">{r}</a></li>)}</ul>
            </Panel>
          )}
        </div>
      </div>
    </>
  )
}
