import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Sparkles } from 'lucide-react'
import { post, type ThreatSummary } from './api'
import { AiBadge, Panel, safeReference } from './ui'

// Grounded threat summary (POST /api/threats/{id}/summary). Works offline: template or cached LLM wording.
export function ThreatAiSummary({ threatId, enabled, title = 'AI summary' }: { threatId: string; enabled: boolean; title?: string }) {
  const [state, setState] = useState<{ busy?: boolean; s?: ThreatSummary; error?: string }>({})
  const run = async () => {
    setState({ busy: true })
    try { setState({ s: await post(`/api/threats/${encodeURIComponent(threatId)}/summary`) as ThreatSummary }) }
    catch (e) { setState({ error: e instanceof Error ? e.message : 'Summary unavailable' }) }
  }
  const s = state.s
  return <Panel title={title}><div className="grid gap-3 p-4 leading-snug">
    <div className="flex flex-wrap items-center gap-2">
      <button type="button" className="btn" disabled={!enabled || state.busy} onClick={() => run()}><Sparkles aria-hidden className="size-4" />{state.busy ? 'Summarising…' : s ? 'Refresh summary' : 'Generate AI summary'}</button>
    </div>
    {!enabled && <p className="text-sm">Connect the backend to generate a summary.</p>}
    {state.error && <p role="alert" className="text-sev-high">{state.error}</p>}
    {s && <>
      <AiBadge generatedBy={s.generated_by} validation={s.validation} fallbackReason={s.fallback_reason} />
      {s.translation && <p className="tag w-fit">{s.translation.label ?? s.translation.note}</p>}
      <p className="text-white">{s.summary}</p>
      <div><h3 className="mb-1 text-white">Who is affected in our inventory</h3><p>{s.affected_summary}</p></div>
      <div><h3 className="mb-1 text-white">Exploit signals</h3><p>{s.exploit_summary}</p></div>
      <div><h3 className="mb-1 text-white">Why it matters</h3><p>{s.why_it_matters}</p></div>
      <div><h3 className="mb-1 text-white">Recommended action</h3><ul className="list-inside list-disc space-y-1">{s.recommended_actions.map((a) => <li key={a}>{a}</li>)}</ul></div>
      {s.alert_ids.length > 0 && <p className="text-sm">Incidents: {s.alert_ids.map((id) => <Link key={id} className="mr-2 text-blue-300 underline" to={`/app/incidents/${encodeURIComponent(id)}`}>{id}</Link>)}</p>}
      <details><summary className="cursor-pointer text-blue-300">Sources</summary><ul className="mt-2 space-y-1 text-xs">{s.sources.references.filter(safeReference).map((r) => <li key={r} className="break-all"><a className="text-blue-300 underline" href={r} target="_blank" rel="noreferrer">{r}</a></li>)}{s.sources.raw_refs.map((r) => <li key={r} className="break-all">Raw payload: {r}</li>)}</ul></details>
      <p className="text-sm">Analyst review required. No action has been executed.</p>
    </>}
  </div></Panel>
}
