import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Sparkles } from 'lucide-react'
import { post, type ThreatSummary } from './api'
import { AiBadge, Panel, safeReference } from './ui'
import { DetailFold, StatCards } from './Visuals'

// Grounded threat summary (POST /api/threats/{id}/summary). Works offline: template or cached LLM wording.
export function ThreatAiSummary({ threatId, enabled, title = 'AI summary' }: { threatId: string; enabled: boolean; title?: string }) {
  const [state, setState] = useState<{ busy?: boolean; s?: ThreatSummary; error?: string }>({})
  const [language, setLanguage] = useState<'en' | 'hi'>('en')
  const [evidenceOnly, setEvidenceOnly] = useState(true)
  const run = async () => {
    setState({ busy: true })
    try { setState({ s: await post(`/api/threats/${encodeURIComponent(threatId)}/summary?lang=${language}&evidence_only=${evidenceOnly}`) as ThreatSummary }) }
    catch (e) { setState({ error: e instanceof Error ? e.message : 'Summary unavailable' }) }
  }
  const s = state.s
  return <Panel title={title}><div className="grid gap-3 p-4 leading-snug">
    <div className="flex flex-wrap items-center gap-2">
      <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={evidenceOnly} disabled={state.busy} onChange={e=>{setEvidenceOnly(e.target.checked);setState({})}} />Evidence only (no LLM or model cache)</label>
      <select className="dash-select" aria-label="Requested summary language" value={language} disabled={state.busy} onChange={e=>{setLanguage(e.target.value as 'en'|'hi');setState({})}}><option value="en">English</option><option value="hi">Hindi · best effort</option></select>
      <button type="button" className="btn" disabled={!enabled || state.busy} onClick={() => run()}><Sparkles aria-hidden className="size-4" />{state.busy ? 'Summarising…' : s ? 'Refresh summary' : 'Generate AI summary'}</button>
    </div>
    {!enabled && <p className="text-sm">Connect the backend to generate a summary.</p>}
    {state.error && <p role="alert" className="text-sev-high">{state.error}</p>}
    {s && <>
      <AiBadge generatedBy={s.generated_by} validation={s.validation} fallbackReason={s.fallback_reason} />
      <span className="tag w-fit">Returned language: {s.language === 'hi' ? 'Hindi' : 'English'}</span>
      {s.translation && <p className="tag w-fit">{s.translation.label ?? s.translation.note}</p>}
      <StatCards items={[{label:'Confirmed affected',value:s.affected_assets.filter(a=>a.match_detail==='confirmed_affected').length,tone:'amber'},{label:'Needs verification',value:s.affected_assets.filter(a=>a.match_detail==='needs_verification').length},{label:'Linked incidents',value:s.alert_ids.length,tone:'teal'}]} />
      <p className="text-white line-clamp-3">{s.summary}</p>
      {s.recommended_actions[0] && <p className="text-sm text-blue-200">Next review step: {s.recommended_actions[0]}</p>}
      <DetailFold title="Full narrative, exploit signals and review steps"><p>{s.summary}</p><p>{s.affected_summary}</p><p>{s.exploit_summary}</p><p>{s.why_it_matters}</p><ul>{s.recommended_actions.map(a=><li key={a}>{a}</li>)}</ul></DetailFold>
      {s.alert_ids.length > 0 && <p className="text-sm">Incidents: {s.alert_ids.map((id) => <Link key={id} className="mr-2 text-blue-300 underline" to={`/app/incidents/${encodeURIComponent(id)}`}>{id}</Link>)}</p>}
      <details><summary className="cursor-pointer text-blue-300">Sources</summary><ul className="mt-2 space-y-1 text-xs">{s.sources.references.filter(safeReference).map((r) => <li key={r} className="break-all"><a className="text-blue-300 underline" href={r} target="_blank" rel="noreferrer">{r}</a></li>)}{s.sources.raw_refs.map((r) => <li key={r} className="break-all">Raw payload: {r}</li>)}</ul></details>
      <p className="visual-caption">Analyst review required. This summary proposes actions; executed responses are verified separately.</p>
    </>}
  </div></Panel>
}
