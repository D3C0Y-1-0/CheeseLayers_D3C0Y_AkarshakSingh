import { useState } from 'react'
import { FileText } from 'lucide-react'
import { post, type GeneratedBy, type Validation, type Translation } from './api'
import { AiBadge, Panel } from './ui'
import { DetailFold, JourneyRail } from './Visuals'

type Draft = { alert_id: string; reportability_assessment: string; suggested_category: { number: number; category: string; reason: string; status: string } | null
  markdown: string; sent: boolean; generated_by: GeneratedBy; validation: Validation | null; fallback_reason: string | null; disclaimer: string; language?: string; translation?: Translation }

// CERT-In report draft: generated for analyst review only. Nothing is sent from the dashboard.
export function CertInDraft({ alertId, enabled }: { alertId: string; enabled: boolean }) {
  const [state, setState] = useState<{ busy?: boolean; d?: Draft; error?: string; copied?: boolean }>({})
  const [language, setLanguage] = useState<'en' | 'hi'>('en')
  const [evidenceOnly, setEvidenceOnly] = useState(true)
  const run = async () => {
    setState({ busy: true })
    try { setState({ d: await post(`/api/alerts/${encodeURIComponent(alertId)}/certin-draft?lang=${language}&evidence_only=${evidenceOnly}`) as Draft }) }
    catch (e) { setState({ error: e instanceof Error ? e.message : 'Draft unavailable' }) }
  }
  const d = state.d
  const download = () => {
    if (!d) return
    const url = URL.createObjectURL(new Blob([d.markdown], { type: 'text/markdown' }))
    const a = Object.assign(document.createElement('a'), { href: url, download: `certin-draft-${d.alert_id}.md` })
    a.click(); URL.revokeObjectURL(url)
  }
  const copy = async () => { if (d) { try { await navigator.clipboard.writeText(d.markdown); setState({ ...state, copied: true, error: undefined }) } catch { setState({ ...state, error: "Clipboard unavailable. Download Markdown or copy from the preview." }) } } }
  return <Panel title="CERT-In incident report"><div className="grid gap-3 p-4 leading-snug">
    <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={evidenceOnly} disabled={state.busy} onChange={e=>{setEvidenceOnly(e.target.checked);setState({})}} />Evidence only (no LLM or model cache)</label>
    <select className="dash-select w-fit" aria-label="Requested draft language" value={language} disabled={state.busy} onChange={e=>{setLanguage(e.target.value as 'en'|'hi');setState({})}}><option value="en">English</option><option value="hi">Hindi · best effort</option></select>
    <button type="button" className="btn-line w-fit" disabled={!enabled || state.busy} onClick={run}><FileText aria-hidden className="mr-1 inline size-4" />{state.busy ? 'Drafting…' : d ? 'Redraft' : 'Draft CERT-In report'}</button>
    {state.error && <p role="alert" className="text-sev-high">{state.error}</p>}
    {d && <>
      <AiBadge generatedBy={d.generated_by} validation={d.validation} fallbackReason={d.fallback_reason} />
      <span className="tag w-fit">Returned language: {d.language === 'hi' ? 'Hindi' : 'English'}</span>
      {d.translation && <p className="visual-caption">{d.translation.label ?? d.translation.note}</p>}
      <JourneyRail active={1} items={[{label:'Evidence collected'},{label:'Analyst review'},{label:d.sent?'Submission recorded':'Not submitted'}]} />
      <p className="text-white line-clamp-2">{d.reportability_assessment}</p>
      {d.suggested_category && <p>Suggested category ({d.suggested_category.status}): {d.suggested_category.number}. {d.suggested_category.category}</p>}
      <DetailFold title="Reportability assessment and reporting limits"><p>{d.reportability_assessment}</p><p>{d.disclaimer}</p></DetailFold>
      <div className="flex flex-wrap gap-2"><button type="button" className="btn-line" onClick={copy}>{state.copied ? 'Copied' : 'Copy Markdown'}</button><button type="button" className="btn-line" onClick={download}>Download .md</button></div>
      <details><summary className="cursor-pointer text-blue-300">Preview draft</summary><pre className="mt-2 max-h-[28rem] overflow-auto whitespace-pre-wrap bg-black/30 p-3 text-xs">{d.markdown}</pre></details>
      <p className="text-sm">Draft only{d.sent ? '' : ': not sent'}. Complete the missing information and file through CERT-In's official channel if the analyst decides it is reportable.</p>
    </>}
  </div></Panel>
}
