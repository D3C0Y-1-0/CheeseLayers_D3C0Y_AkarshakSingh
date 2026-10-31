import { useState } from 'react'
import { FileText } from 'lucide-react'
import { post, type GeneratedBy, type Validation } from './api'
import { AiBadge, Panel } from './ui'

type Draft = { alert_id: string; reportability_assessment: string; suggested_category: { number: number; category: string; reason: string; status: string } | null
  markdown: string; sent: boolean; generated_by: GeneratedBy; validation: Validation | null; fallback_reason: string | null; disclaimer: string }

// CERT-In report draft: generated for analyst review only. Nothing is sent from the dashboard.
export function CertInDraft({ alertId, enabled }: { alertId: string; enabled: boolean }) {
  const [state, setState] = useState<{ busy?: boolean; d?: Draft; error?: string; copied?: boolean }>({})
  const run = async () => {
    setState({ busy: true })
    try { setState({ d: await post(`/api/alerts/${encodeURIComponent(alertId)}/certin-draft`) as Draft }) }
    catch (e) { setState({ error: e instanceof Error ? e.message : 'Draft unavailable' }) }
  }
  const d = state.d
  const download = () => {
    if (!d) return
    const url = URL.createObjectURL(new Blob([d.markdown], { type: 'text/markdown' }))
    const a = Object.assign(document.createElement('a'), { href: url, download: `certin-draft-${d.alert_id}.md` })
    a.click(); URL.revokeObjectURL(url)
  }
  const copy = async () => { if (d) { await navigator.clipboard.writeText(d.markdown); setState({ ...state, copied: true }) } }
  return <Panel title="CERT-In incident report"><div className="grid gap-3 p-4 leading-snug">
    <button type="button" className="btn-line w-fit" disabled={!enabled || state.busy} onClick={run}><FileText aria-hidden className="mr-1 inline size-4" />{state.busy ? 'Drafting…' : d ? 'Redraft' : 'Draft CERT-In report'}</button>
    {state.error && <p role="alert" className="text-sev-high">{state.error}</p>}
    {d && <>
      <AiBadge generatedBy={d.generated_by} validation={d.validation} fallbackReason={d.fallback_reason} />
      <p className="text-white">{d.reportability_assessment}</p>
      {d.suggested_category && <p>Suggested category ({d.suggested_category.status}): {d.suggested_category.number}. {d.suggested_category.category}</p>}
      <p className="text-sm">{d.disclaimer}</p>
      <div className="flex flex-wrap gap-2"><button type="button" className="btn-line" onClick={copy}>{state.copied ? 'Copied' : 'Copy Markdown'}</button><button type="button" className="btn-line" onClick={download}>Download .md</button></div>
      <details><summary className="cursor-pointer text-blue-300">Preview draft</summary><pre className="mt-2 max-h-[28rem] overflow-auto whitespace-pre-wrap bg-black/30 p-3 text-xs">{d.markdown}</pre></details>
      <p className="text-sm">Draft only{d.sent ? '' : ': not sent'}. Complete the missing information and file through CERT-In's official channel if the analyst decides it is reportable.</p>
    </>}
  </div></Panel>
}
