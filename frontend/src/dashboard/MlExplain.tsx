import { Download } from 'lucide-react'
import { useData } from './api'
import { Panel } from './ui'
import { StatCards } from './Visuals'

type Feature = { feature: string; label: string; value: number; training_median: number; training_percentile: number
  shap_value: number; toward: 'unusual' | 'normal' | 'none'; share_pct: number; sentence: string }
type Explanation = { event_id: string; observed_at: string; asset_id: string; sensor_name: string; summary: string
  outlier_score: number; unusual_percentile: number; training_minutes: number; features: Feature[]; limitations: string[] }
type Data = { alert_id: string; ml_findings: number; explanations: Explanation[] }

// Explainable AI for the Isolation Forest (SW-ML-001): SHAP contributions, in plain words. Shown only when the
// incident contains an ML finding. Every number comes from the backend's SHAP computation on the live model.
export function MlExplanation({ alertId }: { alertId: string }) {
  const res = useData<Data | null>(`/api/alerts/${encodeURIComponent(alertId)}/ml-explanation`, null, (j) => j as Data)
  const d = res.data
  if (!d || !d.ml_findings) return null
  return <Panel title="Why the ML model flagged this (explainable AI)"><div className="grid gap-4 p-4 leading-snug">
    {d.explanations.map((e) => {
      const max = Math.max(...e.features.map((f) => Math.abs(f.shap_value)), 1e-9)
      return <div key={e.event_id} className="grid gap-3">
        <p className="text-sm text-grey-300">Minute {e.observed_at.slice(0, 16).replace('T', ' ')} UTC · {e.sensor_name} · Isolation Forest + SHAP</p>
        <StatCards items={[{label:'Relative unusualness',value:`${e.unusual_percentile}%`,detail:'Not attack probability',tone:'amber'},{label:'Training minutes',value:e.training_minutes.toLocaleString('en-IN'),detail:'This historical sensor only'},{label:'Outlier score',value:e.outlier_score.toFixed(4),detail:'Model decision function'}]} />
        <p className="text-white line-clamp-3">{e.summary}</p>
        <div className="grid gap-1.5" role="img" aria-label={`Feature contributions: ${e.features.map((f) => `${f.label} ${f.share_pct}% towards ${f.toward}`).join('; ')}`}>
          <div className="flex justify-between text-xs"><span className="text-sev-high">← made it look unusual</span><span className="text-blue-300">looked normal →</span></div>
          {e.features.map((f) => {
            const w = `${(Math.abs(f.shap_value) / max) * 50}%`
            return <div key={f.feature} className="grid grid-cols-[minmax(0,13rem)_1fr_3rem] items-center gap-2 text-sm">
              <span className="truncate" title={f.label}>{f.label}</span>
              <span className="relative h-3 rounded bg-white/5">
                <span aria-hidden className="absolute top-0 bottom-0 left-1/2 w-px bg-white/25" />
                {f.toward === 'unusual' && <span className="absolute top-0 bottom-0 rounded-l bg-sev-high" style={{ right: '50%', width: w }} />}
                {f.toward === 'normal' && <span className="absolute top-0 bottom-0 rounded-r bg-blue" style={{ left: '50%', width: w }} />}
              </span>
              <span className="text-right tabular-nums text-grey-300">{f.share_pct}%</span>
            </div>
          })}
        </div>
        <details><summary className="cursor-pointer text-blue-300">Feature by feature, in simple words</summary>
          <p className="mt-3">{e.summary}</p>
          <ul className="mt-2 list-inside list-disc space-y-1.5">{e.features.map((f) => <li key={f.feature}>{f.sentence}</li>)}</ul>
        </details>
        <p className="visual-caption">Bars show contributions to isolation path length, not attack probability. {e.limitations[0]}</p>
      </div>
    })}
    <a className="btn-line w-fit" download href={`/api/alerts/${encodeURIComponent(d.alert_id)}/ml-explanation.pdf`}><Download aria-hidden className="mr-1 inline size-4" />Download detailed explanation (PDF)</a>
  </div></Panel>
}
