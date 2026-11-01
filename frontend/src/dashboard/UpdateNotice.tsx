import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { BellRing, ChevronDown, ShieldCheck, X } from 'lucide-react'
import { getJson, parseList, useData } from './api'
import './update-notice.css'

// A prominent, dismissible banner that appears when the threat-intelligence database changes
// (new KEV listing, EPSS jump, public exploit, CERT-In advisory, new/updated CVE). It surfaces the
// existing early-warning signals and, on request, the AI's recommended remediation for the newest one.
// Self-contained: one new component + its own stylesheet, so it does not touch shared dashboard code.

type Signal = { signal_id: string; threat_id: string; cve_id?: string | null; signal_type: string; detected_at: string; is_simulated: boolean }

const LABELS: Record<string, string> = {
  new_kev: 'new KEV listing', epss_jump: 'EPSS increase', new_public_exploit: 'public exploit',
  new_certin_advisory: 'CERT-In advisory', new_critical_cve: 'critical CVE', new_cve: 'new CVE', threat_updated: 'intel revision',
}
const DISMISS_KEY = 'vectra-update-notice-dismissed'

export default function UpdateNotice() {
  const signals = useData<Signal[]>('/api/signals?limit=25', [], parseList<Signal>, 8000)
  // Never raise a notice off bundled sample data when the backend is unreachable.
  const list = signals.mode === 'sample' ? [] : signals.data
  const latest = list[0]
  const [dismissed, setDismissed] = useState(() => { try { return localStorage.getItem(DISMISS_KEY) || '' } catch { return '' } })
  const [open, setOpen] = useState(false)
  const [steps, setSteps] = useState<string[] | null>(null)
  const fetchedFor = useRef('')

  // Pull the AI's recommended actions for the newest update, only when the analyst expands it.
  useEffect(() => {
    if (!open || !latest || fetchedFor.current === latest.threat_id) return
    fetchedFor.current = latest.threat_id
    setSteps(null)
    getJson(`/api/threats/${encodeURIComponent(latest.threat_id)}/summary`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
      .then((r) => setSteps(Array.isArray(r?.recommended_actions) ? r.recommended_actions : []))
      .catch(() => setSteps([]))
  }, [open, latest])

  if (!latest || latest.signal_id === dismissed) return null

  const dismiss = () => {
    try { localStorage.setItem(DISMISS_KEY, latest.signal_id) } catch { /* private mode */ }
    setDismissed(latest.signal_id)
    setOpen(false)
  }
  const kinds = [...new Set(list.map((s) => LABELS[s.signal_type] || s.signal_type))].slice(0, 4).join(' · ')
  const cve = latest.cve_id || latest.threat_id

  return (
    <div className="update-notice" role="status">
      <BellRing aria-hidden className="size-5 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="update-notice-head">
          <b>{list.length} threat-intelligence update{list.length > 1 ? 's' : ''}</b>
          <span className="update-notice-kinds">{kinds}</span>
          {latest.is_simulated && <span className="update-notice-sim">seeded example</span>}
        </div>
        <div className="update-notice-sub">
          The database changed. The AI recommends reviewing exposure and patching affected assets — latest:{' '}
          <b>{cve}</b> ({LABELS[latest.signal_type] || latest.signal_type}).
        </div>
        {open && (
          <div className="update-notice-steps">
            {steps === null
              ? <span className="muted">Loading AI patch guidance…</span>
              : steps.length
                ? <ol>{steps.map((s, i) => <li key={i}><ShieldCheck aria-hidden className="size-3.5" /><span>{s}</span></li>)}</ol>
                : <span className="muted">No specific action for our inventory; keep monitoring.</span>}
          </div>
        )}
      </div>
      <div className="update-notice-actions">
        <button className="update-notice-btn" onClick={() => setOpen((v) => !v)}>
          <ChevronDown aria-hidden className={`size-4 ${open ? 'update-notice-flip' : ''}`} /> {open ? 'Hide' : 'AI patch steps'}
        </button>
        <Link className="update-notice-btn is-primary" to="/app/signals">Review all →</Link>
        <button className="update-notice-x" aria-label="Dismiss" onClick={dismiss}><X aria-hidden className="size-4" /></button>
      </div>
    </div>
  )
}
