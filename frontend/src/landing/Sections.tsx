import { useEffect, useRef, useState } from 'react'
import gsap from 'gsap'
import { FxButton } from './FxButton'
import { SOURCES, riskFactors, riskLevel } from './data'

function Segmented<T extends string | number | boolean>({ label, value, options, onChange }: {
  label: string
  value: T
  options: { label: string; value: T }[]
  onChange: (v: T) => void
}) {
  return (
    <div role="group" aria-label={label} className="lab-row">
      <span className="lab-label">{label}</span>
      <div className="lab-options">
        {options.map((o) => (
          <button
            key={String(o.value)}
            type="button"
            aria-pressed={o.value === value}
            onClick={() => onChange(o.value)}
            className={`lab-option ${o.value === value ? 'is-on' : ''}`}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  )
}

export function ScoreLab() {
  const [cvss, setCvss] = useState(9.8)
  const [exploit, setExploit] = useState(1)
  const [criticality, setCriticality] = useState(5)
  const [internetFacing, setInternetFacing] = useState(true)
  const [confidence, setConfidence] = useState(1)

  const input = { cvss, inKev: exploit === 1, epss: exploit, criticality, internetFacing, confidence }
  const { score, exploit: ex, exposure } = riskFactors(input)
  const level = riskLevel(score, confidence)
  const factors: [string, string, number][] = [
    ['Severity', `CVSS ${cvss.toFixed(1)}`, cvss / 10],
    ['Exploitation', exploit === 1 ? 'In CISA KEV' : `EPSS ${exploit.toFixed(2)}`, Math.sqrt(ex)],
    ['Criticality', `${criticality} of 5`, criticality / 5],
    ['Exposure', internetFacing ? 'Internet-facing' : 'Internal', exposure],
    ['Match', confidence === 1 ? 'Exact version' : confidence === 0.7 ? 'Product only' : 'Vendor only', confidence],
  ]

  const scoreEl = useRef<HTMLSpanElement>(null)
  const shown = useRef({ v: score })

  // The number runs to its new value, so a change of fact visibly moves the score.
  useEffect(() => {
    const tween = gsap.to(shown.current, {
      v: score,
      duration: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 0.7,
      ease: 'power3.out',
      onUpdate: () => {
        if (scoreEl.current) scoreEl.current.textContent = String(Math.round(shown.current.v))
      },
    })
    return () => { tween.kill() }
  }, [score])

  return (
    <section id="score" className="lab">
      <div className="lab-controls">
        <h2 className="lab-title text-ink">Change the facts. Watch the score move.</h2>
        <p className="lab-intro text-muted">
          The same flaw matters more on an exposed grid firewall than on an internal test box. Every factor stays visible, so nobody has to trust a black box.
        </p>
        <div className="lab-rows">
          <Segmented label="Severity" value={cvss} onChange={setCvss} options={[
            { label: '5.0', value: 5 }, { label: '7.5', value: 7.5 }, { label: '9.0', value: 9 }, { label: '9.8', value: 9.8 },
          ]} />
          <Segmented label="Exploitation" value={exploit} onChange={setExploit} options={[
            { label: 'Rare', value: 0.05 }, { label: 'Likely', value: 0.4 }, { label: 'Active, in KEV', value: 1 },
          ]} />
          <Segmented label="Criticality" value={criticality} onChange={setCriticality} options={[1, 2, 3, 4, 5].map((n) => ({ label: String(n), value: n }))} />
          <Segmented label="Exposure" value={internetFacing} onChange={setInternetFacing} options={[
            { label: 'Internal', value: false }, { label: 'Internet-facing', value: true },
          ]} />
          <Segmented label="Match" value={confidence} onChange={setConfidence} options={[
            { label: 'Vendor only', value: 0.4 }, { label: 'Product', value: 0.7 }, { label: 'Exact version', value: 1 },
          ]} />
        </div>
      </div>

      <div className="lab-result">
        <div className="lab-verdict" aria-live="polite">
          <span ref={scoreEl} className="lab-score">{Math.round(score)}</span>
          <span className="lab-of">of 100<b className="lab-level">{level}</b></span>
        </div>
        <dl className="lab-factors">
          {factors.map(([name, note, v]) => (
            <div key={name} className="lab-factor">
              <dt>{name}<span className="lab-note">{note}</span></dt>
              <dd className="lab-bar"><span style={{ transform: `scaleX(${v})` }} /></dd>
              <dd className="lab-value">{v.toFixed(2)}</dd>
            </div>
          ))}
        </dl>
        <p className="lab-formula">Illustrative vulnerability priority: 30% severity + 35% exploitation + 20% criticality + 15% exposure. Exploitation uses square-root EPSS, or 1 for KEV. An unverified version match caps priority at High. The dashboard separately shows behavioural suspicion and evidence confidence.</p>
      </div>
    </section>
  )
}

export function Sources() {
  return (
    <section id="sources" className="src">
      <div className="src-head">
        <h2 className="lab-title text-ink">What it reads</h2>
        <p className="lab-intro text-muted">
          Counts come from the current data snapshot. In demo mode everything runs from this snapshot, with no network.
        </p>
        <FxButton to="/app" arrow>Open dashboard</FxButton>
      </div>
      <table className="src-table">
        <thead className="sr-only">
          <tr><th>Source</th><th>What it gives us</th><th>Records</th></tr>
        </thead>
        <tbody>
          {SOURCES.map((s) => (
            <tr key={s.name} className="source-row">
              <th scope="row">{s.name}</th>
              <td className="src-gives">{s.gives}</td>
              <td className="src-count">{s.count.toLocaleString('en-IN')} <span>{s.unit}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
