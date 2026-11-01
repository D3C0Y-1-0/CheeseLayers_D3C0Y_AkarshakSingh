import type { CSSProperties, ReactNode } from 'react'
import { Link } from 'react-router-dom'

export type Tone = 'blue' | 'teal' | 'amber' | 'red' | 'muted'
const COLORS: Record<Tone, string> = { blue: '#80afff', teal: '#55d9ba', amber: '#f3c46e', red: '#ff8598', muted: '#8592ad' }
const toneStyle = (tone: Tone = 'blue') => ({ '--visual-tone': COLORS[tone] }) as CSSProperties

export function StatCards({ items }: { items: { label: string; value: ReactNode; detail?: string; tone?: Tone }[] }) {
  return <div className="visual-stats">{items.map(i => <div className="visual-stat" key={i.label} style={toneStyle(i.tone)}>
    <span className="visual-kicker">{i.label}</span><strong>{i.value ?? 'Unknown'}</strong>{i.detail && <small>{i.detail}</small>}
  </div>)}</div>
}

export function ScoreGauge({ value, label, tone = 'blue' }: { value?: number | null; label: string; tone?: Tone }) {
  const known = typeof value === 'number' && Number.isFinite(value)
  const circumference = 2 * Math.PI * 37
  return <div className="score-gauge" style={toneStyle(tone)}>
    <div className="score-gauge-face" role="img" aria-label={`${label}: ${known ? `${value} out of 100` : 'unknown'}`}>
      <svg viewBox="0 0 88 88" aria-hidden><circle className="gauge-track" cx="44" cy="44" r="37" />
        {known && <circle className="gauge-value" cx="44" cy="44" r="37" strokeDasharray={`${Math.min(100, Math.max(0, value)) / 100 * circumference} ${circumference}`} />}
      </svg><strong>{known ? Math.round(value) : '—'}</strong>
    </div><span>{label}</span><small>{known ? 'Score / 100' : 'Not supplied'}</small>
  </div>
}

export function Breakdown({ rows, maximum, caption }: { rows: { label: string; value: number; tone?: Tone }[]; maximum?: number; caption?: string }) {
  const max = maximum ?? Math.max(1, ...rows.map(r => r.value))
  return <div className="visual-breakdown">{caption && <p className="visual-caption">{caption}</p>}{rows.length ? rows.map(r => <div className="visual-bar-row" key={r.label} style={toneStyle(r.tone)}>
    <div><span>{r.label}</span><b>{r.value.toLocaleString('en-IN')}</b></div>
    <div className="visual-bar-track"><span style={{ width: `${Math.min(100, Math.max(0, r.value / max * 100))}%` }} /></div>
  </div>) : <p className="visual-caption">No recorded values in this view.</p>}</div>
}

export function Distribution({ rows, label, caption }: { rows: { label: string; value: number; tone?: Tone }[]; label: string; caption?: string }) {
  const total = rows.reduce((n, r) => n + Math.max(0, r.value), 0)
  const circumference = 2 * Math.PI * 40
  let offset = 0
  return <div className="visual-distribution">
    <div className="distribution-face" role="img" aria-label={`${label}: ${rows.map(r => `${r.label} ${r.value}`).join(', ')}`}>
      <svg viewBox="0 0 100 100" aria-hidden><circle className="gauge-track" cx="50" cy="50" r="40" />{total > 0 && rows.map(r => {
        const length = Math.max(0, r.value) / total * circumference
        const part = <circle key={r.label} cx="50" cy="50" r="40" fill="none" stroke={COLORS[r.tone ?? 'blue']} strokeWidth="9" strokeDasharray={`${length} ${circumference}`} strokeDashoffset={-offset} />
        offset += length
        return part
      })}</svg><div><strong>{total.toLocaleString('en-IN')}</strong><small>{label}</small></div>
    </div><div className="distribution-legend">{rows.map(r => <div key={r.label} style={toneStyle(r.tone)}><i aria-hidden /><span>{r.label}</span><b>{r.value.toLocaleString('en-IN')}</b></div>)}{caption && <p className="visual-caption">{caption}</p>}</div>
  </div>
}

export function JourneyRail({ items, active }: { items: { label: string; to?: string; detail?: string }[]; active?: number }) {
  return <ol className="journey-rail" aria-label="Workflow">{items.map((item, i) => <li key={item.label} className={active === i ? 'is-current' : ''}>
    <span className="journey-number">{String(i + 1).padStart(2, '0')}</span><div>{item.to ? <Link to={item.to}>{item.label}</Link> : <b>{item.label}</b>}{item.detail && <small>{item.detail}</small>}</div>
  </li>)}</ol>
}

export function DetailFold({ title, children, open = false }: { title: string; children: ReactNode; open?: boolean }) {
  return <details className="detail-fold" open={open}><summary>{title}</summary><div>{children}</div></details>
}
