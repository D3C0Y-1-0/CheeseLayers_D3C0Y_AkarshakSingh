import { useState } from 'react'

const fmt = (n: number) => n.toLocaleString('en-IN')
const day = (iso: string) => new Date(`${iso}T00:00:00Z`).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', timeZone: 'UTC' })

// Top: intel records per day, with the selected time range bracketed. Bottom: incident events per bucket.
export function Timeline({ days, range, buckets, bucketLabel }: { days: { date: string; count: number }[]; range: number; buckets: { label: string; count: number }[]; bucketLabel: string }) {
  const [hover, setHover] = useState<string | null>(null)
  const W = 300
  const H1 = 92
  const max = Math.max(1, ...days.map((d) => d.count))
  const bw = W / Math.max(1, days.length)
  const from = Math.max(0, days.length - range)
  const bmax = Math.max(1, ...buckets.map((b) => b.count))
  const sw = W / Math.max(1, buckets.length)
  return (
    <div className="soc-timeline">
      <svg viewBox={`0 0 ${W} ${H1 + 16}`} role="img" aria-label={`Threat records per day: ${days.map((d) => `${day(d.date)} ${d.count}`).join(', ')}`}>
        <line x1="0" x2={W} y1={H1} y2={H1} className="axis" />
        {days.map((d, i) => {
          const h = (d.count / max) * (H1 - 8)
          const on = i >= from
          return (
            <g key={d.date} onMouseEnter={() => setHover(`${day(d.date)} · ${fmt(d.count)} records`)} onMouseLeave={() => setHover(null)}>
              <rect x={i * bw} y={0} width={bw} height={H1} fill="transparent" />
              <rect x={i * bw + bw * 0.12} y={H1 - h} width={bw * 0.76} height={h} className={on ? 'bar is-on' : 'bar'} />
            </g>
          )
        })}
        {days.length > 0 && (
          <>
            <line x1={from * bw} x2={from * bw} y1={4} y2={H1 + 6} className="brush" />
            <line x1={W - 0.5} x2={W - 0.5} y1={4} y2={H1 + 6} className="brush" />
            <circle cx={from * bw} cy={4} r={2.5} className="knob" />
            <circle cx={W - 0.5} cy={4} r={2.5} className="knob" />
            <text x={from * bw} y={H1 + 14} className="tick" textAnchor="middle">{day(days[from].date)}</text>
            <text x={W} y={H1 + 14} className="tick" textAnchor="end">{day(days[days.length - 1].date)}</text>
          </>
        )}
      </svg>
      <p className="soc-chart-note">{hover ?? 'Intel records per day · bracket = selected range'}</p>
      <svg viewBox={`0 0 ${W} 70`} role="img" aria-label={`Incident events per ${bucketLabel}: ${buckets.filter((b) => b.count).map((b) => `${b.label} ${b.count}`).join(', ') || 'none'}`}>
        <line x1="0" x2={W} y1={58} y2={58} className="axis" />
        {buckets.map((b, i) => {
          if (!b.count) return <circle key={b.label} cx={i * sw + sw / 2} cy={58} r={0.8} className="dot" />
          const h = 8 + (b.count / bmax) * 42
          return (
            <g key={b.label} onMouseEnter={() => setHover(`${b.label} · ${b.count} incident event${b.count === 1 ? '' : 's'}`)} onMouseLeave={() => setHover(null)}>
              <rect x={i * sw} y={0} width={sw} height={60} fill="transparent" />
              <line x1={i * sw + sw / 2} x2={i * sw + sw / 2} y1={58} y2={58 - h} className="spike" />
              <circle cx={i * sw + sw / 2} cy={58 - h} r={2.2} className="knob" />
            </g>
          )
        })}
        <text x={0} y={68} className="tick">{buckets[0]?.label}</text>
        <text x={W} y={68} className="tick" textAnchor="end">{buckets[buckets.length - 1]?.label}</text>
      </svg>
      <p className="soc-chart-note">Incident events per {bucketLabel}</p>
    </div>
  )
}

// Half-circle gauge with ticks, like a radar dial.
export function Gauge({ value, big, label }: { value: number; big: string; label: string }) {
  const v = Math.max(0, Math.min(1, value))
  const cx = 110
  const cy = 104
  const r = 84
  const pt = (f: number, rr = r) => [cx + Math.cos(Math.PI * (1 - f)) * rr, cy - Math.sin(Math.PI * (1 - f)) * rr]
  const [ex, ey] = pt(v)
  return (
    <svg viewBox="0 0 220 118" className="soc-gauge" role="img" aria-label={`${big} ${label}`}>
      <path d={`M${cx - r} ${cy}A${r} ${r} 0 0 1 ${cx + r} ${cy}`} className="track" />
      <path d={`M${cx - r} ${cy}A${r} ${r} 0 0 1 ${ex.toFixed(1)} ${ey.toFixed(1)}`} className="fill" />
      {Array.from({ length: 21 }, (_, i) => {
        const [x1, y1] = pt(i / 20, r - 9)
        const [x2, y2] = pt(i / 20, r - (i % 5 === 0 ? 15 : 12))
        return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} className={i / 20 <= v ? 'tick-line is-on' : 'tick-line'} />
      })}
      <circle cx={ex} cy={ey} r={3.5} className="knob" />
      <text x={cx} y={cy - 18} className="big" textAnchor="middle">{big}</text>
      <text x={cx} y={cy - 2} className="sub" textAnchor="middle">{label}</text>
    </svg>
  )
}

export function VolumeBars({ series }: { series: { date: string; count: number }[] }) {
  const [hover, setHover] = useState<number | null>(null)
  const W = 260
  const H = 92
  const max = Math.max(1, ...series.map((s) => s.count))
  const step = Math.pow(10, Math.floor(Math.log10(max)))
  const top = Math.ceil(max / step) * step
  const left = 34
  const bw = (W - left) / Math.max(1, series.length)
  return (
    <svg viewBox={`0 0 ${W} ${H + 14}`} className="soc-volume" role="img" aria-label={`Threat records per day: ${series.map((s) => `${day(s.date)} ${s.count}`).join(', ')}`}>
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={left} x2={W} y1={H - f * (H - 6)} y2={H - f * (H - 6)} className="grid" />
          <text x={left - 6} y={H - f * (H - 6) + 3} className="tick" textAnchor="end">{fmt(Math.round(top * f))}</text>
        </g>
      ))}
      {series.map((s, i) => {
        const h = (s.count / top) * (H - 6)
        return (
          <g key={s.date} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
            <rect x={left + i * bw} y={0} width={bw} height={H} fill="transparent" />
            <rect x={left + i * bw + bw * 0.18} y={H - h} width={bw * 0.64} height={h} className={hover === i ? 'bar is-hover' : 'bar'} />
          </g>
        )
      })}
      {series.length > 0 && <text x={left} y={H + 12} className="tick">{day(series[0].date)}</text>}
      {series.length > 1 && <text x={W} y={H + 12} className="tick" textAnchor="end">{day(series[series.length - 1].date)}</text>}
      {hover !== null && <text x={(left + W) / 2} y={10} className="hover" textAnchor="middle">{day(series[hover].date)} · {fmt(series[hover].count)}</text>}
    </svg>
  )
}

export function Ring({ value }: { value: number | null }) {
  const v = value === null ? 0 : Math.max(0, Math.min(1, value))
  const c = 2 * Math.PI * 9
  return (
    <svg viewBox="0 0 24 24" className="soc-ring" aria-hidden>
      <circle cx="12" cy="12" r="9" className="track" />
      <circle cx="12" cy="12" r="9" className="fill" strokeDasharray={`${c * v} ${c}`} transform="rotate(-90 12 12)" />
    </svg>
  )
}
