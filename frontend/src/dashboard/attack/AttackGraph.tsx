import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Pause, Play, RotateCcw, SkipBack, SkipForward } from 'lucide-react'
import type { Alert } from '../api'
import { PriorityBadge } from '../ui'
import './attack.css'

// Animated replay of one Attack Lab run: a REAL attacker's real traffic (SANS ISC sensors) replayed against one of our
// simulated assets. Everything shown comes from the backend response; nothing here decides anything.

type Match = { start: number; end: number; text: string; technique: string; family?: string; signature?: string }
export type GraphLine = { line_no: number; raw: string; source: string; flagged_by: string | null; decoded: string | null; matches: Match[] }
type Mitre = { id: string; name: string }
type Detection = { rule_id: string; name: string; label: string; stage: string; reason: string; mitre: Mitre[]; evidence: { line_no: number }[] }
type Check = { rule_id: string; fired: boolean; observed: string; threshold: string }
type Step = { title: string; detail: string; actor: string; line_nos: number[] }
export type IntelCve = { cve_id: string; in_feed: boolean; title?: string; kev_listed?: boolean | null; epss?: number | null; cvss?: number | null
  target_match?: string; target_reason?: string; other_exposed_assets?: string[] }
export type GraphRun = {
  run_id: string; kind: string; steps: Step[]; lines: GraphLine[]; detections: Detection[]; checks: Check[]
  verdict: { attack_detected: boolean; headline: string; attacker_ips: string[] }
  attacker: { ip: string; country: string | null; as_name: string | null }
  target: { asset_id: string; hostname: string; role: string }
  intel: { cves: IntelCve[] }
  correlation: { note: string; incidents: Alert[]; vulnerability_alerts?: string[] }
}
type Thresholds = { brute_force_failures?: number; port_scan_distinct_ports?: number; recon_min_requests?: number
  login_hammer_min?: number; login_ports?: number[] }

type NodeKind = 'attacker' | 'asset' | 'data' | 'intel'
type GNode = { id: string; x: number; y: number; label: string; sub?: string; kind: NodeKind }
type Tone = 'bad' | 'warn' | 'good' | 'calm' | 'data'
type Hop = { from: string; to: string; tone: Tone; label?: string }
type Effect = { node: string; tone: Tone; badge: string }
type Routed = { hops: Hop[]; effect?: Effect; port?: number; family: 'exploit' | 'inject' | 'recon' | 'web' | 'login' | 'port' }

const STAGES = ['recon', 'attempt', 'success'] as const
const STAGE_LABEL = { recon: 'Reconnaissance', attempt: 'Attack attempt', success: 'Compromise likely' }
const VULNERABLE = new Set(['confirmed_affected', 'needs_verification'])

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)
const pathOf = (l: GraphLine) => (l.decoded ?? l.raw.match(/"GET (\S+)/)?.[1] ?? '').split('?')[0]

// Where the boxes sit and which way each real log line travels, from what is in this run's data.
function layout(run: GraphRun, loginPorts: number[]) {
  const host = run.target.hostname
  const nodes: GNode[] = [{ id: 'atk', x: 110, y: 200, label: run.attacker.ip, sub: [run.attacker.country, run.attacker.as_name].filter(Boolean).join(' · ') || 'real attacker', kind: 'attacker' }]
  const edges: [string, string][] = []
  const hasWeb = run.lines.some((l) => l.source === 'web')
  const hasFw = run.lines.some((l) => l.source === 'firewall')
  const hasLogin = run.lines.some((l) => loginPorts.includes(+(l.raw.match(/DPT=(\d+)/)?.[1] ?? -1)))
  const cves = run.intel.cves.filter((c) => c.in_feed)
  if (hasWeb) {
    nodes.push({ id: 'web', x: 470, y: hasFw ? 120 : 200, label: 'Web server', sub: host, kind: 'asset' })
    edges.push(['atk', 'web'])
    if (cves.length) {
      nodes.push({ id: 'intel', x: 840, y: hasFw ? 120 : 200, label: 'Our threat intel', sub: `${cves.length} CVE(s) · NVD + CISA KEV`, kind: 'intel' })
      edges.push(['web', 'intel'])
    }
  }
  if (hasFw) {
    nodes.push({ id: 'fw', x: 470, y: hasWeb ? 290 : 200, label: 'Firewall', sub: host, kind: 'asset' })
    edges.push(['atk', 'fw'])
    if (hasLogin) {
      nodes.push({ id: 'login', x: 840, y: hasWeb ? 290 : 200, label: 'Login services', sub: 'SSH · Telnet · RDP · VNC', kind: 'data' })
      edges.push(['fw', 'login'])
    }
  }
  const vulnerable = cves.some((c) => VULNERABLE.has(c.target_match ?? ''))
  const route = (l: GraphLine): Routed => {
    if (l.source === 'firewall') {
      const port = +(l.raw.match(/DPT=(\d+)/)?.[1] ?? 0)
      return loginPorts.includes(port)
        ? { family: 'login', hops: [{ from: 'atk', to: 'fw', tone: 'warn', label: `:${port}` }, { from: 'fw', to: 'login', tone: 'warn' }] }
        : { family: 'port', port, hops: [{ from: 'atk', to: 'fw', tone: 'warn', label: `:${port}` }] }
    }
    const fam = new Set(l.matches.map((m) => m.family))
    const exploit = l.matches.find((m) => m.family === 'known_exploit')
    if (exploit) {
      const cve = run.intel.cves.find((c) => c.cve_id === exploit.signature)
      const hops: Hop[] = [{ from: 'atk', to: 'web', tone: 'bad', label: exploit.signature }]
      if (cve?.in_feed) hops.push({ from: 'web', to: 'intel', tone: 'data', label: `KEV ${cve.kev_listed ? '✓' : '✗'} · EPSS ${cve.epss != null ? Math.round(cve.epss * 100) + '%' : '?'}` })
      const hit = cve && VULNERABLE.has(cve.target_match ?? '')
      return { family: 'exploit', hops, effect: cve?.in_feed ? { node: 'intel', tone: hit ? 'bad' : 'good', badge: hit ? 'WE ARE VULNERABLE' : 'NOT VULNERABLE' } : undefined }
    }
    const sig = l.matches.find((m) => m.family && m.family !== 'recon')
    if (sig) return { family: 'inject', hops: [{ from: 'atk', to: 'web', tone: 'bad', label: clip(sig.text, 24) }] }
    if (fam.has('recon')) return { family: 'recon', hops: [{ from: 'atk', to: 'web', tone: 'warn', label: clip(pathOf(l), 24) }] }
    return { family: 'web', hops: [{ from: 'atk', to: 'web', tone: 'calm', label: clip(pathOf(l), 22) }] }
  }
  return { nodes, edges, route, vulnerable }
}

// Draw the decoded request with every match highlighted.
function Highlighted({ text, matches }: { text: string; matches: Match[] }) {
  const parts: React.ReactNode[] = []
  let at = 0
  for (const m of [...matches].filter((m) => m.end > m.start).sort((a, b) => a.start - b.start)) {
    if (m.start < at) continue
    parts.push(text.slice(at, m.start), <mark key={m.start} className="lab-mark" title={m.technique}>{text.slice(m.start, m.end)}</mark>)
    at = m.end
  }
  parts.push(text.slice(at))
  return <>{parts}</>
}

const W = 1000, H = 400, NODE_W = 190, NODE_H = 64

export default function AttackGraph({ run, thresholds }: { run: GraphRun; thresholds: Thresholds }) {
  const lines = run.lines
  const total = lines.length
  const reduced = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const [cursor, setCursor] = useState(reduced ? total : 0)  // number of real log lines replayed so far
  const [playing, setPlaying] = useState(!reduced)
  const [speed, setSpeed] = useState(1)
  const [focus, setFocus] = useState<string | null>(null)  // selected rule or node
  const logRef = useRef<HTMLOListElement>(null)

  const loginPorts = useMemo(() => thresholds.login_ports ?? [22, 23, 2222, 3389, 5900], [thresholds])
  const { nodes, edges, route } = useMemo(() => layout(run, loginPorts), [run, loginPorts])
  const byId = useMemo(() => Object.fromEntries(nodes.map((n) => [n.id, n])), [nodes])
  const routed = useMemo(() => lines.map(route), [lines, route])

  // The line on which each rule "trips": threshold rules on the line that crosses the threshold, others on first evidence.
  const trips = useMemo(() => {
    const t = new Map<string, number>()
    const nth = (pred: (r: Routed) => boolean, n?: number) => {
      if (!n) return undefined
      let k = 0
      for (let i = 0; i < routed.length; i++) if (pred(routed[i]) && ++k === n) return i
      return undefined
    }
    const seen = new Set<number>()
    const distinct = (r: Routed) => r.port !== undefined && !seen.has(r.port) && (seen.add(r.port), true)
    const special: Record<string, number | undefined> = {
      'WEB-RECON-001': nth((r) => r.family === 'recon', thresholds.recon_min_requests),
      'NET-LOGIN-001': nth((r) => r.family === 'login', thresholds.login_hammer_min),
      'NET-SCAN-001': nth(distinct, thresholds.port_scan_distinct_ports),
    }
    for (const d of run.detections) {
      const first = Math.min(...d.evidence.map((e) => lines.findIndex((l) => l.line_no === e.line_no)).filter((x) => x >= 0))
      const idx = special[d.rule_id] ?? first
      if (Number.isFinite(idx)) t.set(d.rule_id, idx)
    }
    return t
  }, [run, lines, routed, thresholds])

  // Playback: one real log line per tick, scaled so a run replays in roughly 12-20 seconds.
  const tick = Math.min(950, Math.max(90, 15000 / Math.max(total, 1))) / speed
  useEffect(() => {
    if (!playing) return
    if (cursor >= total) { setPlaying(false); return }
    const t = setTimeout(() => setCursor((c) => c + 1), cursor === 0 ? 400 : tick)
    return () => clearTimeout(t)
  }, [playing, cursor, total, tick])
  useEffect(() => { setCursor(reduced ? total : 0); setPlaying(!reduced); setFocus(null) }, [run, reduced, total])
  useEffect(() => { const el = logRef.current; if (el) el.scrollTop = el.scrollHeight }, [cursor])

  // Everything below is derived from "the first `cursor` real lines have happened".
  const done = routed.slice(0, cursor)
  const current = cursor > 0 ? routed[cursor - 1] : null
  const lit = run.detections.filter((d) => (trips.get(d.rule_id) ?? Infinity) < cursor)
  const stage = lit.reduce((s, d) => Math.max(s, STAGES.indexOf(d.stage as (typeof STAGES)[number])), -1)
  const finished = cursor >= total
  const edgeUse = new Map<string, Tone>()
  const rank: Tone[] = ['calm', 'good', 'warn', 'data', 'bad']
  done.forEach((r) => r.hops.forEach((h) => {
    const k = [h.from, h.to].sort().join('|')
    const prev = edgeUse.get(k)
    if (!prev || rank.indexOf(h.tone) > rank.indexOf(prev)) edgeUse.set(k, h.tone)
  }))
  const effects = new Map<string, Effect>()
  // Worst outcome wins: once one exploited CVE hits a vulnerable version, the node stays red.
  done.forEach((r) => { if (r.effect && effects.get(r.effect.node)?.tone !== 'bad') effects.set(r.effect.node, r.effect) })
  const alarm = new Set<string>()
  for (const d of lit) for (const e of d.evidence) {
    const i = lines.findIndex((l) => l.line_no === e.line_no)
    routed[i]?.hops.forEach((h) => { if (h.to !== 'atk' && h.to !== 'intel') alarm.add(h.to) })
  }
  const stepIdx = cursor === 0 ? 0 : Math.max(0, run.steps.findIndex((s) => s.line_nos.includes(lines[cursor - 1].line_no)))
  const step = run.steps[stepIdx]
  const count = (f: Routed['family']) => done.filter((r) => r.family === f).length
  const ports = [...new Set(done.filter((r) => r.port !== undefined).map((r) => r.port!))]
  const allPorts = useMemo(() => [...new Set(routed.filter((r) => r.port !== undefined).map((r) => r.port!))].sort((a, b) => a - b).slice(0, 48), [routed])
  const focusRule = run.detections.find((d) => d.rule_id === focus)
  const focusLines = new Set(focusRule ? focusRule.evidence.map((e) => e.line_no)
    : focus ? lines.filter((_, i) => routed[i].hops.some((h) => h.to === focus || h.from === focus)).map((l) => l.line_no) : [])
  const incident = run.correlation.incidents[0]
  const tripwires = useMemo(() => {
    const out: Check[] = [...run.checks]
    for (const d of run.detections) {
      if (out.some((c) => c.rule_id === d.rule_id)) continue
      const family = d.rule_id.split('-').slice(0, 2).join('-')
      const at = out.map((c) => c.rule_id.startsWith(family)).lastIndexOf(true)
      out.splice(at >= 0 ? at + 1 : out.length, 0, { rule_id: d.rule_id, fired: true, observed: d.reason, threshold: '' })
    }
    // Fired rules first so the story reads left to right.
    return out.sort((a, b) => +!!run.detections.find((d) => d.rule_id === b.rule_id) - +!!run.detections.find((d) => d.rule_id === a.rule_id))
  }, [run])

  const gauges: { label: string; value: number; max: number; mark?: number }[] = []
  if (routed.some((r) => r.family === 'exploit')) gauges.push({ label: 'Exploit requests (known CVEs)', value: count('exploit'), max: Math.max(5, routed.filter((r) => r.family === 'exploit').length) })
  if (routed.some((r) => r.family === 'inject')) gauges.push({ label: 'Injection / traversal payloads', value: count('inject'), max: Math.max(5, routed.filter((r) => r.family === 'inject').length) })
  if (routed.some((r) => r.family === 'recon')) gauges.push({ label: 'Secret / admin-path requests', value: count('recon'), max: Math.max(10, routed.filter((r) => r.family === 'recon').length), mark: thresholds.recon_min_requests })
  if (routed.some((r) => r.family === 'login')) gauges.push({ label: 'Login-port connections', value: count('login'), max: Math.max(25, routed.filter((r) => r.family === 'login').length), mark: thresholds.login_hammer_min })
  if (allPorts.length) gauges.push({ label: 'Distinct ports probed', value: ports.length, max: Math.max(20, allPorts.length), mark: thresholds.port_scan_distinct_ports })
  if (!gauges.length) gauges.push({ label: 'Requests replayed', value: cursor, max: total })

  const jump = (to: number) => { setPlaying(false); setCursor(Math.max(0, Math.min(total, to))) }
  const replay = () => { setCursor(0); setPlaying(true) }

  return (
    <section className="panel ag">
      <header className="ag-head">
        <div className="min-w-0">
          <p className="ag-kicker">Real traffic · {step ? `${step.title} (${Math.min(stepIdx + 1, run.steps.length)} of ${run.steps.length})` : 'no requests'}</p>
          <h2 className="ag-title">{run.attacker.ip} → {run.target.hostname} ({run.target.asset_id})</h2>
          <p className="ag-detail">{step?.detail}</p>
        </div>
        <Meter stage={stage} finished={finished} detected={run.verdict.attack_detected} />
      </header>

      <div className="ag-stage">
        <svg viewBox={`0 0 ${W} ${H}`} className="ag-svg" role="img" aria-label={`Animated replay: ${run.verdict.headline}`}>
          <defs><pattern id="ag-grid" width="28" height="28" patternUnits="userSpaceOnUse"><path d="M28 0H0V28" className="ag-grid" /></pattern></defs>
          <rect width={W} height={H} fill="url(#ag-grid)" />
          {edges.map(([a, b]) => {
            const tone = edgeUse.get([a, b].sort().join('|'))
            return <line key={a + b} x1={byId[a].x} y1={byId[a].y} x2={byId[b].x} y2={byId[b].y} className={`ag-edge ${tone ? `is-${tone}` : ''} ${b === 'intel' ? 'ag-dash' : ''}`} />
          })}
          {nodes.map((n) => {
            const fx = effects.get(n.id)
            return (
              <g key={n.id} className={`ag-node k-${n.kind} ${alarm.has(n.id) ? 'is-alarm' : ''} ${focus === n.id ? 'is-focus' : ''}`}
                transform={`translate(${n.x - NODE_W / 2} ${n.y - NODE_H / 2})`} onClick={() => setFocus(focus === n.id ? null : n.id)} role="button">
                <title>{`${n.label}${n.sub ? ` · ${n.sub}` : ''} — click to highlight its log lines`}</title>
                {alarm.has(n.id) && <rect className="ag-ring" x={-6} y={-6} width={NODE_W + 12} height={NODE_H + 12} rx={14} />}
                <rect className="ag-box" width={NODE_W} height={NODE_H} rx={10} />
                <text x={14} y={27} className="ag-label">{clip(n.label, 22)}</text>
                <text x={14} y={47} className="ag-sub">{clip(n.sub ?? '', 28)}</text>
                {fx && <g transform={`translate(${NODE_W / 2} ${NODE_H + 18})`}><rect x={-72} y={-12} width={144} height={22} rx={11} className={`ag-badge t-${fx.tone}`} />
                  <text textAnchor="middle" y={4} className="ag-badge-text">{fx.badge}</text></g>}
              </g>
            )
          })}
          {current?.hops.map((h, i) => {
            const a = byId[h.from], b = byId[h.to]
            if (!a || !b) return null
            const dur = (tick * 0.85) / current.hops.length
            return (
              <g key={`${cursor}-${i}`} className={`ag-pkt t-${h.tone}`}
                style={{ '--dx': `${b.x - a.x}px`, '--dy': `${b.y - a.y}px`, animationDuration: `${dur}ms`, animationDelay: `${i * dur}ms` } as React.CSSProperties}>
                <circle cx={a.x} cy={a.y} r={7} />
                {h.label && <text x={a.x} y={a.y - 14} textAnchor="middle" className="ag-pkt-label">{h.label}</text>}
              </g>
            )
          })}
        </svg>
        {allPorts.length > 0 && <PortGrid all={allPorts} seen={new Set(ports)} />}
      </div>

      <div className="ag-gauges">
        {gauges.map((x) => (
          <div key={x.label} className="ag-gauge">
            <div className="flex justify-between gap-2 text-sm"><span>{x.label}</span><b className="text-white">{x.value}{x.mark ? ` / threshold ${x.mark}` : ''}</b></div>
            <div className="ag-bar">
              <span style={{ width: `${Math.min(100, (100 * x.value) / x.max)}%` }} className={x.mark && x.value >= x.mark ? 'is-over' : ''} />
              {x.mark ? <i style={{ left: `${Math.min(100, (100 * x.mark) / x.max)}%` }} title={`rule threshold: ${x.mark}`} /> : null}
            </div>
          </div>
        ))}
      </div>

      <div className="ag-trips" aria-label="Detection rules">
        {tripwires.map((c) => {
          const d = run.detections.find((x) => x.rule_id === c.rule_id)
          const on = !!d && (trips.get(c.rule_id) ?? Infinity) < cursor
          return (
            <button key={c.rule_id} type="button" className={`ag-trip ${on ? 'is-on' : ''} ${focus === c.rule_id ? 'is-focus' : ''}`}
              title={d ? d.reason : `${c.observed} (needs ${c.threshold})`}
              onClick={() => { setFocus(focus === c.rule_id ? null : c.rule_id); if (d && trips.has(c.rule_id)) jump(trips.get(c.rule_id)! + 1) }}>
              <span className="ag-dot" />{c.rule_id}{on && d && <em>{d.label}</em>}
            </button>
          )
        })}
      </div>

      <div className="ag-controls">
        <button type="button" className="ag-btn" onClick={replay} aria-label="Replay"><RotateCcw className="size-4" /></button>
        <button type="button" className="ag-btn" onClick={() => jump(cursor - 1)} aria-label="Previous line"><SkipBack className="size-4" /></button>
        <button type="button" className="ag-btn is-main" onClick={() => (finished ? replay() : setPlaying(!playing))} aria-label={playing ? 'Pause' : 'Play'}>
          {playing ? <Pause className="size-4" /> : <Play className="size-4" />}
        </button>
        <button type="button" className="ag-btn" onClick={() => jump(cursor + 1)} aria-label="Next line"><SkipForward className="size-4" /></button>
        <input type="range" min={0} max={total} value={cursor} onChange={(e) => jump(+e.target.value)} className="ag-scrub" aria-label="Timeline" />
        <span className="ag-count">{cursor}/{total} real log lines</span>
        <div className="ag-speed" role="group" aria-label="Speed">
          {[0.5, 1, 2, 4].map((s) => <button key={s} type="button" className={speed === s ? 'is-on' : ''} onClick={() => setSpeed(s)}>{s}×</button>)}
        </div>
      </div>

      <div className="ag-bottom">
        <ol ref={logRef} className="lab-log ag-log" aria-label="Log stream">
          {lines.slice(0, cursor).map((l, i) => (
            <li key={l.line_no} className={`lab-line ${l.flagged_by ? 'is-hit' : routed[i].family !== 'web' ? 'is-attacker' : ''} ${i === cursor - 1 ? 'is-now' : ''} ${focusLines.has(l.line_no) ? 'is-focus' : ''}`}
              onClick={() => jump(i + 1)}>
              <span className="lab-no">{l.line_no}</span>
              <span className="min-w-0">
                <span className="block break-all">{l.raw}</span>
                {l.matches.some((m) => m.end > m.start) && l.decoded && <span className="mt-1 block break-all text-grey-200">decoded: <Highlighted text={l.decoded} matches={l.matches} /></span>}
              </span>
              {l.flagged_by && <span className="lab-rule">{l.flagged_by}</span>}
            </li>
          ))}
          {cursor === 0 && <li className="px-3 py-2 text-grey-400">Press play: the attacker's real requests stream in, in their original order.</li>}
        </ol>
        <aside className={`ag-outcome ${finished ? 'is-in' : ''}`}>
          {!finished ? <p className="text-grey-400">The verdict and the incident appear when the replay ends.</p> : <>
            <p className="ag-kicker">Verdict</p>
            <p className="ag-verdict">{run.verdict.headline}</p>
            {incident ? <>
              <div className="mt-3 flex flex-wrap items-center gap-2"><PriorityBadge priority={incident.priority} /><span className="tag">score {incident.risk_score}</span></div>
              <Link className="mt-2 block text-blue-300 underline" to={`/app/incidents/${incident.alert_id}`}>{incident.alert_id}: {incident.title}</Link>
              {!!run.correlation.vulnerability_alerts?.length && <p className="mt-2 text-sm text-sev-high">Also raised the CVE alert(s) for this asset: {run.correlation.vulnerability_alerts.join(', ')}</p>}
              <p className="mt-2 text-sm text-grey-400">{run.correlation.note}</p>
            </> : <p className="mt-2 text-grey-200">{run.correlation.note}</p>}
          </>}
        </aside>
      </div>
    </section>
  )
}

function Meter({ stage, finished, detected }: { stage: number; finished: boolean; detected: boolean }) {
  if (finished && !detected) return <div className="ag-meter is-clean"><span>✓ No rule fired</span></div>
  return (
    <div className="ag-meter" aria-label="Attack stage">
      {STAGES.map((s, i) => <span key={s} className={`ag-seg s-${s} ${i === stage ? 'is-on' : i < stage ? 'is-past' : ''}`}>{STAGE_LABEL[s]}</span>)}
    </div>
  )
}

function PortGrid({ all, seen }: { all: number[]; seen: Set<number> }) {
  return (
    <div className="ag-ports" aria-label="Ports probed">
      <p className="ag-kicker">Ports this attacker probed</p>
      <div className="ag-port-grid">
        {all.map((p) => <span key={p} className={`ag-port ${seen.has(p) ? 'is-drop' : ''}`} title={seen.has(p) ? 'probed (blocked by the sensor)' : 'not yet in the replay'}>{p}</span>)}
      </div>
    </div>
  )
}
