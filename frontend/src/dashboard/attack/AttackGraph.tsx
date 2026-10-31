import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Pause, Play, RotateCcw, SkipBack, SkipForward } from 'lucide-react'
import type { Alert } from '../api'
import { PriorityBadge } from '../ui'
import './attack.css'

// Animated replay of one Attack Lab run. Everything shown comes from the backend response: the log lines the lab
// wrote, the rules that fired on them, and the incident the correlator created. Nothing here decides anything.

type Match = { start: number; end: number; text: string; technique: string }
export type GraphLine = { line_no: number; raw: string; source: string; flagged_by: string | null; decoded: string | null; matches: Match[] }
type Mitre = { id: string; name: string }
type Detection = { rule_id: string; name: string; label: string; stage: string; reason: string; mitre: Mitre[]; evidence: { line_no: number }[] }
type Check = { rule_id: string; fired: boolean; observed: string; threshold: string }
type Step = { title: string; detail: string; actor: string; line_nos: number[] }
export type GraphRun = {
  run_id: string; scenario: string; steps: Step[]; lines: GraphLine[]; detections: Detection[]; checks: Check[]
  verdict: { attack_detected: boolean; headline: string; attacker_ips: string[] }
  target: { asset_id: string; hostname: string; role: string }
  correlation: { note: string; incidents: Alert[] }
}
type Thresholds = { brute_force_failures?: number; port_scan_distinct_ports?: number }

type NodeKind = 'attacker' | 'users' | 'asset' | 'data' | 'external'
type GNode = { id: string; x: number; y: number; label: string; sub?: string; kind: NodeKind }
type Tone = 'bad' | 'warn' | 'good' | 'calm' | 'data'
type Hop = { from: string; to: string; tone: Tone; label?: string }
type Effect = { node: string; tone: Tone; badge: string }
type Routed = { hops: Hop[]; effect?: Effect; port?: { port: number; open: boolean } }

const STAGES = ['recon', 'attempt', 'success'] as const
const STAGE_LABEL = { recon: 'Reconnaissance', attempt: 'Attack attempt', success: 'Compromise likely' }

// --- parsing the raw log text (same formats the backend writes) ----------------------------------------------
const webFields = (raw: string) => {
  const m = raw.match(/" (\d{3}) (\d+)/)
  return { status: m ? +m[1] : 0, bytes: m ? +m[2] : 0 }
}
const kb = (n: number) => (n >= 1024 ? `${(n / 1024).toFixed(0)} KB` : `${n} B`)

// --- scenario layouts: where the boxes sit and which way each log line travels ------------------------------
function layout(run: GraphRun): { nodes: GNode[]; edges: [string, string][]; route: (l: GraphLine, actor: string) => Routed } {
  const atk = run.verdict.attacker_ips[0] ?? 'attacker'
  const host = run.target.hostname
  const attacker: GNode = { id: 'atk', x: 95, y: 110, label: 'Attacker', sub: atk, kind: 'attacker' }
  switch (run.scenario) {
    case 'brute_force':
      return {
        nodes: [attacker, { id: 'usr', x: 95, y: 290, label: 'Staff', sub: 'internal users', kind: 'users' },
          { id: 'login', x: 430, y: 200, label: 'Login service', sub: `${host} · sshd`, kind: 'asset' },
          { id: 'acct', x: 780, y: 200, label: 'admin account', sub: 'privileged access', kind: 'data' }],
        edges: [['atk', 'login'], ['usr', 'login'], ['login', 'acct']],
        route: (l, actor) => {
          const ok = /Accepted/.test(l.raw)
          const user = l.raw.match(/for (?:invalid user )?(\S+)/)?.[1] ?? ''
          if (actor !== 'attacker') return { hops: [{ from: 'usr', to: 'login', tone: ok ? 'good' : 'calm', label: ok ? `✓ ${user}` : `✗ ${user}` }] }
          return ok
            ? { hops: [{ from: 'atk', to: 'login', tone: 'bad', label: `✓ ${user}` }, { from: 'login', to: 'acct', tone: 'bad', label: 'logged in' }],
                effect: { node: 'acct', tone: 'bad', badge: 'COMPROMISED' } }
            : { hops: [{ from: 'atk', to: 'login', tone: 'warn', label: `✗ ${user}` }] }
        },
      }
    case 'port_scan':
      return {
        nodes: [attacker, { id: 'usr', x: 95, y: 290, label: 'Visitors', sub: 'HTTPS clients', kind: 'users' },
          { id: 'fw', x: 400, y: 200, label: 'Firewall', sub: host, kind: 'asset' }],
        edges: [['atk', 'fw'], ['usr', 'fw']],
        route: (l, actor) => {
          if (l.source === 'firewall') {
            const port = +(l.raw.match(/DPT=(\d+)/)?.[1] ?? 0)
            const open = /ACTION=ACCEPT/.test(l.raw)
            return actor === 'attacker'
              ? { hops: [{ from: 'atk', to: 'fw', tone: 'warn', label: `:${port}` }], port: { port, open } }
              : { hops: [{ from: 'usr', to: 'fw', tone: 'calm', label: ':443' }] }
          }
          return { hops: [{ from: 'atk', to: 'fw', tone: 'warn', label: 'GET / (fingerprint)' }] }
        },
      }
    case 'command_injection':
      return {
        nodes: [attacker, { id: 'web', x: 360, y: 200, label: 'Web server', sub: host, kind: 'asset' },
          { id: 'sh', x: 620, y: 200, label: 'Shell', sub: '/bin/sh on the server', kind: 'data' },
          { id: 'c2', x: 880, y: 110, label: 'Attacker listener', sub: '198.51.100.7:4444', kind: 'external' }],
        edges: [['atk', 'web'], ['web', 'sh'], ['sh', 'c2']],
        route: (l) => {
          if (l.source === 'process') return { hops: [{ from: 'web', to: 'sh', tone: 'bad', label: 'php-fpm → sh' }], effect: { node: 'sh', tone: 'bad', badge: 'SHELL RUNNING' } }
          if (l.source === 'network') return { hops: [{ from: 'sh', to: 'c2', tone: 'bad', label: 'connect :4444' }], effect: { node: 'c2', tone: 'bad', badge: 'REMOTE CONTROL' } }
          const { status } = webFields(l.raw)
          const injected = l.matches.length > 0
          if (!injected) return { hops: [{ from: 'atk', to: 'web', tone: 'calm', label: 'ping 8.8.8.8' }] }
          return status === 403
            ? { hops: [{ from: 'atk', to: 'web', tone: 'bad', label: short(l) }], effect: { node: 'web', tone: 'good', badge: 'BLOCKED 403' } }
            : { hops: [{ from: 'atk', to: 'web', tone: 'bad', label: short(l) }] }
        },
      }
    case 'normal_traffic':
      return {
        nodes: [{ id: 'usr', x: 110, y: 200, label: 'Citizens & staff', sub: 'normal users', kind: 'users' },
          { id: 'web', x: 520, y: 95, label: 'Web portal', sub: host, kind: 'asset' },
          { id: 'login', x: 520, y: 200, label: 'Login service', sub: 'sshd', kind: 'asset' },
          { id: 'fw', x: 520, y: 305, label: 'Firewall', sub: 'port 443', kind: 'asset' }],
        edges: [['usr', 'web'], ['usr', 'login'], ['usr', 'fw']],
        route: (l) => {
          const to = l.source === 'auth' ? 'login' : l.source === 'firewall' ? 'fw' : 'web'
          const label = l.source === 'auth' ? (/Accepted/.test(l.raw) ? '✓ login' : '✗ typo') : l.source === 'web' ? path(l) : ':443'
          return { hops: [{ from: 'usr', to, tone: /Accepted/.test(l.raw) ? 'good' : 'calm', label }] }
        },
      }
    default: // sql_injection
      return {
        nodes: [attacker, { id: 'usr', x: 95, y: 290, label: 'Customers', sub: 'internet banking users', kind: 'users' },
          { id: 'web', x: 430, y: 200, label: 'Web app', sub: host, kind: 'asset' },
          { id: 'db', x: 790, y: 200, label: 'Database', sub: 'customers table', kind: 'data' }],
        edges: [['atk', 'web'], ['usr', 'web'], ['web', 'db']],
        route: (l, actor) => {
          const { status, bytes } = webFields(l.raw)
          if (actor !== 'attacker' || !l.matches.length) {
            return { hops: [{ from: actor === 'attacker' ? 'atk' : 'usr', to: 'web', tone: 'calm', label: path(l) }, { from: 'web', to: 'db', tone: 'calm' }] }
          }
          const hops: Hop[] = [{ from: 'atk', to: 'web', tone: 'bad', label: short(l) }]
          if (status === 403) return { hops, effect: { node: 'web', tone: 'good', badge: 'BLOCKED 403' } }
          hops.push({ from: 'web', to: 'db', tone: 'bad', label: 'injected query' })
          if (status === 200 && bytes >= 10000) {
            hops.push({ from: 'db', to: 'web', tone: 'data', label: kb(bytes) }, { from: 'web', to: 'atk', tone: 'data', label: `${kb(bytes)} out` })
            return { hops, effect: { node: 'db', tone: 'bad', badge: 'DATA LEAKED' } }
          }
          return { hops, effect: status >= 500 ? { node: 'web', tone: 'warn', badge: `ERROR ${status}` } : undefined }
        },
      }
  }
}

function short(l: GraphLine) {
  const m = l.matches[0]
  return m ? (m.text.length > 26 ? `${m.text.slice(0, 24)}…` : m.text) : path(l)
}
function path(l: GraphLine) {
  const p = (l.decoded ?? l.raw.match(/"GET (\S+)/)?.[1] ?? '').split('?')[0]
  return p.length > 22 ? `${p.slice(0, 20)}…` : p
}

// Draw the decoded request with every signature match highlighted.
function Highlighted({ text, matches }: { text: string; matches: Match[] }) {
  const parts: React.ReactNode[] = []
  let at = 0
  for (const m of [...matches].sort((a, b) => a.start - b.start)) {
    if (m.start < at) continue
    parts.push(text.slice(at, m.start), <mark key={m.start} className="lab-mark" title={m.technique}>{text.slice(m.start, m.end)}</mark>)
    at = m.end
  }
  parts.push(text.slice(at))
  return <>{parts}</>
}

const W = 1000, H = 380, NODE_W = 170, NODE_H = 64

export default function AttackGraph({ run, thresholds }: { run: GraphRun; thresholds: Thresholds }) {
  const lines = run.lines
  const total = lines.length
  const reduced = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const [cursor, setCursor] = useState(reduced ? total : 0)  // number of lines that have happened
  const [playing, setPlaying] = useState(!reduced)
  const [speed, setSpeed] = useState(1)
  const [focus, setFocus] = useState<string | null>(null)  // selected rule or node
  const logRef = useRef<HTMLOListElement>(null)

  const { nodes, edges, route } = useMemo(() => layout(run), [run])
  const byId = useMemo(() => Object.fromEntries(nodes.map((n) => [n.id, n])), [nodes])
  const actorOf = useMemo(() => {
    const m = new Map<number, string>()
    run.steps.forEach((s) => s.line_nos.forEach((n) => m.set(n, s.actor)))
    return m
  }, [run])
  const routed = useMemo(() => lines.map((l) => route(l, actorOf.get(l.line_no) ?? 'attacker')), [lines, route, actorOf])

  // When does each rule "trip"? Threshold rules trip on the line that crosses the threshold, others on their first evidence.
  const trips = useMemo(() => {
    const t = new Map<string, number>()
    const atkFails: number[] = [], ports = new Set<number>(), portLines: number[] = []
    lines.forEach((l, i) => {
      if (actorOf.get(l.line_no) === 'attacker' && /Failed password/.test(l.raw)) atkFails.push(i)
      const p = routed[i].port
      if (p && !ports.has(p.port)) { ports.add(p.port); portLines.push(i) }
    })
    for (const d of run.detections) {
      let idx = Math.min(...d.evidence.map((e) => lines.findIndex((l) => l.line_no === e.line_no)).filter((x) => x >= 0))
      if (d.rule_id === 'AUTH-BF-001' && thresholds.brute_force_failures) idx = atkFails[thresholds.brute_force_failures - 1] ?? idx
      if (d.rule_id === 'NET-SCAN-001' && thresholds.port_scan_distinct_ports) idx = portLines[thresholds.port_scan_distinct_ports - 1] ?? idx
      if (!t.has(d.rule_id) && Number.isFinite(idx)) t.set(d.rule_id, idx)
    }
    return t
  }, [run, lines, routed, actorOf, thresholds])

  // Playback: one log line per tick; the tick length scales so every attack replays in roughly 12 seconds.
  const tick = Math.min(950, Math.max(260, 12000 / Math.max(total, 1))) / speed
  useEffect(() => {
    if (!playing) return
    if (cursor >= total) { setPlaying(false); return }
    const t = setTimeout(() => setCursor((c) => c + 1), cursor === 0 ? 400 : tick)
    return () => clearTimeout(t)
  }, [playing, cursor, total, tick])
  useEffect(() => { setCursor(reduced ? total : 0); setPlaying(!reduced); setFocus(null) }, [run, reduced, total])
  useEffect(() => { const el = logRef.current; if (el) el.scrollTop = el.scrollHeight }, [cursor])

  // Everything below is derived from "the first `cursor` lines have happened".
  const done = routed.slice(0, cursor)
  const current = cursor > 0 ? routed[cursor - 1] : null
  const lit = run.detections.filter((d) => (trips.get(d.rule_id) ?? Infinity) < cursor)
  const stage = lit.reduce((s, d) => Math.max(s, STAGES.indexOf(d.stage as (typeof STAGES)[number])), -1)
  const finished = cursor >= total
  const edgeUse = new Map<string, Tone>()
  done.forEach((r) => r.hops.forEach((h) => {
    const k = [h.from, h.to].sort().join('|')
    const prev = edgeUse.get(k)
    edgeUse.set(k, prev === 'bad' || h.tone === 'bad' ? 'bad' : prev === 'data' || h.tone === 'data' ? 'data' : h.tone === 'warn' || prev === 'warn' ? 'warn' : 'calm')
  }))
  const effects = new Map<string, Effect>()
  done.forEach((r) => { if (r.effect) effects.set(r.effect.node, r.effect) })
  const alarm = new Set<string>()
  for (const d of lit) for (const e of d.evidence) {
    const i = lines.findIndex((l) => l.line_no === e.line_no)
    routed[i]?.hops.forEach((h) => { if (h.to !== 'atk') alarm.add(h.to) })
  }
  const stepIdx = cursor === 0 ? 0 : Math.max(0, run.steps.findIndex((s) => s.line_nos.includes(lines[cursor - 1].line_no)))
  const step = run.steps[stepIdx]
  const ports = done.filter((r) => r.port).map((r) => r.port!)
  const atkFails = lines.slice(0, cursor).filter((l) => actorOf.get(l.line_no) === 'attacker' && /Failed password/.test(l.raw)).length
  const focusRule = run.detections.find((d) => d.rule_id === focus)
  const focusLines = new Set(focusRule ? focusRule.evidence.map((e) => e.line_no)
    : focus ? lines.filter((_, i) => routed[i].hops.some((h) => h.to === focus || h.from === focus)).map((l) => l.line_no) : [])
  const incident = run.correlation.incidents[0]
  // Every rule that was checked, plus follow-up rules that fired (e.g. WEB-SQLI-002) placed next to their family.
  const tripwires = useMemo(() => {
    const out: Check[] = [...run.checks]
    for (const d of run.detections) {
      if (out.some((c) => c.rule_id === d.rule_id)) continue
      const family = d.rule_id.split('-').slice(0, 2).join('-')
      const at = out.map((c) => c.rule_id.startsWith(family)).lastIndexOf(true)
      out.splice(at >= 0 ? at + 1 : out.length, 0, { rule_id: d.rule_id, fired: true, observed: d.reason, threshold: '' })
    }
    return out
  }, [run])

  const jump = (to: number) => { setPlaying(false); setCursor(Math.max(0, Math.min(total, to))) }
  const replay = () => { setCursor(0); setPlaying(true) }

  return (
    <section className="panel ag">
      <header className="ag-head">
        <div className="min-w-0">
          <p className="ag-kicker">Step {Math.min(stepIdx + 1, run.steps.length)} of {run.steps.length} · {step?.actor}</p>
          <h2 className="ag-title">{step?.title}</h2>
          <p className="ag-detail">{step?.detail}</p>
        </div>
        <Meter stage={stage} finished={finished} detected={run.verdict.attack_detected} />
      </header>

      <div className="ag-stage">
        <svg viewBox={`0 0 ${W} ${H}`} className="ag-svg" role="img" aria-label={`Animated replay: ${run.verdict.headline}`}>
          <defs>
            <pattern id="ag-grid" width="28" height="28" patternUnits="userSpaceOnUse"><path d="M28 0H0V28" className="ag-grid" /></pattern>
          </defs>
          <rect width={W} height={H} fill="url(#ag-grid)" />
          {run.scenario === 'command_injection' && <path d={`M${byId.c2.x} ${byId.c2.y - NODE_H / 2} C ${byId.c2.x - 120} 0, ${byId.atk.x + 160} 0, ${byId.atk.x + 40} ${byId.atk.y - NODE_H / 2}`}
            className={`ag-edge ${edgeUse.has('c2|sh') ? 'is-bad ag-dash' : ''}`} />}
          {edges.map(([a, b]) => {
            const tone = edgeUse.get([a, b].sort().join('|'))
            return <line key={a + b} x1={byId[a].x} y1={byId[a].y} x2={byId[b].x} y2={byId[b].y} className={`ag-edge ${tone ? `is-${tone}` : ''}`} />
          })}
          {nodes.map((n) => {
            const fx = effects.get(n.id)
            return (
              <g key={n.id} className={`ag-node k-${n.kind} ${alarm.has(n.id) ? 'is-alarm' : ''} ${focus === n.id ? 'is-focus' : ''}`}
                transform={`translate(${n.x - NODE_W / 2} ${n.y - NODE_H / 2})`} onClick={() => setFocus(focus === n.id ? null : n.id)} role="button">
                <title>{`${n.label}${n.sub ? ` · ${n.sub}` : ''} — click to highlight its log lines`}</title>
                {alarm.has(n.id) && <rect className="ag-ring" x={-6} y={-6} width={NODE_W + 12} height={NODE_H + 12} rx={14} />}
                <rect className="ag-box" width={NODE_W} height={NODE_H} rx={10} />
                <text x={14} y={27} className="ag-label">{n.label}</text>
                <text x={14} y={47} className="ag-sub">{n.sub}</text>
                {fx && <g transform={`translate(${NODE_W / 2} ${NODE_H + 18})`}><rect x={-62} y={-12} width={124} height={22} rx={11} className={`ag-badge t-${fx.tone}`} />
                  <text textAnchor="middle" y={4} className="ag-badge-text">{fx.badge}</text></g>}
              </g>
            )
          })}
          {current?.hops.map((h, i) => {
            const a = byId[h.from], b = byId[h.to]
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
        {run.scenario === 'port_scan' && <PortGrid ports={ports} />}
      </div>

      <Gauges run={run} thresholds={thresholds} atkFails={atkFails} ports={ports.length} done={done} />

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
        <span className="ag-count">{cursor}/{total} log lines</span>
        <div className="ag-speed" role="group" aria-label="Speed">
          {[0.5, 1, 2, 4].map((s) => <button key={s} type="button" className={speed === s ? 'is-on' : ''} onClick={() => setSpeed(s)}>{s}×</button>)}
        </div>
      </div>

      <div className="ag-bottom">
        <ol ref={logRef} className="lab-log ag-log" aria-label="Log stream">
          {lines.slice(0, cursor).map((l, i) => (
            <li key={l.line_no} className={`lab-line ${l.flagged_by ? 'is-hit' : actorOf.get(l.line_no) === 'attacker' ? 'is-attacker' : ''} ${i === cursor - 1 ? 'is-now' : ''} ${focusLines.has(l.line_no) ? 'is-focus' : ''}`}
              onClick={() => jump(i + 1)}>
              <span className="lab-no">{l.line_no}</span>
              <span className="min-w-0">
                <span className="block break-all">{l.raw}</span>
                {l.matches.length > 0 && l.decoded && <span className="mt-1 block break-all text-grey-200">decoded: <Highlighted text={l.decoded} matches={l.matches} /></span>}
              </span>
              {l.flagged_by && <span className="lab-rule">{l.flagged_by}</span>}
            </li>
          ))}
          {cursor === 0 && <li className="px-3 py-2 text-grey-400">Press play: log lines stream in as the attack happens.</li>}
        </ol>
        <aside className={`ag-outcome ${finished ? 'is-in' : ''}`}>
          {!finished ? <p className="text-grey-400">The verdict and the incident appear when the replay ends.</p> : <>
            <p className="ag-kicker">Verdict</p>
            <p className="ag-verdict">{run.verdict.headline}</p>
            {incident ? <>
              <div className="mt-3 flex flex-wrap items-center gap-2"><PriorityBadge priority={incident.priority} /><span className="tag">score {incident.risk_score}</span></div>
              <Link className="mt-2 block text-blue-300 underline" to={`/app/incidents/${incident.alert_id}`}>{incident.alert_id}: {incident.title}</Link>
              <p className="mt-2 text-sm text-grey-400">{run.correlation.note}</p>
            </> : <p className="mt-2 text-grey-200">{run.correlation.note}</p>}
          </>}
        </aside>
      </div>
    </section>
  )
}

function Meter({ stage, finished, detected }: { stage: number; finished: boolean; detected: boolean }) {
  if (finished && !detected) return <div className="ag-meter is-clean"><span>✓ No attack detected</span></div>
  return (
    <div className="ag-meter" aria-label="Attack stage">
      {STAGES.map((s, i) => <span key={s} className={`ag-seg s-${s} ${i === stage ? 'is-on' : i < stage ? 'is-past' : ''}`}>{STAGE_LABEL[s]}</span>)}
    </div>
  )
}

function Gauges({ run, thresholds, atkFails, ports, done }: { run: GraphRun; thresholds: Thresholds; atkFails: number; ports: number; done: Routed[] }) {
  const g: { label: string; value: number; max: number; mark?: number; unit?: string }[] = []
  if (run.scenario === 'brute_force') g.push({ label: 'Failed logins from the attacker', value: atkFails, max: 40, mark: thresholds.brute_force_failures })
  if (run.scenario === 'port_scan') g.push({ label: 'Distinct ports probed', value: ports, max: 30, mark: thresholds.port_scan_distinct_ports })
  if (run.scenario === 'sql_injection' || run.scenario === 'command_injection') {
    const bad = done.filter((r) => r.hops.some((h) => h.from === 'atk' && h.tone === 'bad')).length
    const blocked = done.filter((r) => r.effect?.badge.startsWith('BLOCKED')).length
    g.push({ label: 'Malicious requests', value: bad, max: 6 }, { label: 'Blocked by the firewall', value: blocked, max: 6 })
  }
  if (run.scenario === 'sql_injection') {
    const out = done.flatMap((r) => r.hops).filter((h) => h.from === 'web' && h.to === 'atk' && h.tone === 'data')
      .reduce((n, h) => n + (parseFloat(h.label ?? '0') || 0), 0)
    g.push({ label: 'Data returned to the attacker', value: out, max: 70, unit: 'KB' })
  }
  if (run.scenario === 'normal_traffic') g.push({ label: 'Requests checked', value: done.length, max: run.lines.length })
  return (
    <div className="ag-gauges">
      {g.map((x) => (
        <div key={x.label} className="ag-gauge">
          <div className="flex justify-between gap-2 text-sm"><span>{x.label}</span><b className="text-white">{x.value}{x.unit ? ` ${x.unit}` : ''}{x.mark ? ` / threshold ${x.mark}` : ''}</b></div>
          <div className="ag-bar">
            <span style={{ width: `${Math.min(100, (100 * x.value) / x.max)}%` }} className={x.mark && x.value >= x.mark ? 'is-over' : ''} />
            {x.mark && <i style={{ left: `${(100 * x.mark) / x.max}%` }} title={`rule threshold: ${x.mark}`} />}
          </div>
        </div>
      ))}
    </div>
  )
}

function PortGrid({ ports }: { ports: { port: number; open: boolean }[] }) {
  const seen = new Map(ports.map((p) => [p.port, p.open]))
  const all = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 9200, 11211, 27017]
  return (
    <div className="ag-ports" aria-label="Ports probed">
      <p className="ag-kicker">Ports on the target</p>
      <div className="ag-port-grid">
        {all.map((p) => <span key={p} className={`ag-port ${seen.has(p) ? (seen.get(p) ? 'is-open' : 'is-drop') : ''}`} title={seen.has(p) ? (seen.get(p) ? 'open (ACCEPT)' : 'dropped') : 'not probed yet'}>{p}</span>)}
      </div>
      <p className="mt-2 text-xs text-grey-400"><span className="ag-port is-open">open</span> <span className="ag-port is-drop">dropped</span></p>
    </div>
  )
}
