import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { notifyRefresh, post, useAssets, useData, useHealth, type Alert } from './api'
import { Empty, PageHead, Panel, PriorityBadge } from './ui'

// Attack Lab: the backend writes the log lines a real server would record for a simple attack, a separate
// detector reads ONLY that text and names the attack, then the correlator scores it as an incident.

type Playbook = { scenario: string; name: string; what: string; default_target: string; outcome_label: string | null; log_sources: string[] }
type Match = { start: number; end: number; text: string; technique: string; signature: string }
type Line = { line_no: number; raw: string; source: string; flagged_by: string | null; decoded: string | null; matches: Match[] }
type Mitre = { id: string; name: string; tactic: string; url: string }
type Detection = { rule_id: string; name: string; label: string; stage: string; confidence: string; src_ip: string | null;
  count: number; reason: string; techniques: string[]; mitre: Mitre[]; evidence: { line_no: number }[] }
type Check = { rule_id: string; fired: boolean; observed: string; threshold: string }
type Verdict = { attack_detected: boolean; headline: string; attack_types: string[]; stage: string | null; confidence: string | null;
  mitre: Mitre[]; attacker_ips: string[]; decision_path: string[] }
type Analysis = { lines: Line[]; detections: Detection[]; checks: Check[]; verdict: Verdict; parsed: Record<string, number> }
type Step = { title: string; detail: string; actor: string; line_nos: number[] }
type RunResult = Analysis & { run_id: string; name: string; data_classification: string; steps: Step[];
  target: { asset_id: string; hostname: string; role: string }; correlation: { created: string[]; note: string; incidents: Alert[] } }
type Rule = { rule_id: string; name: string; log_source: string; kind: string; logic: string; why_it_works: string; mitre: Mitre[] }

const STAGE_TONE: Record<string, string> = { Reconnaissance: 'medium', 'Attack attempt': 'high', 'Compromise likely': 'critical' }
const EXAMPLES: Record<string, string> = {
  'SQL injection': "/login?user=admin' OR '1'='1'--\n/products?id=7 UNION SELECT username,password FROM users--",
  'Command injection': '/tools/ping?host=8.8.8.8;cat /etc/passwd',
  'Brute force': Array.from({ length: 12 }, (_, i) => `2026-10-31T10:00:${String(i * 3).padStart(2, '0')}+05:30 vpn sshd[311]: Failed password for admin from 203.0.113.9 port ${41000 + i} ssh2`).join('\n'),
  'Normal input': "/search?q=O'Neil Road\n/report?from=2026-10-01&to=2026-10-31\nname=Rock and Roll",
}

// Draw the URL-decoded request with every signature match highlighted.
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

function LogLine({ line }: { line: Line }) {
  return (
    <li className={`lab-line ${line.flagged_by ? 'is-hit' : ''}`}>
      <span className="lab-no">{line.line_no}</span>
      <span className="min-w-0">
        <span className="block break-all">{line.raw}</span>
        {line.matches.length > 0 && line.decoded && (
          <span className="mt-1 block break-all text-grey-200">decoded: <Highlighted text={line.decoded} matches={line.matches} /></span>
        )}
      </span>
      {line.flagged_by && <span className="lab-rule">{line.flagged_by}</span>}
    </li>
  )
}

function MitreChips({ items }: { items: Mitre[] }) {
  return <span className="flex flex-wrap gap-1.5">{items.map((m) =>
    <a key={m.id} className="tag hover:underline" href={m.url} target="_blank" rel="noreferrer" title={`${m.tactic}: ${m.name}`}>{m.id} {m.name}</a>)}</span>
}

function Detections({ result }: { result: Analysis }) {
  const quiet = result.checks.filter((c) => !c.fired)
  return <>
    <Panel title={`How we detected it · ${result.detections.length} rule(s) fired`}>
      {!result.detections.length ? <Empty>No rule fired. Nothing here looks like an attack.</Empty> :
        <ol className="divide-y divide-rule">{result.detections.map((d, i) => (
          <li key={i} className="grid gap-2 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="lab-rule">{d.rule_id}</span><b className="text-white">{d.label}</b>
              <span className="tag">confidence {d.confidence}</span><span className="tag">{d.stage}</span>
            </div>
            <p>{d.reason}</p>
            {d.techniques.length > 0 && <ul className="list-disc pl-5 text-grey-200">{d.techniques.map((t) => <li key={t}>{t}</li>)}</ul>}
            <MitreChips items={d.mitre} />
            <p className="text-sm text-grey-400">Evidence: line {d.evidence.map((e) => e.line_no).join(', ')}{d.count > d.evidence.length ? ` (+${d.count - d.evidence.length} more)` : ''}</p>
          </li>))}
        </ol>}
    </Panel>
    {quiet.length > 0 && <details className="panel mt-4">
      <summary className="panel-title cursor-pointer">Rules checked that did not fire ({quiet.length})</summary>
      <table className="dash-table"><thead><tr><th>Rule</th><th>What it saw</th><th>Needs</th></tr></thead>
        <tbody>{quiet.map((c) => <tr key={c.rule_id}><td className="whitespace-nowrap">{c.rule_id}</td><td>{c.observed}</td><td>{c.threshold}</td></tr>)}</tbody></table>
    </details>}
  </>
}

function VerdictPanel({ v, children }: { v: Verdict; children?: React.ReactNode }) {
  const tone = v.stage ? STAGE_TONE[v.stage] : 'low'
  return (
    <section className={`panel lab-verdict tone-${tone}`}>
      <div className="grid gap-3 p-4">
        <p className="text-sm tracking-wide text-grey-300 uppercase">Verdict: what kind of attack is this?</p>
        <h2 className="font-display text-2xl font-light text-white">{v.headline}</h2>
        {v.attack_detected && <div className="flex flex-wrap items-center gap-2">
          <span className={`badge badge-${tone}`}>{v.stage}</span><span className="tag">confidence {v.confidence}</span>
          {v.attacker_ips.map((ip) => <span key={ip} className="tag">attacker {ip}</span>)}
        </div>}
        {v.mitre.length > 0 && <MitreChips items={v.mitre} />}
        <details open><summary className="cursor-pointer text-blue-300">Decision path</summary>
          <ol className="mt-2 list-decimal space-y-1 pl-5">{v.decision_path.map((p, i) => <li key={i}>{p}</li>)}</ol></details>
        {children}
      </div>
    </section>
  )
}

function Incident({ result }: { result: RunResult }) {
  const inc = result.correlation.incidents[0]
  return (
    <div className="grid gap-2 border-t border-rule pt-3">
      <p className="text-sm tracking-wide text-grey-300 uppercase">Incident in the SOC queue</p>
      {!inc ? <p>{result.correlation.note}</p> : <>
        <div className="flex flex-wrap items-center gap-3">
          <PriorityBadge priority={inc.priority} />
          <Link className="text-blue-300 underline" to={`/app/incidents/${inc.alert_id}`}>{inc.alert_id}: {inc.title}</Link>
        </div>
        <p className="text-grey-200">Behaviour score {inc.behavioural_suspicion_score} · evidence confidence {inc.evidence_confidence_score} · {result.correlation.note}</p>
      </>}
    </div>
  )
}

export default function AttackLab() {
  const health = useHealth()
  const assets = useAssets()
  const playbooks = useData<Playbook[]>('/api/attack-lab/playbooks', [], (j) => j as Playbook[])
  const rules = useData<{ rules: Rule[] }>('/api/attack-lab/rules', { rules: [] }, (j) => j as { rules: Rule[] })
  const [scenario, setScenario] = useState('sql_injection')
  const [target, setTarget] = useState('')
  const [succeed, setSucceed] = useState(true)
  const [state, setState] = useState<{ busy?: boolean; result?: RunResult; error?: string }>({})
  const [shown, setShown] = useState(0)  // steps revealed so far (replay)
  const [replay, setReplay] = useState(0)
  const [text, setText] = useState(EXAMPLES['SQL injection'])
  const [mine, setMine] = useState<{ busy?: boolean; result?: Analysis; error?: string }>({})

  const pb = playbooks.data.find((p) => p.scenario === scenario)
  const enabled = health.mode === 'live' && health.data.demo_mode
  const result = state.result

  useEffect(() => {
    if (!result) return
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) { setShown(result.steps.length); return }
    setShown(1)
    const t = setInterval(() => setShown((n) => (n >= result.steps.length ? (clearInterval(t), n) : n + 1)), 900)
    return () => clearInterval(t)
  }, [result, replay])

  const run = async () => {
    setState({ busy: true })
    try {
      const r = await post('/api/attack-lab/run', { scenario, target_asset_id: target || null, succeed }) as RunResult
      setState({ result: r })
      notifyRefresh()
    } catch (e) { setState({ error: e instanceof Error ? e.message : 'Simulation failed' }) }
  }
  const reset = async () => {
    try { await post('/api/demo/reset-alerts'); setState({}); notifyRefresh() }
    catch (e) { setState({ error: e instanceof Error ? e.message : 'Reset failed' }) }
  }
  const analyze = async () => {
    setMine({ busy: true })
    try { setMine({ result: await post('/api/attack-lab/analyze', { lines: text.split('\n').filter((l) => l.trim()) }) as Analysis }) }
    catch (e) { setMine({ error: e instanceof Error ? e.message : 'Analysis failed' }) }
  }
  const lineByNo = new Map(result?.lines.map((l) => [l.line_no, l]))

  return <>
    <PageHead title="Attack simulation" />
    <p className="mb-4 max-w-4xl">
      Pick a simple attack and a simulated asset. The lab writes the log lines a real server would record. The detector
      reads <b className="text-white">only that text</b> (it is never told which attack ran), names the attack, and the
      correlation engine turns it into a scored incident. Everything is synthetic; no traffic leaves this machine.
    </p>

    <Panel title="1 · Choose an attack">
      <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-5">
        {playbooks.data.map((p) => (
          <button key={p.scenario} type="button" aria-pressed={p.scenario === scenario}
            className={`lab-card ${p.scenario === scenario ? 'is-on' : ''}`} onClick={() => { setScenario(p.scenario); setTarget('') }}>
            <b className="text-white">{p.name}</b>
            <span className="text-sm">{p.what}</span>
            <span className="mt-auto flex flex-wrap gap-1">{p.log_sources.map((s) => <span key={s} className="tag">{s} log</span>)}</span>
          </button>
        ))}
        {!playbooks.data.length && <Empty>Attack playbooks need the backend.</Empty>}
      </div>
      <div className="flex flex-wrap items-center gap-3 border-t border-rule p-4">
        <label className="flex items-center gap-2">Target
          <select className="dash-select" value={target || pb?.default_target || ''} onChange={(e) => setTarget(e.target.value)}>
            {assets.data.map((a) => <option key={a.asset_id} value={a.asset_id}>{a.asset_id} · {a.hostname} · {a.role}</option>)}
          </select>
        </label>
        {pb?.outcome_label && <label className="flex items-center gap-2">
          <input type="checkbox" checked={succeed} onChange={(e) => setSucceed(e.target.checked)} />
          Attack succeeds ({pb.outcome_label.toLowerCase()})
        </label>}
        <button type="button" className="btn-line" disabled={!enabled || state.busy} onClick={run}>{state.busy ? 'Running' : 'Run attack'}</button>
        <button type="button" className="btn-line" disabled={!enabled || state.busy} onClick={reset}>Reset demo alerts</button>
        {!enabled && <p className="w-full text-grey-300">Running attacks needs the backend in demo mode. The rulebook and log analyzer below still work when connected.</p>}
        {state.error && <p role="status" className="w-full text-sev-high">{state.error}</p>}
      </div>
    </Panel>

    {result && <>
      <div className="mt-4"><VerdictPanel v={result.verdict}><Incident result={result} /></VerdictPanel></div>
      <div className="mt-4 grid items-start gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
        <Panel title={`2 · What happened, and what the logs recorded · ${result.target.hostname} (${result.target.asset_id})`}>
          <ol className="divide-y divide-rule">
            {result.steps.slice(0, shown).map((s, i) => (
              <li key={i} className="lab-step p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="lab-no">{i + 1}</span>
                  <b className="text-white">{s.title}</b>
                  <span className={`tag ${s.actor === 'attacker' ? 'tag-attacker' : ''}`}>{s.actor}</span>
                </div>
                <p className="mt-1">{s.detail}</p>
                {s.line_nos.length > 0 && <ul className="lab-log mt-2">
                  {s.line_nos.slice(0, 14).map((n) => { const l = lineByNo.get(n); return l ? <LogLine key={n} line={l} /> : null })}
                  {s.line_nos.length > 14 && <li className="px-3 py-1 text-grey-400">… {s.line_nos.length - 14} more similar lines</li>}
                </ul>}
              </li>
            ))}
          </ol>
          {shown < result.steps.length
            ? <p className="p-4 text-grey-400">Replaying…</p>
            : <button type="button" className="m-4 text-blue-300 underline" onClick={() => setReplay((n) => n + 1)}>Replay</button>}
        </Panel>
        <div><Detections result={result} /></div>
      </div>
      <p className="mt-2 text-sm text-grey-400">{result.data_classification} · run {result.run_id} · parsed {Object.entries(result.parsed).filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(', ')}</p>
    </>}

    <Panel title="Try it yourself: paste log lines or a request" className="mt-6">
      <div className="grid gap-3 p-4">
        <div className="flex flex-wrap gap-2">{Object.keys(EXAMPLES).map((k) =>
          <button key={k} type="button" className="tag" onClick={() => { setText(EXAMPLES[k]); setMine({}) }}>{k}</button>)}</div>
        <textarea className="dash-select min-h-32 font-mono text-sm" value={text} onChange={(e) => setText(e.target.value)}
          aria-label="Log lines to analyse" spellCheck={false} />
        <div><button type="button" className="btn-line" disabled={mine.busy || health.mode !== 'live'} onClick={analyze}>Analyse</button></div>
        <p className="text-sm text-grey-400">Accepts web access-log lines, sshd auth lines, firewall lines, or just a URL / form value. Nothing is stored.</p>
        {mine.error && <p role="status" className="text-sev-high">{mine.error}</p>}
      </div>
      {mine.result && <div className="grid gap-4 border-t border-rule p-4 xl:grid-cols-2">
        <div className="grid content-start gap-4">
          <VerdictPanel v={mine.result.verdict} />
          <ul className="lab-log">{mine.result.lines.map((l) => <LogLine key={l.line_no} line={l} />)}</ul>
        </div>
        <div><Detections result={mine.result} /></div>
      </div>}
    </Panel>

    <Panel title="Detection rulebook: exactly how each attack type is recognised" className="mt-6">
      <div className="overflow-auto"><table className="dash-table">
        <thead><tr><th>Rule</th><th>Detects</th><th>Reads</th><th>Logic</th><th>Why it works</th><th>MITRE ATT&CK</th></tr></thead>
        <tbody>{rules.data.rules.map((r) => <tr key={r.rule_id}>
          <td className="whitespace-nowrap"><span className="lab-rule">{r.rule_id}</span></td>
          <td className="text-white">{r.name}<span className="block text-xs text-grey-400">{r.kind}</span></td>
          <td>{r.log_source}</td><td className="min-w-72">{r.logic}</td><td className="min-w-60 text-grey-200">{r.why_it_works}</td>
          <td><MitreChips items={r.mitre} /></td>
        </tr>)}</tbody>
      </table></div>
    </Panel>
  </>
}
