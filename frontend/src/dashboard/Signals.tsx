import { useState } from 'react'
import { Link } from 'react-router-dom'
import { notifyRefresh, parseList, post, useData, useHealth, when } from './api'
import { DataNotice, Empty, PageHead, Panel } from './ui'
import { Breakdown, DetailFold, StatCards } from './Visuals'

type Signal = { signal_id: string; threat_id: string; signal_type: string; detected_at: string; source: string;
  old_value: unknown; new_value: unknown; details: Record<string, unknown>; is_simulated: boolean }
type Summary = { total: number; last_24h: Record<string, number>; last_7d: Record<string, number>; thresholds: Record<string, number> }
const TYPES = ['new_kev', 'epss_jump', 'new_public_exploit', 'new_certin_advisory', 'new_critical_cve']
const LABELS: Record<string, string> = { new_kev: 'New KEV listing', epss_jump: 'EPSS increase', new_public_exploit: 'Public exploit', new_certin_advisory: 'CERT-In advisory', new_critical_cve: 'Critical CVE' }
const empty: Summary = { total: 0, last_24h: {}, last_7d: {}, thresholds: {} }

export default function Signals() {
  const health = useHealth()
  const [type, setType] = useState('all')
  const [simulate, setSimulate] = useState('epss_jump')
  const [limit, setLimit] = useState(15)
  const [state, setState] = useState<{ busy?: boolean; message?: string }>({})
  const signals = useData<Signal[]>(`/api/signals?limit=100${type === 'all' ? '' : `&type=${type}`}`, [], parseList<Signal>, 5000)
  const summary = useData<Summary>('/api/signals/summary', empty, (j) => j as Summary, 5000)
  const run = async () => {
    setState({ busy: true })
    try { await post('/api/demo/simulate-signal', { fixture_id: 'DEMO-VULN-001', signal_type: simulate }); setState({ message: 'Simulated signal recorded and matched against the asset inventory.' }); notifyRefresh() }
    catch (e) { setState({ message: e instanceof Error ? e.message : 'Simulation unavailable' }) }
  }
  return <>
    <PageHead title="Early warnings"><select className="dash-select" aria-label="Filter warning type" value={type} onChange={(e) => setType(e.target.value)}><option value="all">All warning types</option>{TYPES.map((t) => <option key={t} value={t}>{t.replaceAll('_', ' ')}</option>)}</select></PageHead>
    <DataNotice mode={signals.mode} error={signals.error} />
    {summary.error && <DataNotice mode={summary.mode} error={summary.error} />}
    <StatCards items={TYPES.map((t,i) => ({label:LABELS[t],value:summary.mode === 'live' ? summary.data.last_24h[t] ?? 0 : 'Unavailable',detail:'Recorded in the last 24 hours',tone:i===0?'red':i===3?'teal':'blue'}))} />
    <Panel title="Warning activity · last seven days" className="mb-4"><div className="visual-panel-pad"><Breakdown rows={summary.mode === 'live' ? TYPES.map(t => ({label:LABELS[t],value:summary.data.last_7d[t]??0})) : []} caption="These are intelligence-change signals, not counts of attacks against the organisation." /></div></Panel>
    <Panel title="Optional fixture-generated warning"><DetailFold title="Open labelled signal demonstration"><div className="flex flex-wrap items-center gap-3">
      <select className="dash-select" aria-label="Simulated warning type" value={simulate} onChange={(e) => setSimulate(e.target.value)}>{TYPES.map((t) => <option key={t} value={t}>{t.replaceAll('_', ' ')}</option>)}</select>
      <button type="button" className="btn-line" disabled={state.busy || health.mode !== 'live' || !health.data.demo_mode} onClick={run}>Simulate on DEMO-VULN-001</button>
      <p className="w-full text-sm">Uses a fictional vulnerability and the simulated asset inventory.</p>{state.message && <p role="status" className="w-full">{state.message}</p>}
    </div></DetailFold></Panel>
    <Panel title={`${summary.mode === 'live' ? summary.data.total : '—'} recorded warnings`} className="mt-4">
      {!signals.data.length ? <Empty>No warnings in this view. Run a demo signal or collect feed changes.</Empty> : <div className="p-4">{signals.data.slice(0,limit).map(s => <article className="evidence-event" key={s.signal_id}>
        <time dateTime={s.detected_at}>{when(s.detected_at)} IST</time><div className="flex flex-wrap items-center gap-2"><span className="tag">{LABELS[s.signal_type]??s.signal_type}</span><Link className="text-blue-300" to={`/app/threats?search=${encodeURIComponent(s.threat_id)}`}>{s.threat_id}</Link><span className="visual-caption">{s.source}</span>{s.is_simulated && <span className="tag">Simulated signal</span>}</div>
        <DetailFold title="Before / after values and source evidence"><div className="intel-path"><div><strong>Previous value</strong><span>{s.old_value === null ? 'Unknown' : typeof s.old_value === 'object' ? 'Structured record' : String(s.old_value)}</span></div><div><strong>Current value</strong><span>{s.new_value === null ? 'Unknown' : typeof s.new_value === 'object' ? 'Structured record' : String(s.new_value)}</span></div><div><strong>Trigger</strong><span>{LABELS[s.signal_type]??s.signal_type}</span></div></div><pre className="text-xs whitespace-pre-wrap">{JSON.stringify({before:s.old_value,after:s.new_value,details:s.details},null,2)}</pre></DetailFold>
      </article>)}<p className="visual-caption">Showing {Math.min(limit,signals.data.length)} of {signals.data.length} retrieved warnings; total above is the stored summary.</p>{limit<signals.data.length && <button type="button" className="btn-line mt-3" onClick={()=>setLimit(n=>n+20)}>Show more warnings</button>}</div>}
    </Panel>
    <details className="mt-4"><summary className="cursor-pointer text-blue-300">Configured warning thresholds</summary><pre className="mt-2 text-sm">{JSON.stringify(summary.data.thresholds, null, 2)}</pre></details>
  </>
}
