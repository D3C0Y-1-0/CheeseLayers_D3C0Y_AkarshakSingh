import { useState } from 'react'
import { Link } from 'react-router-dom'
import { notifyRefresh, parseList, post, useData, useHealth, when } from './api'
import { DataNotice, Empty, PageHead, Panel } from './ui'

type Signal = { signal_id: string; threat_id: string; signal_type: string; detected_at: string; source: string;
  old_value: unknown; new_value: unknown; details: Record<string, unknown>; is_simulated: boolean }
type Summary = { total: number; last_24h: Record<string, number>; last_7d: Record<string, number>; thresholds: Record<string, number> }
const TYPES = ['new_kev', 'epss_jump', 'new_public_exploit', 'new_certin_advisory', 'new_critical_cve']
const empty: Summary = { total: 0, last_24h: {}, last_7d: {}, thresholds: {} }

export default function Signals() {
  const health = useHealth()
  const [type, setType] = useState('all')
  const [simulate, setSimulate] = useState('epss_jump')
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
    <div className="tiles mb-4">{TYPES.map((t) => <div className="tile" key={t}><b className="tile-value">{summary.mode === 'live' ? summary.data.last_24h[t] ?? 0 : '—'}</b><span>{t.replaceAll('_', ' ')} · last 24h</span></div>)}</div>
    <Panel title="Demo signal"><div className="flex flex-wrap items-center gap-3 p-4">
      <select className="dash-select" aria-label="Simulated warning type" value={simulate} onChange={(e) => setSimulate(e.target.value)}>{TYPES.map((t) => <option key={t} value={t}>{t.replaceAll('_', ' ')}</option>)}</select>
      <button type="button" className="btn-line" disabled={state.busy || health.mode !== 'live' || !health.data.demo_mode} onClick={run}>Simulate on DEMO-VULN-001</button>
      <p className="w-full text-sm">Uses a fictional vulnerability and the simulated asset inventory.</p>{state.message && <p role="status" className="w-full">{state.message}</p>}
    </div></Panel>
    <Panel title={`${summary.mode === 'live' ? summary.data.total : '—'} recorded warnings`} className="mt-4">
      {!signals.data.length ? <Empty>No warnings in this view. Run a demo signal or collect feed changes.</Empty> : <div className="overflow-auto"><table className="dash-table"><thead><tr><th>Detected</th><th>Warning</th><th>Threat</th><th>Provenance</th><th>Change</th></tr></thead><tbody>{signals.data.map((s) => <tr key={s.signal_id}>
        <td className="whitespace-nowrap">{when(s.detected_at)}</td><td>{s.signal_type.replaceAll('_', ' ')}</td><td><Link className="text-blue-300 underline" to={`/app/threats?search=${encodeURIComponent(s.threat_id)}`}>{s.threat_id}</Link></td><td>{s.source} {s.is_simulated && <span className="tag">Simulated</span>}</td>
        <td className="max-w-80 break-words"><details><summary className="cursor-pointer text-blue-300">Inspect change</summary><pre className="whitespace-pre-wrap text-xs">{JSON.stringify({ before: s.old_value, after: s.new_value, details: s.details }, null, 2)}</pre></details></td>
      </tr>)}</tbody></table></div>}
    </Panel>
    <details className="mt-4"><summary className="cursor-pointer text-blue-300">Configured warning thresholds</summary><pre className="mt-2 text-sm">{JSON.stringify(summary.data.thresholds, null, 2)}</pre></details>
  </>
}
