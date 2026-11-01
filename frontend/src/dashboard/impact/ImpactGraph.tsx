import { useCallback, useEffect, useMemo, useState } from 'react'
import { getJson } from '../api'
import './impact.css'

type Pos = { x: number; y: number }

// Shapes mirror GET /api/impact/{threat_id} (backend/app/analytics.py). The graph is a detect -> match ->
// spread view of ONE advisory against our synthetic inventory, built from the real matcher + scorer.
type Tier = 'source' | 'cve' | 'entry' | 'affected' | 'blast'
type Node = {
  id: string; type: 'source' | 'cve' | 'asset'; tier: Tier; label?: string; source?: string
  threat_id?: string; title?: string; cvss?: number | null; severity?: string | null
  kev_listed?: boolean | null; epss?: number | null; public_exploit?: boolean
  asset_id?: string; hostname?: string; role?: string; sector?: string; organisation?: string
  criticality?: number; internet_facing?: boolean; os?: string | null
  match_detail?: string | null; score?: number | null; priority?: string | null; software?: string | null; reason?: string
}
type Edge = { from: string; to: string; kind: 'reported_by' | 'affects' | 'can_spread_to'
  label?: string; match_detail?: string; score?: number; basis?: string; requires_foothold?: boolean }
type Impact = {
  threat_id: string; cve_id: string | null; title: string; source_label: string
  cvss: number | null; severity: string | null; kev_listed: boolean | null; epss: number | null
  public_exploit: boolean; threat_is_simulated: boolean; spread_model: string; data_classification: string
  summary: Record<string, number>; nodes: Node[]; edges: Edge[]; notes: string[]
}

// CVEs that actually touch the simulated inventory — good for a live walk-through. Any CVE id can be typed too.
const PRESETS = [
  { id: 'CVE-2024-21762', label: 'CVE-2024-21762 · FortiOS SSL-VPN (power + banking)' },
  { id: 'CVE-2024-4577', label: 'CVE-2024-4577 · PHP-CGI injection (e-gov)' },
  { id: 'CVE-2023-22515', label: 'CVE-2023-22515 · Confluence access control (telecom)' },
]

const COL: Record<'source' | 'cve' | 'hit' | 'blast', number> = { source: 14, cve: 210, hit: 430, blast: 706 }
const W = 160, H = 46, GAP = 14, PAD = 22, VBW = COL.blast + W + 14

const cssVars = (o: Record<string, string | number>) => o as React.CSSProperties

function layout(nodes: Node[]) {
  const col = (t: Tier): keyof typeof COL => t === 'source' ? 'source' : t === 'cve' ? 'cve' : t === 'blast' ? 'blast' : 'hit'
  const hits = nodes.filter((n) => n.tier === 'entry' || n.tier === 'affected')
  // Order orgs by their first direct hit so blast nodes line up beside their foothold and edges stay local.
  const orgOrder = [...new Set(hits.map((n) => n.organisation))]
  const rank = (n: Node) => [orgOrder.indexOf(n.organisation ?? ''), -(n.criticality ?? 0), n.asset_id ?? '']
  const columns: Record<keyof typeof COL, Node[]> = {
    source: nodes.filter((n) => n.tier === 'source'),
    cve: nodes.filter((n) => n.tier === 'cve'),
    hit: [...hits].sort((a, b) => (rank(a) < rank(b) ? -1 : 1)),
    blast: nodes.filter((n) => n.tier === 'blast').sort((a, b) => (rank(a) < rank(b) ? -1 : 1)),
  }
  const colH = (list: Node[]) => list.length * H + Math.max(0, list.length - 1) * GAP
  const maxH = Math.max(...Object.values(columns).map(colH), H)
  const pos = new Map<string, { x: number; y: number }>()
  for (const [key, list] of Object.entries(columns) as [keyof typeof COL, Node[]][]) {
    const top = PAD + (maxH - colH(list)) / 2
    list.forEach((n, i) => pos.set(n.id, { x: COL[key], y: top + i * (H + GAP) }))
  }
  return { pos, height: maxH + PAD * 2, colFor: (n: Node) => COL[col(n.tier)] }
}

const edgeClass = (e: Edge) =>
  e.kind === 'reported_by' ? 'ig-e-detect'
    : e.kind === 'can_spread_to' ? 'ig-e-spread'
      : e.match_detail === 'confirmed_affected' ? 'ig-e-hit' : 'ig-e-verify'

function Chip({ on, children }: { on?: boolean; children: React.ReactNode }) {
  return <span className={`ig-chip ${on ? 'is-on' : ''}`}>{children}</span>
}

export default function ImpactGraph() {
  const [target, setTarget] = useState(PRESETS[0].id)
  const [typed, setTyped] = useState('')
  const [data, setData] = useState<Impact | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [focus, setFocus] = useState<string | null>(null)
  const reduce = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

  const load = useCallback(async (id: string) => {
    setLoading(true); setError(null); setFocus(null)
    try {
      setData(await getJson(`/api/impact/${encodeURIComponent(id.trim())}`) as Impact)
    } catch (e) {
      setData(null); setError(e instanceof Error ? e.message : 'Could not load the impact graph')
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { load(target) }, [target, load])

  const { pos, height, nodesById } = useMemo(() => {
    if (!data) return { pos: new Map<string, Pos>(), height: 0, nodesById: new Map<string, Node>() }
    const l = layout(data.nodes)
    return { pos: l.pos, height: l.height, nodesById: new Map(data.nodes.map((n) => [n.id, n])) }
  }, [data])

  const focused = focus ? nodesById.get(focus) ?? null : null
  const s = data?.summary ?? {}

  return (
    <section className="panel ig mt-3">
      <div className="ig-head">
        <div>
          <h2 className="panel-title ig-h2">CVE impact &amp; spread</h2>
          <p className="ig-sub">A single advisory, from whichever feed reported it, checked against every asset with the
            real matcher &amp; scorer — what it reaches directly, and how it could move laterally.</p>
        </div>
        <form className="ig-pick" onSubmit={(ev) => { ev.preventDefault(); if (typed.trim()) setTarget(typed.trim()) }}>
          <select aria-label="Pick a CVE" value={PRESETS.some((p) => p.id === target) ? target : ''}
            onChange={(ev) => { setTyped(''); setTarget(ev.target.value) }}>
            {PRESETS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
            {!PRESETS.some((p) => p.id === target) && <option value={target}>{target}</option>}
          </select>
          <input aria-label="Any CVE id" placeholder="or type any CVE id" value={typed}
            onChange={(ev) => setTyped(ev.target.value)} />
          <button type="submit" className="btn-line" disabled={loading || !typed.trim()}>Detect</button>
        </form>
      </div>

      {loading && <p role="status" className="px-4 py-6 text-grey-300">Matching {target} against the inventory…</p>}
      {error && !loading && <p role="status" className="dash-banner mx-4 mb-3">{error}</p>}

      {data && !loading && (
        <>
          <div className="ig-meta">
            <Chip>{data.source_label} → {data.cve_id ?? data.threat_id}</Chip>
            {data.cvss != null && <Chip on={data.cvss >= 9}>CVSS {data.cvss}</Chip>}
            {data.kev_listed && <Chip on>KEV — exploited in the wild</Chip>}
            {data.epss != null && <Chip>EPSS {(data.epss * 100).toFixed(0)}%</Chip>}
            {data.public_exploit && <Chip on>public exploit</Chip>}
            {data.threat_is_simulated && <Chip>simulated advisory</Chip>}
          </div>
          {data.title && <p className="ig-title">{data.title}</p>}

          <div className="ig-stats">
            <div className="ig-stat"><b>{s.confirmed_affected ?? 0}</b><span>directly affected</span></div>
            <div className="ig-stat"><b>{s.needs_verification ?? 0}</b><span>needs verification</span></div>
            <div className="ig-stat"><b>{s.entry_points ?? 0}</b><span>internet entry points</span></div>
            <div className="ig-stat"><b>{s.blast_radius_assets ?? 0}</b><span>reachable by spread</span></div>
            <div className="ig-stat"><b>{s.sectors_touched ?? 0}</b><span>sectors touched</span></div>
            <div className="ig-stat"><b>{(s.aggregate_exposure_score ?? 0).toLocaleString('en-IN')}</b><span>aggregate exposure</span></div>
          </div>

          {(s.confirmed_affected ?? 0) + (s.needs_verification ?? 0) === 0 ? (
            <div className="ig-clean">
              <b>No asset in our inventory runs an affected version.</b> We checked all {s.checked_assets ?? 40} and are
              not exposed to this advisory right now — the match is re-run whenever inventory changes.
            </div>
          ) : (
            <div className="ig-stage">
              <svg className="ig-svg" viewBox={`0 0 ${VBW} ${height}`} role="img"
                aria-label={`Graph: ${data.source_label} reported ${data.cve_id}; ${s.confirmed_affected} assets directly affected, ${s.blast_radius_assets} reachable by lateral movement.`}>
                <g className="ig-lane-labels">
                  {(['source', 'cve', 'hit', 'blast'] as const).map((k, i) => (
                    <text key={k} x={COL[k] + W / 2} y={12} className="ig-lane">
                      {['Source feed', 'Advisory', 'Directly affected', 'Blast radius'][i]}
                    </text>
                  ))}
                </g>
                {data.edges.map((e, i) => {
                  const a = pos.get(e.from), b = pos.get(e.to)
                  if (!a || !b) return null
                  const x1 = a.x + W, y1 = a.y + H / 2, x2 = b.x, y2 = b.y + H / 2
                  const mx = (x1 + x2) / 2
                  const delay = e.kind === 'reported_by' ? 0 : e.kind === 'affects' ? 0.5 : 1.1
                  return (
                    <g key={i} className={`ig-edge ${edgeClass(e)} ${focus && (focus === e.from || focus === e.to) ? 'is-focus' : ''}`}>
                      <path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} className="ig-link" />
                      {!reduce && <circle r={4} className="ig-pkt"
                        style={cssVars({ '--dx': x2 - x1, '--dy': y2 - y1, animationDelay: `${delay}s`, transform: `translate(${x1}px,${y1}px)` })} />}
                    </g>
                  )
                })}
                {data.nodes.map((n) => {
                  const p = pos.get(n.id); if (!p) return null
                  const sub = n.type === 'asset' ? n.role : n.type === 'cve' ? (n.severity ?? '') : n.source
                  return (
                    <g key={n.id} className={`ig-node t-${n.tier} ${focus === n.id ? 'is-focus' : ''}`}
                      transform={`translate(${p.x},${p.y})`} onClick={() => setFocus(focus === n.id ? null : n.id)}
                      role="button" tabIndex={0} onKeyDown={(ev) => { if (ev.key === 'Enter') setFocus(focus === n.id ? null : n.id) }}>
                      <rect className="ig-box" width={W} height={H} rx={7} />
                      {n.tier === 'entry' && <rect className="ig-ring" width={W} height={H} rx={7} />}
                      <text className="ig-nlabel" x={11} y={19}>{n.label ?? n.asset_id}</text>
                      <text className="ig-nsub" x={11} y={35}>{(sub ?? '').slice(0, 22)}</text>
                      {n.type === 'asset' && <circle className={`ig-crit c-${n.criticality}`} cx={W - 14} cy={14} r={5} />}
                      {n.internet_facing && n.type === 'asset' && <text className="ig-wan" x={W - 30} y={38}>WAN</text>}
                    </g>
                  )
                })}
              </svg>

              <aside className="ig-detail">
                {focused ? (
                  <>
                    <p className="ig-d-kick">{focused.type === 'asset' ? focused.tier === 'blast' ? 'Reachable by spread' : 'Directly affected' : focused.type === 'cve' ? 'Advisory' : 'Source feed'}</p>
                    <p className="ig-d-title">{focused.label ?? focused.asset_id}</p>
                    {focused.type === 'asset' && <>
                      <dl className="ig-dl">
                        <dt>Role</dt><dd>{focused.role}</dd>
                        <dt>Org / sector</dt><dd>{focused.organisation} · {focused.sector}</dd>
                        <dt>Criticality</dt><dd>{focused.criticality}/5{focused.internet_facing ? ' · internet-facing' : ' · internal'}</dd>
                        {focused.software && <><dt>Runs</dt><dd>{focused.software}</dd></>}
                        {focused.match_detail && <><dt>Verdict</dt><dd>{focused.match_detail.replace(/_/g, ' ')}{focused.score ? ` · score ${focused.score}` : ''}</dd></>}
                      </dl>
                      {focused.reason && <p className="ig-d-reason">{focused.reason}</p>}
                      {focused.tier === 'blast' && <p className="ig-d-reason">Not directly vulnerable to this CVE — drawn as a lateral-movement target an attacker could reach from a compromised host in the same organisation.</p>}
                    </>}
                    {focused.type === 'cve' && <p className="ig-d-reason">{data.title}</p>}
                  </>
                ) : <p className="ig-d-hint">Click any node to inspect it. <b>Red</b> = internet-facing entry point, <b>amber</b> = directly affected, <b>grey</b> = reachable by lateral movement.</p>}
              </aside>
            </div>
          )}

          <p className="ig-foot"><b>How spread is drawn:</b> {data.spread_model}</p>
          {data.notes.map((note, i) => <p key={i} className="ig-note">{note}</p>)}
          <p className="ig-class">{data.data_classification}</p>
        </>
      )}
    </section>
  )
}
