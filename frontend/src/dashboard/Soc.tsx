import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Bell, Bot, ChevronDown, ExternalLink, LayoutGrid, Plus, Search, SendHorizontal, Sparkles, X } from 'lucide-react'
import { getJson, parseList, post, toTitle, useAlerts, useAssets, useData, useHealth, useOverview, when, type Alert, type StoredEvent, type Threat, type ThreatSummary } from './api'
import { Globe, type Arc, type Satellite } from './soc/Globe'
import postureFx from '../fixtures/api/sectors_posture.json'
import './soc/soc.css'

// Security Operations Center: one live screen over every feed, alert and asset.
// Every number here comes from the API (or the bundled sample when the backend is down); nothing is invented.
// Attacker IPs come from the stored sensor evidence of live incidents; search queries the backend.

type Sector = { sector: string; label: string; active_incidents: number; active_critical_high_incidents: number; weighted_sector_risk_score: number }
type Posture = { sectors: Sector[]; data_classification: string }

// Where each feed is published from. The feeds are global; this is the publisher's location.
const ORIGIN: Record<string, { at: [number, number]; label: string }> = {
  nvd: { at: [-77.2, 39.1], label: 'NVD' },
  kev: { at: [-77.0, 38.9], label: 'CISA KEV' },
  epss: { at: [-78.8, 35.8], label: 'FIRST EPSS' },
  attack_techniques: { at: [-71.3, 42.5], label: 'MITRE' },
  otx: { at: [-122.3, 37.5], label: 'OTX' },
  abusech: { at: [8.5, 47.4], label: 'abuse.ch' },
  threatfox: { at: [8.5, 47.4], label: 'abuse.ch' },
  urlhaus: { at: [8.5, 47.4], label: 'abuse.ch' },
}
const IOC_FEEDS = new Set(['abusech', 'threatfox', 'urlhaus', 'ip_reputation', 'otx'])
const FEED_NAME: Record<string, string> = { nvd: 'NVD', kev: 'CISA KEV', certin: 'CERT-In', otx: 'AlienVault OTX', threatfox: 'ThreatFox', urlhaus: 'URLhaus', abusech: 'abuse.ch', ransomware: 'Ransomware', epss: 'EPSS', ip_reputation: 'IP reputation', attack_techniques: 'MITRE ATT&CK' }
const SUGGEST = ['CVE-2024-21762', 'patient-portal', 'Fortinet', 'ransomware']
const fmt = (n: number) => n.toLocaleString('en-IN')
const healthy = (status: string) => !/fail|error|stale|down/i.test(status)

function Select<T extends string>({ label, value, options, onChange }: { label: string; value: T; options: [T, string][]; onChange: (v: T) => void }) {
  return (
    <label className="soc-select">
      <span>{label}:</span>
      <select value={value} onChange={(e) => onChange(e.target.value as T)} aria-label={label}>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>
      <ChevronDown aria-hidden className="size-3.5" />
    </label>
  )
}

function Card({ title, to, children, className = '' }: { title: string; to?: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={`soc-card ${className}`}>
      <header>
        <h2>{title}</h2>
        {to && <Link to={to} aria-label={`Open ${title}`} className="soc-card-link"><ExternalLink aria-hidden className="size-3.5" /></Link>}
      </header>
      {children}
    </section>
  )
}

// Semicircle of open incidents: each severity takes a share of the arc proportional to its count.
const ARC_COLOR: Record<string, string> = { hot: 'var(--soc-hot)', mid: 'var(--soc-amber)', low: 'var(--soc-teal)' }
function ThreatArc({ levels, total }: { levels: { label: string; count: number; tone: string }[]; total: number }) {
  const R = 80, C = Math.PI * R  // half circumference
  let used = 0
  return (
    <div className="soc-arc">
      <svg viewBox="0 0 200 112" role="img" aria-label={`${total} open incidents: ${levels.map((l) => `${l.count} ${l.label}`).join(', ')}`}>
        <path d="M20 100 A80 80 0 0 1 180 100" className="soc-arc-track" />
        {total > 0 && levels.filter((l) => l.count).map((l) => {
          const len = (l.count / total) * C
          const seg = <path key={l.label} d="M20 100 A80 80 0 0 1 180 100" className="soc-arc-seg" stroke={ARC_COLOR[l.tone]}
            strokeDasharray={`${Math.max(0, len - 2)} ${C}`} strokeDashoffset={-used} />
          used += len
          return seg
        })}
        <text x="100" y="86" textAnchor="middle" className="soc-arc-num">{total}</text>
        <text x="100" y="104" textAnchor="middle" className="soc-arc-sub">open incidents</text>
      </svg>
      <ul className="soc-arc-legend">
        {levels.map((l) => <li key={l.label}><i style={{ background: ARC_COLOR[l.tone] }} aria-hidden />{l.label}<b>{l.count}</b></li>)}
      </ul>
    </div>
  )
}

type Answer = { q: string; busy?: boolean; text?: string; by?: string; links: { to: string; label: string; sub: string }[]; note?: string }

export default function Soc() {
  const navigate = useNavigate()
  const overview = useOverview()
  const alerts = useAlerts()
  const assets = useAssets()
  const health = useHealth()
  const posture = useData<Posture>('/api/sectors/posture', postureFx as unknown as Posture, (j) => j as Posture, 15000)

  const [sector, setSector] = useState('all')
  const [region, setRegion] = useState<'india' | 'global'>('india')
  const [source, setSource] = useState('all')
  const [search, setSearch] = useState('')
  const [bell, setBell] = useState(false)
  const [suggest, setSuggest] = useState(false)
  const [q, setQ] = useState('')
  const [answer, setAnswer] = useState<Answer | null>(null)
  const askRef = useRef<HTMLInputElement>(null)

  // Attacker IPs: read from each open high/critical behaviour incident's stored evidence (GET /api/alerts/{id}/evidence).
  const [attackers, setAttackers] = useState<string[]>([])
  const hotIds = alerts.mode === 'live' ? alerts.data.filter((a) => a.kind === 'behaviour' && a.status !== 'resolved' && !a.suppressed
    && (a.priority === 'critical' || a.priority === 'high')).map((a) => a.alert_id).slice(0, 8).join(',') : ''
  useEffect(() => {
    if (!hotIds) { setAttackers([]); return }
    let alive = true
    Promise.all(hotIds.split(',').map((id) => getJson(`/api/alerts/${encodeURIComponent(id)}/evidence`).then(parseList<StoredEvent>).catch(() => [] as StoredEvent[])))
      .then((lists) => {
        if (!alive) return
        const ips = lists.flat().flatMap((e) => [e.details.client_ip, e.details.dest_ip, e.details.src_ip, e.details.source_ip])
          .filter((x): x is string => typeof x === 'string' && /^\d{1,3}(\.\d{1,3}){3}$/.test(x))
        setAttackers([...new Set(ips)].slice(0, 12))
      })
    return () => { alive = false }
  }, [hotIds])

  const sectorOf = useMemo(() => new Map(assets.data.map((a) => [a.asset_id, a.sector])), [assets.data])
  const inSector = (a: Alert) => sector === 'all' || a.asset_ids.some((id) => sectorOf.get(id) === sector)
  const open = alerts.data.filter((a) => a.status !== 'resolved' && inSector(a))
  const live = open.filter((a) => !a.suppressed)
  const sources = overview.data.sources.filter((s) => source === 'all' || s.source === source)

  // Globe: arcs per feed publisher, nodes per sector plus attacker IPs from evidence.
  const arcs: Arc[] = [...new Map(sources.filter((s) => ORIGIN[s.source]).map((s) => [ORIGIN[s.source].at.join(','), { id: s.source, from: ORIGIN[s.source].at, label: ORIGIN[s.source].label }])).values()]
  const maxRisk = Math.max(1, ...posture.data.sectors.map((s) => s.weighted_sector_risk_score))
  const satellites: Satellite[] = [
    ...posture.data.sectors.map((s) => ({ id: s.sector, label: s.label.toUpperCase(), sub: `RISK ${s.weighted_sector_risk_score.toFixed(1)}${s.active_incidents ? ` · ${s.active_incidents} OPEN` : ''}`, weight: s.weighted_sector_risk_score / maxRisk, tone: (s.active_critical_high_incidents ? 'amber' : 'teal') as Satellite['tone'], active: sector === 'all' || sector === s.sector })),
    ...attackers.map((ip) => ({ id: ip, label: ip, sub: 'SOURCE IP IN EVIDENCE', weight: 0.6, tone: 'red' as const, active: true })),
  ]

  // Side panel: plain counts, all from the API.
  const feedsOk = overview.data.sources.filter((s) => healthy(s.status)).length
  const iocTotal = overview.data.ioc_count ?? sources.filter((s) => IOC_FEEDS.has(s.source)).reduce((n, s) => n + (s.records ?? 0), 0)
  const trend = overview.data.trend
  const levels = [
    { label: 'Critical / High', list: live.filter((a) => a.priority === 'critical' || a.priority === 'high'), tone: 'hot' },
    { label: 'Medium', list: live.filter((a) => a.priority === 'medium'), tone: 'mid' },
    { label: 'Low', list: live.filter((a) => a.priority === 'low'), tone: 'low' },
  ]
  const sectors = posture.data.sectors
  const fresh = alerts.data.filter((a) => a.status === 'new' && !a.suppressed)
  const ai = health.data.llm

  // "Ask Threat Intelligence": a CVE ID gets the grounded AI summary; anything else searches our own data.
  const ask = async (raw: string) => {
    const text = raw.trim()
    if (!text) return
    setSuggest(false)
    const needle = text.toLowerCase()
    const hit = (s: string | null | undefined) => !!s && s.toLowerCase().includes(needle)
    const links = [
      ...alerts.data.filter((a) => hit(toTitle(a)) || a.asset_ids.some(hit) || a.threat_ids.some(hit)).slice(0, 3).map((a) => ({ to: `/app/incidents/${encodeURIComponent(a.alert_id)}`, label: toTitle(a), sub: `Incident · ${a.priority}` })),
      ...(await getJson(`/api/threats?q=${encodeURIComponent(text)}&page_size=3`).then(parseList<Threat>).catch(() => [] as Threat[])).map((t) => ({ to: `/app/threats?search=${encodeURIComponent(t.threat_id)}`, label: t.title, sub: `Threat · ${t.source}${t.is_simulated ? ' · simulated' : ''}` })),
      ...assets.data.filter((a) => hit(a.hostname) || hit(a.asset_id) || hit(a.role) || a.software.some((s) => hit(s.product) || hit(s.vendor))).slice(0, 3).map((a) => ({ to: `/app/assets`, label: `${a.hostname} (${a.asset_id})`, sub: `Asset · ${a.role}` })),
    ]
    const cve = text.match(/CVE-\d{4}-\d{4,}/i)?.[0].toUpperCase()
    const base = { q: text, links, note: links.length ? undefined : 'Nothing in the current feeds, alerts or inventory matches that.' }
    if (!cve) {
      setAnswer({ ...base, by: 'Search across feeds, alerts and inventory', text: links.length ? `${links.length} match${links.length === 1 ? '' : 'es'} for “${text}”.` : undefined })
      return
    }
    setAnswer({ ...base, busy: true })
    try {
      const s = await post(`/api/threats/${encodeURIComponent(cve)}/summary`) as ThreatSummary
      setAnswer({ ...base, text: `${s.summary} ${s.why_it_matters}`, by: s.generated_by === 'template' ? 'Template · grounded' : s.generated_by === 'llm_cached' ? 'LLM-cached · grounding checked' : 'LLM · grounding checked', note: s.recommended_actions[0] ? `Recommended: ${s.recommended_actions[0]}` : undefined })
    } catch {
      const t = (await getJson(`/api/threats/${encodeURIComponent(cve)}`).catch(() => null)) as Threat | null
      setAnswer({ ...base, text: t ? `${t.title}. CVSS ${t.cvss ?? 'unknown'}; ${t.kev_listed === null ? 'exploitation status unknown' : t.kev_listed ? 'listed in CISA KEV (actively exploited)' : 'not in CISA KEV'}.` : `No stored record for ${cve}.`, by: 'Stored record · AI summary needs the backend' })
    }
  }

  const sectorOptions: [string, string][] = [['all', 'Global SOC'], ...sectors.map((s) => [s.sector, s.label] as [string, string])]
  const sourceOptions: [string, string][] = [['all', 'All feeds'], ...overview.data.sources.map((s) => [s.source, FEED_NAME[s.source] ?? s.name] as [string, string])]

  return (
    <div className="soc">
      <div className="soc-top">
        <span className="soc-logo" aria-hidden><LayoutGrid className="size-5" /></span>
        <div className="soc-filters">
          <Select label="Team" value={sector} options={sectorOptions} onChange={setSector} />
          <Select label="Region" value={region} options={[['india', 'Asia Pacific'], ['global', 'Global']]} onChange={setRegion} />
          <Select label="Threat" value={source} options={sourceOptions} onChange={setSource} />
        </div>
        <form className="soc-search" role="search" onSubmit={(e) => { e.preventDefault(); if (search.trim()) navigate(`/app/threats?search=${encodeURIComponent(search.trim())}`) }}>
          <input type="search" placeholder="Search by name, CVE…" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search threats" />
          <Search aria-hidden className="size-4" />
        </form>
        <div className="soc-bell">
          <button type="button" aria-label={`${fresh.length} new alerts`} aria-expanded={bell} onClick={() => setBell((v) => !v)}>
            <Bell aria-hidden className="size-4" />
            {fresh.length > 0 && <i>{fresh.length}</i>}
          </button>
          {bell && (
            <ul className="soc-pop">
              {fresh.slice(0, 6).map((a) => <li key={a.alert_id}><Link to={`/app/incidents/${encodeURIComponent(a.alert_id)}`}><b className={`is-${a.priority}`}>{a.priority}</b>{toTitle(a)}</Link></li>)}
              {fresh.length === 0 && <li className="px-3 py-2">No new alerts.</li>}
            </ul>
          )}
        </div>
        <span className="soc-avatar" title="SOC analyst">SA</span>
      </div>

      <div className="soc-stage">
        <div className="soc-head">
          <h1>Security Operations Center</h1>
          <p>Real-Time Threat Intelligence &amp; Incident Monitoring <span className={`soc-live ${alerts.mode === 'live' ? 'is-live' : ''}`}><i aria-hidden />{alerts.mode === 'live' ? 'Live' : alerts.mode === 'loading' ? 'Connecting' : 'Sample data'}</span></p>
        </div>
        <Globe arcs={arcs} satellites={satellites} spin={region === 'india' ? 'india' : 'free'} />

        {answer && (
          <div className="soc-answer" role="status">
            <header>
              <span><Sparkles aria-hidden className="size-3.5" />{answer.busy ? 'Analysing…' : answer.by}</span>
              <button type="button" aria-label="Close answer" onClick={() => setAnswer(null)}><X aria-hidden className="size-4" /></button>
            </header>
            <p className="soc-answer-q">{answer.q}</p>
            {answer.text && <p>{answer.text}</p>}
            {answer.note && <p className="soc-muted">{answer.note}</p>}
            {answer.links.length > 0 && <ul>{answer.links.map((l) => <li key={l.to + l.label}><Link to={l.to}>{l.label}</Link><span>{l.sub}</span></li>)}</ul>}
          </div>
        )}

        <div className="soc-ask">
          <form onSubmit={(e) => { e.preventDefault(); ask(q) }}>
            <Sparkles aria-hidden className="size-4 text-[var(--soc-teal)]" />
            <input ref={askRef} placeholder="Ask Threat Intelligence… (a CVE, host, vendor or keyword)" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Ask threat intelligence" />
            <button type="submit" className="soc-send" aria-label="Ask"><SendHorizontal aria-hidden className="size-4" /></button>
          </form>
          <div className="soc-chips">
            <button type="button" className="soc-chip" onClick={() => askRef.current?.focus()}><Bot aria-hidden className="size-3.5" />My agent</button>
            <div className="relative">
              <button type="button" className="soc-chip" aria-expanded={suggest} onClick={() => setSuggest((v) => !v)}><Plus aria-hidden className="size-3.5" />{SUGGEST.length - 1}</button>
              {suggest && (
                <ul className="soc-pop is-up">
                  {SUGGEST.map((s) => <li key={s}><button type="button" onClick={() => { setQ(s); ask(s) }}>{s}</button></li>)}
                </ul>
              )}
            </div>
            <span className="soc-chip is-right" title={ai?.reason ?? undefined}><Sparkles aria-hidden className="size-3.5" />AI Security Analyst · {health.mode !== 'live' ? 'offline' : ai?.cloud_enabled ? 'cloud LLM' : 'template'}</span>
          </div>
        </div>
      </div>

      <aside className="soc-side">
        <Card title="Open incidents" to="/app/incidents">
          <ThreatArc levels={levels.map((l) => ({ label: l.label, count: l.list.length, tone: l.tone }))} total={live.length} />
        </Card>
        <Card title="Threat intelligence" to="/app/threats">
          <p className="soc-big">{fmt(iocTotal)}</p>
          <p className="soc-muted">malicious IPs, domains, URLs and file hashes we watch for</p>
          <dl className="soc-facts">
            <div><dt>Threat records collected</dt><dd>{fmt(overview.data.threats_received)}</dd></div>
            <div><dt>New on the latest day</dt><dd>+{fmt(trend[trend.length - 1]?.count ?? 0)}</dd></div>
            {overview.data.kev_count !== undefined && <div><dt>Actively exploited (CISA KEV)</dt><dd>{fmt(overview.data.kev_count)}</dd></div>}
            {overview.data.public_exploit_count !== undefined && <div><dt>Public exploit code exists</dt><dd>{fmt(overview.data.public_exploit_count)}</dd></div>}
            <div><dt>Feeds healthy</dt><dd>{feedsOk} of {overview.data.sources.length}</dd></div>
          </dl>
          <p className="soc-muted">Newest record received {when(overview.data.snapshot_at)} · refreshes every 10 s</p>
        </Card>
      </aside>
    </div>
  )
}
