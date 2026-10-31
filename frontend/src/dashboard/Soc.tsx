import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Bell, Bot, ChevronDown, ExternalLink, LayoutGrid, Plus, Search, SendHorizontal, Sparkles, X } from 'lucide-react'
import { fixtures, post, toTitle, useAlerts, useAssets, useData, useHealth, useOverview, useThreats, when, type Alert, type ThreatSummary } from './api'
import { Globe, type Arc, type Satellite } from './soc/Globe'
import { Gauge, Ring, Timeline, VolumeBars } from './soc/charts'
import postureFx from '../fixtures/api/sectors_posture.json'
import leadFx from '../fixtures/api/lead_time.json'
import './soc/soc.css'

// Security Operations Center: one live screen over every feed, alert and asset.
// Every number here comes from the API (or the bundled sample when the backend is down); nothing is invented.

type Sector = { sector: string; label: string; active_incidents: number; active_critical_high_incidents: number; weighted_sector_risk_score: number }
type Posture = { sectors: Sector[]; data_classification: string }
type Lead = { window_days: number; pct_flagged_before_kev: number; median_lead_days: number | null }

const RANGES = { '24h': { days: 1, label: 'Last 24 hours' }, '7d': { days: 7, label: 'Last 7 days' }, '14d': { days: 14, label: 'Last 14 days' } } as const
type Range = keyof typeof RANGES
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

type Answer = { q: string; busy?: boolean; text?: string; by?: string; links: { to: string; label: string; sub: string }[]; note?: string }

export default function Soc() {
  const navigate = useNavigate()
  const overview = useOverview()
  const alerts = useAlerts()
  const threats = useThreats()
  const assets = useAssets()
  const health = useHealth()
  const posture = useData<Posture>('/api/sectors/posture', postureFx as unknown as Posture, (j) => j as Posture, 15000)
  const lead = useData<Lead>('/api/insights/lead-time?days=90', leadFx as unknown as Lead, (j) => j as Lead)

  const [sector, setSector] = useState('all')
  const [region, setRegion] = useState<'india' | 'global'>('india')
  const [range, setRange] = useState<Range>('24h')
  const [source, setSource] = useState('all')
  const [search, setSearch] = useState('')
  const [bell, setBell] = useState(false)
  const [suggest, setSuggest] = useState(false)
  const [q, setQ] = useState('')
  const [answer, setAnswer] = useState<Answer | null>(null)
  const askRef = useRef<HTMLInputElement>(null)
  // A clock for the sliding time window, so buckets move forward while the page is open.
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30000)
    return () => clearInterval(t)
  }, [])

  const sectorOf = useMemo(() => new Map(assets.data.map((a) => [a.asset_id, a.sector])), [assets.data])
  const inSector = (a: Alert) => sector === 'all' || a.asset_ids.some((id) => sectorOf.get(id) === sector)
  const open = alerts.data.filter((a) => a.status !== 'resolved' && inSector(a))
  const live = open.filter((a) => !a.suppressed)
  const sources = overview.data.sources.filter((s) => source === 'all' || s.source === source)

  // Globe: arcs per feed publisher, nodes per sector plus attacker IPs from evidence.
  const arcs: Arc[] = [...new Map(sources.filter((s) => ORIGIN[s.source]).map((s) => [ORIGIN[s.source].at.join(','), { id: s.source, from: ORIGIN[s.source].at, label: ORIGIN[s.source].label }])).values()]
  const maxRisk = Math.max(1, ...posture.data.sectors.map((s) => s.weighted_sector_risk_score))
  const attackers = [...new Set(live.filter((a) => a.kind === 'behaviour' && (a.priority === 'critical' || a.priority === 'high')).flatMap((a) => a.evidence_ids.flatMap((id) => {
    const d = fixtures.events.find((e) => e.event_id === id)?.details as Record<string, unknown> | undefined
    if (!d || d.client_label !== undefined) return []
    return [d.client_ip, d.dest_ip, d.src_ip].filter((x): x is string => typeof x === 'string')
  })))]
  const satellites: Satellite[] = [
    ...posture.data.sectors.map((s) => ({ id: s.sector, label: s.label.toUpperCase(), sub: `RISK ${s.weighted_sector_risk_score.toFixed(1)}${s.active_incidents ? ` · ${s.active_incidents} OPEN` : ''}`, weight: s.weighted_sector_risk_score / maxRisk, tone: (s.active_critical_high_incidents ? 'amber' : 'teal') as Satellite['tone'], active: sector === 'all' || sector === s.sector })),
    ...attackers.map((ip) => ({ id: ip, label: ip, sub: 'ATTACKER', weight: 0.6, tone: 'red' as const, active: true })),
  ]

  // Timeline + volume
  const days = RANGES[range].days
  const trend = overview.data.trend
  const recent = trend.slice(-Math.max(1, days))
  const volume = recent.reduce((n, d) => n + d.count, 0)
  const end = now
  const span = days * 24 * 3600 * 1000
  const nB = days === 1 ? 24 : days
  const bucketMs = span / nB
  const buckets = Array.from({ length: nB }, (_, i) => {
    const t = new Date(end - span + i * bucketMs)
    return { label: days === 1 ? t.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Kolkata' }) : t.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', timeZone: 'Asia/Kolkata' }), count: 0 }
  })
  for (const a of open) for (const ev of a.timeline) {
    const i = Math.floor((Date.parse(ev.at) - (end - span)) / bucketMs)
    if (i >= 0 && i < nB) buckets[i].count++
  }

  // Radar + detection
  const iocTotal = sources.filter((s) => source !== 'all' || IOC_FEEDS.has(s.source)).reduce((n, s) => n + (s.records ?? 0), 0)
  const feedsOk = overview.data.sources.filter((s) => healthy(s.status)).length
  const band = (p: Alert['priority'][]) => live.filter((a) => p.includes(a.priority))
  const split = (list: Alert[]) => `${list.filter((a) => a.kind === 'vulnerability').length} CVE · ${list.filter((a) => a.kind === 'behaviour').length} BEH`
  const conf = (kind: Alert['kind']) => {
    const v = live.filter((a) => a.kind === kind).map((a) => a.evidence_confidence_score ?? a.factors?.confidence).filter((x): x is number => typeof x === 'number')
    return v.length ? v.reduce((s, x) => s + x, 0) / v.length : null
  }
  const bands = [
    { k: 'High risk', list: band(['critical', 'high']), tone: 'hot' },
    { k: 'Medium', list: band(['medium']), tone: 'mid' },
    { k: 'Low', list: band(['low']), tone: 'low' },
    { k: 'Not escalated', list: open.filter((a) => a.suppressed), tone: 'quiet' },
  ]

  // KPIs
  const sectors = posture.data.sectors
  const postureScore = sectors.length ? Math.round(100 - sectors.reduce((n, s) => n + s.weighted_sector_risk_score, 0) / sectors.length) : null
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
      ...threats.data.filter((t) => hit(t.threat_id) || hit(t.title) || hit(t.cve_id)).slice(0, 3).map((t) => ({ to: `/app/threats?search=${encodeURIComponent(t.threat_id)}`, label: t.title, sub: `Threat · ${t.source}${t.is_simulated ? ' · simulated' : ''}` })),
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
      setAnswer({ ...base, text: `${s.summary} ${s.why_it_matters}`, by: s.generated_by === 'template' ? 'Template · grounded' : 'LLM · grounding checked', note: s.recommended_actions[0] ? `Recommended: ${s.recommended_actions[0]}` : undefined })
    } catch {
      const t = threats.data.find((x) => x.cve_id === cve || x.threat_id === cve)
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
          <Select label="Time Range" value={range} options={Object.entries(RANGES).map(([k, v]) => [k as Range, v.label])} onChange={setRange} />
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

        <Card title="Threat Activity Timeline" to="/app/signals" className="soc-timeline-card">
          <Timeline days={trend} range={days} buckets={buckets} bucketLabel={days === 1 ? 'hour' : 'day'} />
        </Card>

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

      <div className="soc-kpis">
        <div className="soc-kpi">
          <span>Security Score</span>
          <b>{postureScore === null ? '–' : `${postureScore}%`}<em>{sectors.filter((s) => !s.active_critical_high_incidents).length}/{sectors.length} sectors clear</em></b>
          <small title={posture.data.data_classification}>100 − average sector risk</small>
        </div>
        <div className="soc-kpi">
          <span>Threat Records Ingested</span>
          <b>{fmt(overview.data.threats_received)}<em>+{fmt(trend[trend.length - 1]?.count ?? 0)} latest day</em></b>
          <small>Across {overview.data.sources.length} feeds · {when(overview.data.snapshot_at)}</small>
        </div>
        <div className="soc-kpi is-wide">
          <span>Early Warning Lead · last {lead.data.window_days} days</span>
          <div className="soc-kpi-rings">
            <p><Ring value={lead.data.pct_flagged_before_kev / 100} /><b>{lead.data.pct_flagged_before_kev}%</b><small>before CISA KEV</small></p>
            <i className="soc-kpi-sep" aria-hidden />
            <p><Ring value={lead.data.median_lead_days === null ? null : Math.min(1, lead.data.median_lead_days / 60)} /><b>{lead.data.median_lead_days ?? '–'}</b><small>d median lead</small></p>
          </div>
        </div>
      </div>

      <aside className="soc-side">
        <Card title="Global Threat Radar" to="/app/threats">
          <Gauge value={overview.data.sources.length ? feedsOk / overview.data.sources.length : 0} big={fmt(iocTotal)} label={source === 'all' ? 'Malicious indicators tracked' : `${FEED_NAME[source] ?? source} records`} />
          <p className="soc-muted text-center">{feedsOk} of {overview.data.sources.length} feeds healthy</p>
        </Card>
        <Card title="Attack Volume Trend" to="/app/threats">
          <p className="soc-big">{fmt(volume)} <span>records · {RANGES[range].label.toLowerCase()}</span></p>
          <VolumeBars series={trend.slice(-Math.max(days, 7))} />
        </Card>
        <Card title="AI Threat Detection" to="/app/incidents" className="soc-detect">
          <div className="soc-bands">
            {bands.map((b) => (
              <Link key={b.k} to="/app/incidents" className="soc-band">
                <span>{b.k}<i className={`is-${b.tone}`}>{split(b.list)}</i></span>
                <b>{b.list.length}</b>
              </Link>
            ))}
          </div>
          <h3>AI Confidence</h3>
          {([['vulnerability', 'CVE match confidence'], ['behaviour', 'Behaviour evidence confidence']] as const).map(([k, l]) => {
            const c = conf(k)
            return (
              <div key={k} className="soc-conf">
                <span>{l}<b>{c === null ? 'n/a' : `${Math.round(c * 100)}%`}</b></span>
                <i><em style={{ width: `${(c ?? 0) * 100}%` }} /></i>
              </div>
            )
          })}
        </Card>
      </aside>
    </div>
  )
}
