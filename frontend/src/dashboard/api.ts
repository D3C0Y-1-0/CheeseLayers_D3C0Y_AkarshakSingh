// All backend access for the dashboard. Field names follow data/contracts.json.
// null means "unknown", never 0 or false, so the UI must show it as unknown.
import { useCallback, useEffect, useRef, useState } from 'react'
import assetsFx from '../fixtures/assets.json'
import alertsFx from '../fixtures/alerts_mock.json'
import eventsFx from '../fixtures/events.json'
import overviewFx from '../fixtures/overview_snapshot.json'
import threatsFx from '../fixtures/threats_snapshot.json'

export type Priority = 'low' | 'medium' | 'high' | 'critical'

export type Threat = {
  threat_id: string
  cve_id: string | null
  source: string
  title: string
  description: string | null
  cvss: number | null
  severity: string | null
  epss: number | null
  kev_listed: boolean | null
  public_exploit: boolean | null
  references: string[]
  attack_techniques: string[]
  published_at: string | null
  retrieved_at: string
  is_simulated: boolean
}

export type Asset = {
  asset_id: string
  hostname: string
  ip: string
  organisation: string
  sector: string
  role: string
  os: string | null
  software: { vendor: string; product: string; version: string | null }[]
  criticality: number
  internet_facing: boolean
  owner: string | null
  is_simulated: boolean
}

export type Alert = {
  alert_id: string
  kind: 'vulnerability' | 'behaviour'
  priority: Priority
  status: 'new' | 'ack' | 'resolved'
  asset_ids: string[]
  threat_ids: string[]
  evidence_ids: string[]
  risk_score: number | null
  factors: Record<'severity' | 'exploitation' | 'criticality' | 'exposure' | 'confidence', number | null>
  match_status: 'confirmed' | 'uncertain' | 'requires_manual_review' | null
  reasons: string[]
  limitations: string[]
  timeline: { at: string; event: string; ref: string | null }[]
  created_at: string
  // Not in contracts.json yet. Requested from Member 3. Falls back when missing.
  title?: string
  recommended_actions?: string[]
  is_simulated?: boolean
  lifecycle_status?: string
  match_detail?: string | null
  vulnerability_priority_score?: number
  behavioural_suspicion_score?: number
  evidence_confidence_score?: number
  score_factors?: Record<string, unknown>
  suppressed?: boolean
  assets?: Asset[]
  threats?: Partial<Threat>[]
  // Organisation-defined remediation policy, not a regulatory deadline.
  remediation_target_at?: string | null
  remediation_target_days?: number
  overdue?: boolean | null
  remediation_policy?: string
}

export type StoredEvent = { event_id: string; asset_id: string | null; timestamp: string; event_type: string;
  source_sensor: string; details: Record<string, unknown>; is_simulated: boolean;
  normalized_event?: { raw_ref: string; source: string; ingested_at: string };
  shadow_findings?: { finding_id: string; detector_id: string; reason: string; confidence: string; evidence_ids: string[] }[] }
export type Report = { incident_id: string; summary: string; assessment: string; evidence_ids: string[]; why_relevant: string;
  limitations: string[]; recommended_actions: string[]; references: string[]; generated_by: GeneratedBy;
  is_simulated: boolean; integration_status: string; analyst_review_required: boolean; fallback_reason: string | null
  validation?: Validation | null }
export type GeneratedBy = 'template' | 'llm' | 'llm_cached'
export type Validation = { passed: boolean | null; checked_tokens: number; rejected_tokens: string[]; note: string }
export type Translation = { status: string; label?: string; note?: string }
// POST /api/threats/{id}/summary. Narrative may be LLM-worded; every other field is a stored fact.
export type ThreatSummary = { threat_id: string; cve_id: string | null; is_simulated: boolean; summary: string
  affected_summary: string; exploit_summary: string; why_it_matters: string; recommended_actions: string[]
  affected_assets: { asset_id: string; hostname: string; installed: string | null; match_detail: string; internet_facing: boolean }[]
  alert_ids: string[]; sources: { references: string[]; raw_refs: string[] }
  generated_by: GeneratedBy; validation: Validation | null; fallback_reason: string | null
  language: string; translation?: Translation; analyst_review_required: boolean }
export type DemoResult = { alert_ids: string[]; incident_id: string; handoff_status: string; findings: unknown[];
  evidence: unknown[]; scenario: string }

export type Event = (typeof eventsFx)[number]

// Not defined in contracts.json yet. This is the shape the Command Center expects from Member 2.
export type Overview = {
  snapshot_at: string | null
  threats_received: number
  trend: { date: string; count: number }[]
  sources: { source: string; name: string; records: number | null; newest_record: string | null; status: string }[]
  // Live counts from /api/overview (absent in older bundled samples).
  ioc_count?: number
  iocs_by_type?: Record<string, number>
  kev_count?: number
  public_exploit_count?: number
}

export const fixtures = {
  threats: threatsFx as unknown as Threat[],
  assets: assetsFx as unknown as Asset[],
  alerts: alertsFx as unknown as Alert[],
  events: eventsFx as Event[],
  overview: overviewFx as unknown as Overview,
}

export async function getJson(path: string, init?: RequestInit) {
  // GETs get 15 s: a free cloud host (0.1 CPU) answers in a few seconds; 4 s showed "Backend not connected" there.
  const res = await fetch(path, { ...init, signal: AbortSignal.timeout(init?.method === 'POST' ? 30000 : 15000) })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(typeof body.detail === 'string' ? body.detail : `Request failed (${res.status}). Check the submitted fields.`)
  }
  if (!(res.headers.get('content-type') ?? '').includes('json')) throw new Error('Backend did not return JSON')
  return res.json()
}

// Accepts a bare array or a wrapper like {items: [...]} until response formats are final.
const listOf = <T,>(json: unknown): T[] => {
  if (Array.isArray(json)) return json
  const inner = (json as { items?: unknown })?.items
  if (Array.isArray(inner)) return inner as T[]
  throw new Error('Expected a list')
}

export const parseList = <T,>(json: unknown) => listOf<T>(json)

export type Mode = 'loading' | 'live' | 'sample'

// Asks the backend. If it cannot answer, shows the bundled sample and reports mode "sample",
// so a dead API never gives a blank screen and the page can say what it is showing.
export function useData<T>(path: string, sample: T, parse: (json: unknown) => T, pollMs?: number) {
  const [state, setState] = useState<{ data: T; mode: Mode; error: string | null }>({ data: sample, mode: 'loading', error: null })
  const latest = useRef({ sample, parse })
  useEffect(() => { latest.current = { sample, parse } }, [sample, parse])
  const sequence = useRef(0)

  const load = useCallback(async () => {
    const requestId = ++sequence.current
    try {
      const data = latest.current.parse(await getJson(path))
      if (requestId !== sequence.current) return
      setState({ data, mode: 'live', error: null })
    } catch (e) {
      if (requestId !== sequence.current) return
      setState((prev) => (prev.mode === 'live'
        ? { ...prev, error: 'Lost contact with the backend. Showing the last data received.' }
        : { data: latest.current.sample, mode: 'sample', error: e instanceof Error ? e.message : 'Backend unreachable' }))
    }
  }, [path])

  useEffect(() => {
    const first = setTimeout(load, 0)
    window.addEventListener('vectra:refresh', load)
    const timer = pollMs ? setInterval(load, pollMs) : undefined
    return () => {
      clearTimeout(first)
      clearInterval(timer)
      window.removeEventListener('vectra:refresh', load)
      sequence.current++
    }
  }, [load, pollMs])

  return { ...state, reload: load }
}

// Polling replaces the whole list, keyed by id, so an alert can never appear twice.
const uniqueAlerts = (json: unknown) => [...new Map(listOf<Alert>(json).map((a) => [a.alert_id, a])).values()]

export const useAlerts = () => useData<Alert[]>('/api/alerts', fixtures.alerts, uniqueAlerts, 3000)
export const useThreats = () => useData<Threat[]>('/api/threats', fixtures.threats, listOf<Threat>)
export const useAssets = () => useData<Asset[]>('/api/assets', fixtures.assets, listOf<Asset>)
type BackendOverview = { threats_total: number; newest_retrieved_at: string | null; trend: Overview['trend']; ioc_count?: number
  iocs_by_type?: Record<string, number>; kev_count?: number; public_exploit_count?: number;
  threats_by_source: Record<string, number>; sources: { source: string; status: string; last_success: string | null; record_count: number | null }[] }
export const parseOverview = (json: unknown): Overview => {
  const j = json as BackendOverview
  if (typeof j.threats_total !== 'number' || !Array.isArray(j.trend)) throw new Error('Unsupported overview response')
  return { threats_received: j.threats_total, snapshot_at: j.newest_retrieved_at, trend: j.trend, ioc_count: j.ioc_count,
    iocs_by_type: j.iocs_by_type, kev_count: j.kev_count, public_exploit_count: j.public_exploit_count,
    sources: [...new Set([...Object.keys(j.threats_by_source), ...j.sources.map((s) => s.source)])].map((source) => {
      const health = j.sources.find((s) => s.source === source)
      return { source, name: source, records: j.threats_by_source[source] ?? health?.record_count ?? null,
        newest_record: health?.last_success ?? null, status: health?.status ?? 'Cache available; collector health unknown' }
    }) }
}
export const useOverview = () => useData<Overview>('/api/overview', fixtures.overview, parseOverview, 10000)
export type Health = { demo_mode: boolean; llm?: { cloud_enabled: boolean; reason: string | null; cached_reports: number } | null }
export const useHealth = () => useData<Health>('/health', { demo_mode: false }, (j) => j as Health, 5000)
export const notifyRefresh = () => window.dispatchEvent(new Event('vectra:refresh'))

export const post = (path: string, body?: unknown) =>
  getJson(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })

export const toTitle = (a: Alert) => a.title ?? (a.kind === 'behaviour' ? `Suspicious behaviour on ${a.asset_ids[0] ?? 'unknown asset'}` : `${a.threat_ids[0]} on ${a.asset_ids[0]}`)

export const when = (iso: string | null) =>
  iso && !Number.isNaN(Date.parse(iso)) ? new Date(iso).toLocaleString('en-IN', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Kolkata' }) : 'Unknown'
