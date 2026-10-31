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
}

export type Event = (typeof eventsFx)[number]

// Not defined in contracts.json yet. This is the shape the Command Center expects from Member 2.
export type Overview = {
  snapshot_at: string | null
  threats_received: number
  trend: { date: string; count: number }[]
  sources: { source: string; name: string; records: number; newest_record: string | null; status: string }[]
}

export const fixtures = {
  threats: threatsFx as unknown as Threat[],
  assets: assetsFx as unknown as Asset[],
  alerts: alertsFx as unknown as Alert[],
  events: eventsFx as Event[],
  overview: overviewFx as unknown as Overview,
}

async function getJson(path: string, init?: RequestInit) {
  const res = await fetch(path, { ...init, signal: AbortSignal.timeout(init?.method === 'POST' ? 30000 : 4000) })
  if (!res.ok) throw new Error(`${path} returned ${res.status}`)
  return res.json()
}

// Accepts a bare array or a wrapper like {items: [...]} until response formats are final.
const listOf = <T,>(json: unknown): T[] => {
  if (Array.isArray(json)) return json
  const inner = Object.values((json ?? {}) as object).find(Array.isArray)
  if (inner) return inner as T[]
  throw new Error('Expected a list')
}

export const parseList = <T,>(json: unknown) => listOf<T>(json)

export type Mode = 'loading' | 'live' | 'sample'

// Asks the backend. If it cannot answer, shows the bundled sample and reports mode "sample",
// so a dead API never gives a blank screen and the page can say what it is showing.
export function useData<T>(path: string, sample: T, parse: (json: unknown) => T, pollMs?: number) {
  const [state, setState] = useState<{ data: T; mode: Mode; error: string | null }>({ data: sample, mode: 'loading', error: null })
  const latest = useRef({ sample, parse })

  const load = useCallback(async () => {
    try {
      const data = latest.current.parse(await getJson(path))
      setState({ data, mode: 'live', error: null })
    } catch (e) {
      setState((prev) => (prev.mode === 'live'
        ? { ...prev, error: 'Lost contact with the backend. Showing the last data received.' }
        : { data: latest.current.sample, mode: 'sample', error: e instanceof Error ? e.message : 'Backend unreachable' }))
    }
  }, [path])

  useEffect(() => {
    const first = setTimeout(load, 0)
    if (!pollMs) return () => clearTimeout(first)
    const timer = setInterval(load, pollMs)
    return () => {
      clearTimeout(first)
      clearInterval(timer)
    }
  }, [load, pollMs])

  return { ...state, reload: load }
}

// Polling replaces the whole list, keyed by id, so an alert can never appear twice.
const uniqueAlerts = (json: unknown) => [...new Map(listOf<Alert>(json).map((a) => [a.alert_id, a])).values()]

export const useAlerts = () => useData<Alert[]>('/api/alerts', fixtures.alerts, uniqueAlerts, 3000)
export const useThreats = () => useData<Threat[]>('/api/threats', fixtures.threats, listOf<Threat>)
export const useAssets = () => useData<Asset[]>('/api/assets', fixtures.assets, listOf<Asset>)
export const useOverview = () => useData<Overview>('/api/overview', fixtures.overview, (j) => j as Overview)

export const post = (path: string, body?: unknown) =>
  getJson(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })

export const toTitle = (a: Alert) => a.title ?? (a.kind === 'behaviour' ? `Suspicious behaviour on ${a.asset_ids[0] ?? 'unknown asset'}` : `${a.threat_ids[0]} on ${a.asset_ids[0]}`)

export const when = (iso: string | null) =>
  iso ? new Date(iso).toLocaleString('en-IN', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Kolkata' }) : 'Unknown'
