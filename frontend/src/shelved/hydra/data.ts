// Everything on the landing page that claims a fact lives here, so it is easy to audit.
// Counts were read from backend/data/cache on 31 Oct 2026. Re-read them after a fresh collector run.

export const PRODUCT = 'Vectra'

export const COUNTS = {
  threats: 19534,
  iocs: 23644,
}

export const SOURCES = [
  { name: 'NVD', gives: 'Vulnerability text, severity and affected products', count: 17358, unit: 'CVEs' },
  { name: 'CISA KEV', gives: 'Flaws confirmed as exploited in real attacks', count: 1766, unit: 'CVEs' },
  { name: 'FIRST EPSS', gives: 'Probability a flaw is exploited in the next 30 days', count: 18366, unit: 'scores' },
  { name: 'CERT-In', gives: 'Advisories written for Indian organisations', count: 40, unit: 'advisories' },
  { name: 'abuse.ch', gives: 'Malicious URLs, domains, IPs and file hashes', count: 17703, unit: 'indicators' },
  { name: 'AlienVault OTX', gives: 'Community reports of active campaigns', count: 5941, unit: 'indicators' },
  { name: 'MITRE ATT&CK', gives: 'The catalogue of known attacker techniques', count: 706, unit: 'techniques' },
]

// Real identifiers from the cache. They are drawn as the raw fragments in the sphere.
// Only IDs and truncated hashes appear here: never a live malicious URL or domain.
export const RAW_LABELS = [
  'CVE-2024-3400', 'CVE-2023-29360', 'CVE-2025-59230', 'CVE-2023-2868', 'CVE-2019-15107', 'CVE-2025-53521',
  'CVE-2021-40450', 'CVE-2026-20230', 'CVE-2017-12637', 'CVE-2021-27137', 'CVE-2021-22899', 'CVE-2015-2387',
  'CIAD-2026-0057', 'CIAD-2026-0056', 'CIAD-2026-0054', 'CIAD-2026-0053', 'CIAD-2026-0052',
  'T1649', 'T1110.002', 'T1546.014', 'T1055.002', 'T1036.004',
  'Katz Stealer', 'DragonForce', 'NetWire RC', 'EtherRAT', 'Mirai',
  '5edcbff61370', '46fb97298a4a', 'e5c584172ec0', 'a2572af43c9b', '922aa5838e54',
]

// Labels shown on graph hubs while the AI is linking threats together.
export const GRAPH_LABELS = ['CIAD-2026-0054', 'T1190', 'Mirai', 'Fortinet', 'CVE-2023-20198', 'Citrix NetScaler', 'T1566', 'DragonForce']

// The one warning the page walks through. The CVE facts are real. The asset is simulated.
export const MATCH = {
  cve: 'CVE-2024-3400',
  product: 'PAN-OS 11.1.2',
  fixed: '11.1.2-h3',
  asset: 'gw-grid-01',
}

export type ScoreInput = {
  cvss: number
  inKev: boolean
  epss: number
  criticality: number
  internetFacing: boolean
  confidence: number
}

// Same formula as CLAUDE.md section 9. Keep the two in step.
export function riskFactors(s: ScoreInput) {
  const exploit = s.inKev ? 1 : Math.max(s.epss, 0.05)
  const exposure = s.internetFacing ? 1 : 0.5
  const score = 100 * (s.cvss / 10) * Math.sqrt(exploit) * (s.criticality / 5) * exposure * s.confidence
  return { exploit, exposure, score }
}

export function riskLevel(score: number) {
  if (score >= 75) return 'Critical'
  if (score >= 50) return 'High'
  if (score >= 25) return 'Medium'
  return 'Low'
}

// The walkthrough warning: CVSS 10, in KEV, criticality 4, internet-facing, exact version.
export const WALKTHROUGH: ScoreInput = {
  cvss: 10,
  inKev: true,
  epss: 0.99,
  criticality: 4,
  internetFacing: true,
  confidence: 1,
}

export const STEPS = [
  {
    at: 0,
    title: ['Read every threat.', 'Raise the ones that reach you.'],
    body: `${PRODUCT} reads national and global threat feeds, checks them against the systems you run, and warns your team before an attacker gets there.`,
  },
  {
    at: 0.13,
    title: [`${COUNTS.threats.toLocaleString('en-IN')} threats collected.`, 'Seven feeds, one format.'],
    body: 'Advisories, vulnerability databases, indicator feeds and simulated logs all cross the same line and come out in the same shape.',
  },
  {
    at: 0.32,
    title: ['AI links what was', 'reported separately.'],
    body: 'Shared CVEs, shared indicators and similar language connect separate reports, so a campaign shows up while it is still forming.',
  },
  {
    at: 0.5,
    title: ['One advisory matches', 'a system you run.'],
    body: 'The advisory covers PAN-OS below 11.1.2-h3. Your inventory shows 11.1.2 running on an exposed power-sector gateway.',
  },
  {
    at: 0.68,
    title: ['Critical, and you can', 'see exactly why.'],
    body: 'The score is plain arithmetic on five factors, so an analyst can check it and argue with it.',
  },
  {
    at: 0.86,
    title: ['Your team gets the fix,', 'not just the alarm.'],
    body: 'Each warning says what to patch, what to check and which attacker technique to look for.',
  },
]
