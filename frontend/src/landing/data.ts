import scoring from '../fixtures/scoring_config.json'
// Everything on the landing page that claims a fact lives here, so it is easy to audit.
// Counts were read from backend/data/cache at commit b139a76. Re-read them after a fresh collector run.

export const PRODUCT = 'Vectra' // Change it here and in index.html.

export const SOURCES = [
  { name: 'NVD', gives: 'Vulnerability text, severity and affected products', count: 17324, unit: 'CVEs' },
  { name: 'CISA KEV', gives: 'Flaws confirmed as exploited in real attacks', count: 1766, unit: 'CVEs' },
  { name: 'FIRST EPSS', gives: 'Probability a flaw is exploited in the next 30 days', count: 18340, unit: 'scores' },
  { name: 'CERT-In', gives: 'Advisories written for Indian organisations', count: 40, unit: 'advisories' },
  { name: 'abuse.ch', gives: 'Malicious URLs, domains, IPs and file hashes', count: 17657, unit: 'indicators' },
  { name: 'AlienVault OTX', gives: 'Community reports of active campaigns', count: 5941, unit: 'indicators' },
  { name: 'Spamhaus, Tor, OpenPhish', gives: 'Blocklisted ranges, Tor exits and phishing links', count: 3802, unit: 'indicators' },
  { name: 'MITRE ATT&CK', gives: 'The catalogue of known attacker techniques', count: 706, unit: 'techniques' },
]

// Scenario A from the team's data/demo_cves.json. The CVE facts are real. The asset is simulated.
export const MATCH = {
  cve: 'CVE-2024-21762',
  product: 'FortiOS 7.2.6',
  fixed: '7.2.7',
  asset: 'PWR-FW-01',
}

export type ScoreInput = {
  cvss: number
  inKev: boolean
  epss: number
  criticality: number
  internetFacing: boolean
  confidence: number
}

// Educational projection of the central vulnerability score, with no local telemetry or public-exploit bonus.
// Weights are exported from app.scoring.CONFIG; real incidents always use backend scores.
export function riskFactors(s: ScoreInput) {
  const exploit = s.inKev ? 1 : s.epss
  const config = scoring.vulnerability
  const exposure = config.exposure[s.internetFacing ? 'internet_facing' : 'internal']
  const factors = { severity: s.cvss / 10, exploitation: exploit ** config.epss_exponent, criticality: s.criticality / 5, exposure }
  const score = Math.min(100, Object.entries(factors).reduce((sum, [key, value]) =>
    sum + Math.round(1000 * config.weights[key as keyof typeof config.weights] * value) / 10, 0))
  return { exploit, exposure, score }
}

export function riskLevel(score: number, confidence = 1) {
  const t = scoring.priority_thresholds
  if (score >= t.critical) return confidence === 1 ? 'Critical' : 'High'
  if (score >= t.high) return 'High'
  if (score >= t.medium) return 'Medium'
  return 'Low'
}

// PWR-FW-01: CVSS 9.8, in KEV, criticality 5, internet-facing, exact version.
export const WALKTHROUGH: ScoreInput = {
  cvss: 9.8,
  inKev: true,
  epss: 0.84589,
  criticality: 5,
  internetFacing: true,
  confidence: 1,
}
