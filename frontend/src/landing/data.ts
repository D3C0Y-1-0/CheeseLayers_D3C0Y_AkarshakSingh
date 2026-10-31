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

// Same formula as CLAUDE.md section 9. If Member 3 changes it, change this too.
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

// PWR-FW-01: CVSS 9.8, in KEV, criticality 5, internet-facing, exact version.
export const WALKTHROUGH: ScoreInput = {
  cvss: 9.8,
  inKev: true,
  epss: 0.84589,
  criticality: 5,
  internetFacing: true,
  confidence: 1,
}
