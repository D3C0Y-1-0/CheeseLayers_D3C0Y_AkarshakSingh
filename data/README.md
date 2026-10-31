# NETRA-X shared fixtures (`data/`)

**Everything in this folder is SYNTHETIC demo data**, except the real CVE facts copied into
`demo_cves.json`. No real organisation, host or IP is described. Organisation names start with "Sim",
and internet-facing IPs use the RFC 5737 documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`).
Every record has `is_simulated: true`. Shared by all 4 members, so **don't rename fields; change
`contracts.json` first and tell the team.**

```bash
.venv/bin/python data/generate.py   # rebuild everything below except contracts.json (deterministic)
.venv/bin/python data/validate.py   # check every file against contracts.json; exit 1 on error
```
Edit fixture data in `generate.py`, not in the JSON files: a re-run overwrites them.

| File | What it is | Used by |
|---|---|---|
| `contracts.json` | Source of truth for field names, types and enums (threat, asset, event, alert, window), plus the rule *null = unknown/unverified, never 0/false*. Hand-written. | **All** |
| `assets.json` | 40 assets across power, banking, govt, health, telecom and water. Software uses real NVD CPE vendor/product names. | M3 (matching, scoring), M1 (Assets page) |
| `demo_cves.json` | 3 **real** CISA-KEV CVEs for Scenario A, with exact NVD version ranges, which assets must match and which patched twins must not. Built from `backend/data/raw/nvd_kev` + cache. | M3 (matcher tests), M2 (`inject-cve` allowlist) |
| `threats_synthetic.json` | `DEMO-VULN-001..003`: fictional vulns on a fictional vendor (`netrax_demo_vendor`). `cve_id` is null and titles are `[SIMULATED]`. | M2 (ingest, `is_simulated=true`), M3 |
| `events.json` | 8 sensor events: Scenario B (3), Scenario C (3), incomplete evidence (2). | M4 (Shadow Watch, agent), M3 (correlation) |
| `windows.csv` | 500 one-minute behaviour windows. 350 train (normal only) + 150 test (8 suspicious = 5.3%, plus 4 benign maintenance spikes). Seed 1031. | M4 (Isolation Forest) |
| `generate.py`, `validate.py` | Builder and validator. | All |

## Demo scenarios in this data
**A. Known CVE → matched asset → alert** (real KEV CVEs; the twins prove we don't over-match)

| CVE | Vulnerable (inside NVD range) | Patched twin (no KEV match at all) |
|---|---|---|
| CVE-2024-21762 FortiOS SSL-VPN RCE | PWR-FW-01 (7.2.6), BNK-FW-01 (7.0.13) | PWR-FW-02 (7.4.11), BNK-FW-02 (7.6.6) |
| CVE-2024-4577 PHP-CGI command injection | GOV-WEB-01 (8.1.28, Windows) | GOV-WEB-02 (8.2.35) |
| CVE-2023-22515 Confluence access control | TEL-WIKI-01 (8.5.1) | TEL-WIKI-02 (9.2.26) |

The vulnerable assets also match a few *other* real KEV CVEs (FortiOS 7.2.6 genuinely has 6). That
is accurate, not a bug. Every other asset matches **zero** cached KEV CVEs (checked by `validate.py`).
CVE-2024-4577 only bites PHP on Windows in CGI mode, which NVD's range can't express. It's a good
`limitations[]` example.

Synthetic: DEMO-VULN-001 → PWR-HMI-01 (confirmed), DEMO-VULN-002 → BNK-CBS-01 (confirmed),
DEMO-VULN-003 → HLT-PACS-01 (version unknown and CVSS null → `requires_manual_review`).

**B. No CVE, suspicious behaviour:** HLT-WEB-01. A path-traversal HTTP request, then php-fpm spawns `/bin/sh`, then a new outbound connection to 203.0.113.250:4444. All within 4 minutes.

**C. Benign spike:** BNK-NET-01. An approved maintenance window CHG-2026-1031-07, a 7x traffic spike from the internal load tester, and `apt-get upgrade`. This must **not** escalate.

**Incomplete evidence:** EVT-0007 has `client_ip: null`. EVT-0008 has `asset_id: null` and `dest_ip: null`. Flag these as unverified; don't guess.

## Known simplifications
- OS is plain text in `os`, not a CPE in `software`. OS CPEs (Ubuntu 24.04, Windows with no build) match dozens of kernel KEV CVEs on every host and would bury Scenario A. Add OS CPEs only if the matcher can handle that volume.
- `validate.py`'s version check is fixture QA only (a simple dotted-version compare). The real matcher is Member 3's.
- There is no alert fixture. Alerts are produced at runtime and must follow `contracts.json` → `alert`.
