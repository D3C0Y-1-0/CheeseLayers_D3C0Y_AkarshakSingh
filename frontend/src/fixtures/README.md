Copied from `data/` at commit b139a76 (assets, demo_cves, threats_synthetic, events).
`threats_snapshot.json` and `overview_snapshot.json` are a small sample of `backend/data/cache/threat_items.json`.
`alerts_mock.json` is historical hand-built sample output. The connected dashboard reads Member 3's
`/api/alerts` and persisted incident/evidence endpoints. Do not treat the bundled fallback as engine output.
The dashboard only uses these when the backend is unreachable, and it says so on screen.
