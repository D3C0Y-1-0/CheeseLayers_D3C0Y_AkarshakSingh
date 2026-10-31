# Plan: IP geolocation for indicators (Member 2) — NOT STARTED

Goal: for every malicious IP we hold, show **country + network owner (ASN)** on the dashboard, offline.
Status: planned 31 Oct 2026, build later.

## What it is (and isn't)
- IP geolocation = where the **server/network** is registered, not where the attacker sits.
  Attackers use rented cloud servers, VPNs, Tor exits and hacked machines. Label it in the UI as
  "IP registered in", never "attack from".
- Accuracy: country ~95%+, city often wrong. Network owner (ASN, e.g. "AS14061 DigitalOcean") is the most
  useful field: hosting provider vs home broadband says a lot.
- Data honesty: IP not found / private / documentation range (e.g. `198.51.100.x` in `data/events.json`)
  → `geo: null` (unknown). Never guess a location.

## What we have
| Source | Type | Count (31 Oct) |
|---|---|---|
| threatfox | ip | 2,667 |
| tor_exit | ip | 1,746 |
| otx | ip | 357 |
| feodotracker | ip | 5 |
| spamhaus_drop | cidr | 1,755 (look up the network address) |

## Data source
- **DB-IP Lite** (country + city + ASN), `.mmdb` format, free, no API key, licence CC-BY 4.0
  (must show "IP geolocation by DB-IP" on the dashboard). Monthly updates: https://db-ip.com/db/lite.php
- Download once into `backend/data/geo/` (gitignored, ~100 MB). Works in `DEMO_MODE` (no network).
- Rejected: ip-api.com / ipinfo online APIs (break the offline demo, rate limited); MaxMind GeoLite2
  (needs account + licence key; fine as a swap later, same `.mmdb` format).
- New dependency: `maxminddb` (reads `.mmdb`). Nothing else.

## Steps
1. **Contract first** (`data/contracts.json` → v1.3): add optional `geo` object to `ioc`:
   `{country, country_code, city, asn, asn_org, geo_source, accuracy}`, whole object nullable.
   Tell the team before changing code.
2. `backend/collectors/geo.py`: `lookup(ip) -> dict | None` using `maxminddb`; skip private/reserved IPs
   via stdlib `ipaddress` (`is_global` false → None). CIDR → look up network address.
   Missing `.mmdb` file → every lookup None + one warning log (never crash the pipeline).
3. Enrich in `run_all` after IOC collection (IOC types `ip`, `cidr` only). Store in `iocs.geo` JSON column
   (`init_db` drops/rebuilds only the stale `iocs` table; rebuild with `--from-raw`).
4. Endpoints (feeds.py / insights.py):
   - `GET /api/geo/ip/{ip}` — on-demand lookup for any IP (Member 3/4 use it for alert/event IPs).
     Invalid IP → 422; not found → `{"ip": ..., "geo": null}`.
   - `GET /api/insights/ioc-geo` — counts by country, top 10 ASNs, % on hosting providers,
     `unknown` count, `geo_source`, attribution string. For a world map.
   - `GET /api/threats/{id}` / IOC listings include `geo` per IP IOC.
5. Docs: `docs/API.md` section + `docs/samples/geo_ip.json`, `docs/samples/ioc_geo.json`.
6. Tests: known public IP → country set; private/doc IP (`10.0.0.1`, `198.51.100.200`) → null;
   missing db file → null, no crash; endpoint 422 on garbage input.

## Not mine (hand off)
- Showing location on alerts/incidents → Member 3 (call `/api/geo/ip/{ip}` or reuse `collectors.geo.lookup`).
- Location of IPs in Shadow Watch events → Member 4.
- World map UI → Member 1 (from `ioc_geo.json` sample).

## Pitch line
"Most malicious infrastructure hitting India sits on foreign cloud hosting": back it with the
hosting-provider % from `/api/insights/ioc-geo`, not a guess.
