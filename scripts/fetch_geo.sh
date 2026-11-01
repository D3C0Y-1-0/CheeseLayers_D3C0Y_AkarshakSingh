#!/usr/bin/env bash
# Download DB-IP Lite (free, CC BY 4.0: the dashboard shows "IP geolocation by DB-IP") into backend/data/geo/.
# Used by the Render build so the SOC globe and attacker locations work there. Optional: never fails the build;
# without the files every IP lookup is just null. Tries this month's release, then last month's.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)/backend/data/geo"
mkdir -p "$DIR"
this=$(date -u +%Y-%m)
prev=$(date -u -d "$this-01 -1 month" +%Y-%m 2>/dev/null || date -u -v1d -v-1m +%Y-%m)
for kind in city asn; do
  out="$DIR/dbip-$kind-lite.mmdb"
  [ -s "$out" ] && { echo "geo: $kind already present"; continue; }
  for m in "$this" "$prev"; do
    if curl -fsSL --retry 2 --max-time 300 "https://download.db-ip.com/free/dbip-$kind-lite-$m.mmdb.gz" | gunzip > "$out.tmp" 2>/dev/null \
       && [ -s "$out.tmp" ]; then
      mv "$out.tmp" "$out"; echo "geo: $kind $m ($(du -h "$out" | cut -f1))"; break
    fi
    rm -f "$out.tmp"
  done
  [ -s "$out" ] || echo "geo: $kind unavailable; map points and attacker locations fall back to null/ISC"
done
exit 0
