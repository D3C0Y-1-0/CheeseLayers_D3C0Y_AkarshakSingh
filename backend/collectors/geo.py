"""IP geolocation from DB-IP Lite (offline .mmdb files in backend/data/geo/, CC-BY 4.0, https://db-ip.com).

What this is: where an IP address is REGISTERED (country/city of the network, and the network owner = ASN).
What it is not: where the attacker sits. Attack traffic mostly comes from rented cloud servers, VPNs, Tor exits and
hacked machines, so the UI says "IP registered in", never "attack from". Country is usually right; city often isn't.

Private, reserved and documentation addresses (10.x, 192.168.x, 198.51.100.x, ...) have no location -> None.
Missing database files -> every lookup is None with one warning (the pipeline never crashes on it).
"""
import ipaddress
import logging
from functools import lru_cache
from pathlib import Path

log = logging.getLogger("geo")
GEO_DIR = Path(__file__).resolve().parent.parent / "data" / "geo"
CITY, ASN = GEO_DIR / "dbip-city-lite.mmdb", GEO_DIR / "dbip-asn-lite.mmdb"
SOURCE = "dbip-lite"
ATTRIBUTION = "IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0"
# Network owners whose name says "rented servers/cloud". ponytail: name heuristic, swap for an ASN-type list if needed.
HOSTING_WORDS = ("amazon", "aws", "google", "microsoft", "azure", "digitalocean", "ovh", "hetzner", "linode", "akamai",
                 "cloudflare", "alibaba", "tencent", "contabo", "vultr", "choopa", "m247", "leaseweb", "oracle",
                 "scaleway", "hostinger", "ionos", "hosting", "host", "cloud", "server", "datacenter", "data center",
                 "vps", "colocation", "dedicated")


@lru_cache(maxsize=1)
def _readers():
    try:
        import maxminddb
        return maxminddb.open_database(str(CITY)), (maxminddb.open_database(str(ASN)) if ASN.exists() else None)
    except (ImportError, OSError, ValueError) as e:
        log.warning("IP geolocation unavailable (%s); download DB-IP Lite into %s", type(e).__name__, GEO_DIR)
        return None, None


def available() -> bool:
    return _readers()[0] is not None


def is_hosting(asn_org: str | None) -> bool | None:
    return None if not asn_org else any(w in asn_org.lower() for w in HOSTING_WORDS)


@lru_cache(maxsize=100_000)
def lookup(value: str) -> dict | None:
    """IP or CIDR -> {country, country_code, city, latitude, longitude, asn, asn_org, hosting, geo_source, accuracy}."""
    try:
        ip = ipaddress.ip_network(value.strip(), strict=False).network_address if "/" in value else ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not ip.is_global:  # private, loopback, documentation (TEST-NET), multicast...
        return None
    city_db, asn_db = _readers()
    if city_db is None:
        return None
    rec = city_db.get(str(ip)) or {}
    country = rec.get("country") or {}
    if not country:
        return None
    loc = rec.get("location") or {}
    a = (asn_db.get(str(ip)) if asn_db else None) or {}
    org = a.get("autonomous_system_organization")
    return {"country": (country.get("names") or {}).get("en"), "country_code": country.get("iso_code"),
            "city": ((rec.get("city") or {}).get("names") or {}).get("en"),
            "latitude": loc.get("latitude"), "longitude": loc.get("longitude"),
            "asn": a.get("autonomous_system_number"), "asn_org": org, "hosting": is_hosting(org),
            "geo_source": SOURCE, "accuracy": "country-level (city approximate)"}


if __name__ == "__main__":  # self-check
    assert lookup("10.0.0.1") is None and lookup("198.51.100.200") is None and lookup("not-an-ip") is None
    if available():
        g = lookup("8.8.8.8")
        assert g and g["country_code"] == "US" and g["asn"] == 15169, g
        assert lookup("8.8.8.0/24")["country_code"] == "US"
    print("geo ok", available())
