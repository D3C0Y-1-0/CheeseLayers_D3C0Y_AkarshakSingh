"""IP geolocation (PLAN_ip_geolocation.md): lookups, honest nulls, endpoints."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from collectors import geo

needs_db = pytest.mark.skipif(not geo.available(), reason="DB-IP Lite not downloaded into backend/data/geo/")


@needs_db
def test_public_ip_and_cidr_located():
    g = geo.lookup("8.8.8.8")
    assert g["country_code"] == "US" and g["asn"] == 15169 and g["geo_source"] == "dbip-lite"
    assert geo.lookup("8.8.8.0/24")["country_code"] == "US"


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.5", "198.51.100.200", "203.0.113.77", "127.0.0.1", "garbage"])
def test_private_documentation_and_invalid_are_null(ip):
    assert geo.lookup(ip) is None  # no location is invented for addresses that have none


def test_missing_database_is_null_not_crash(monkeypatch):
    monkeypatch.setattr(geo, "_readers", lambda: (None, None))
    geo.lookup.cache_clear()
    try:
        assert geo.lookup("8.8.8.8") is None
    finally:
        geo.lookup.cache_clear()


def test_hosting_heuristic():
    assert geo.is_hosting("DigitalOcean, LLC") and geo.is_hosting("Amazon.com, Inc.")
    assert geo.is_hosting("Bharti Airtel Ltd.") is False and geo.is_hosting(None) is None


def test_endpoints():
    with TestClient(app) as c:
        assert c.get("/api/geo/ip/not-an-ip").status_code == 422
        doc = c.get("/api/geo/ip/198.51.100.200").json()
        assert doc["geo"] is None and "documentation" in doc["reason"]
        r = c.get("/api/insights/ioc-geo?points=20").json()
        assert r["total_ip_indicators"] > 0 and "not of the person" in r["note"] and len(r["points"]) <= 20
        if r["available"]:
            assert r["located"] > 0 and r["by_country"] and r["points"][0]["count"] >= r["points"][-1]["count"]
