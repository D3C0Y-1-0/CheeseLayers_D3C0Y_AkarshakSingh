"""IP / URL reputation lists — things that should rarely talk to a government or bank network.

- Tor exit nodes: traffic from these is anonymised. Not malicious by itself, but brute-force and
  scanning often come through Tor, so a hit raises suspicion (low confidence).
- Spamhaus DROP: IP ranges hijacked or run by criminals. "Don't Route Or Peer" — block outright (high confidence).
- OpenPhish: live phishing URLs (credential-stealing login pages).
"""
import json

from .common import get, ioc_batches, log, save_raw
from .schema import IOC

SOURCE = "ip_reputation"
# check.torproject.org can be blocked or TLS-intercepted by corporate firewalls (seen: FortiGate re-signing
# its certificate). We never disable certificate checks; we fall back to a GitHub mirror of the same list.
TOR = ["https://check.torproject.org/torbulkexitlist",
       "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst"]
DROP = "https://www.spamhaus.org/drop/drop_v4.json"
OPENPHISH = "https://openphish.com/feed.txt"
URLS = {"tor_exit": "https://metrics.torproject.org/exonerator.html", "spamhaus_drop": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
        "openphish": "https://openphish.com/"}


def _tor() -> list[IOC]:
    for url in TOR:
        try:
            text = get(url).text
            break
        except Exception as e:
            log.warning("ip_reputation: tor list %s failed (%s), trying next", url, e)
    else:
        raise RuntimeError("all Tor exit list sources failed")
    save_raw(SOURCE, text, "tor")
    return [IOC(value=ip, ioc_type="ip", source="tor_exit", malware_family="tor-exit-node", confidence=30)
            for ip in sorted(set(text.split())) if not ip.startswith("#")]


def _drop() -> list[IOC]:
    text = get(DROP).text
    save_raw(SOURCE, text, "spamhaus_drop")
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [IOC(value=r["cidr"], ioc_type="cidr", source="spamhaus_drop", malware_family="hijacked-range", confidence=90)
            for r in rows if "cidr" in r]  # last line is a metadata record


def _openphish() -> list[IOC]:
    text = get(OPENPHISH).text
    save_raw(SOURCE, text, "openphish")
    return [IOC(value=u, ioc_type="url", source="openphish", malware_family="phishing", confidence=80)
            for u in sorted(set(text.split()))]


def fetch() -> dict:
    iocs: list[IOC] = []
    for feed in (_tor, _drop, _openphish):
        try:
            iocs += feed()
        except Exception as e:  # one list down shouldn't drop the others
            log.warning("ip_reputation: %s failed: %s", feed.__name__, e)
    if not iocs:
        raise RuntimeError("all reputation feeds failed")
    return {"items": ioc_batches(iocs, URLS, "reputation"), "iocs": iocs}
