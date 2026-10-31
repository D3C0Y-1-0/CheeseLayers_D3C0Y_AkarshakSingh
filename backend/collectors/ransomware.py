"""ransomware.live: victims posted on ransomware gangs' leak sites ("pay or we publish your data").

A spike of victims in one sector/country = an active campaign worth warning about. We keep the
latest global victims plus recent Indian victims (C-DAC cares about India first).
Each victim -> ThreatItem type "campaign", tags: group:<gang>, sector:<sector>, country:<ISO code>, india.
"""
import hashlib
from datetime import datetime, timedelta, timezone

from .common import get, log, save_raw
from .schema import ThreatItem

SOURCE = "ransomware"
API = "https://api.ransomware.live/v2"
INDIA_DAYS = 90
# The per-country endpoint allows 1 call/minute; we make exactly one per run.


def _item(v: dict) -> ThreatItem:
    # The two endpoints name fields differently: recentvictims (group, victim) vs countryvictims (group_name, post_title).
    group = v.get("group") or v.get("group_name") or "unknown"
    victim = v.get("victim") or v.get("post_title") or "unknown"
    country = v.get("country") or ""
    sector = v.get("activity") or "Unknown"
    date = v.get("discovered") or v.get("published") or v.get("attackdate")
    tags = ["ransomware", f"group:{group}", f"sector:{sector}"] + ([f"country:{country}"] if country else []) + (["india"] if country == "IN" else [])
    return ThreatItem(
        id="ransomware:" + hashlib.sha1(f"{group}|{victim}".encode()).hexdigest()[:12],
        source=SOURCE, type="campaign", title=f"{group} ransomware claims {victim}" + (f" ({country})" if country else ""),
        description=v.get("description") or "", published_at=date,
        # Never link the leak site itself (.onion, criminal-run); link ransomware.live's page instead.
        url=v.get("url") or f"https://www.ransomware.live/group/{group.lower()}",
        tags=tags,
    )


def fetch() -> dict:
    recent = get(f"{API}/recentvictims").json()
    save_raw(SOURCE, recent, "recentvictims")
    india = []
    try:
        india = get(f"{API}/countryvictims/IN").json()
        save_raw(SOURCE, india, "india")
        if not isinstance(india, list):  # rate-limited: {"message": "1 per 1 minute"}
            raise RuntimeError(india)
    except Exception as e:
        log.warning("ransomware: India list failed (%s), global list only", e)
        india = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=INDIA_DAYS)
    india = [v for v in india if (v.get("discovered") or v.get("published") or "") >= cutoff.isoformat()]
    items = {i.id: i for i in map(_item, recent + india)}  # same victim in both lists -> one item
    return {"items": list(items.values())}
