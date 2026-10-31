"""Emerging campaigns: groups of related threats (PS objective 2, "relationships between threats").

Scope: threats published in the last `window_days` of the DATA (anchored to the newest published_at, so offline
caches give the same answer every day) plus every KEV entry, OTX pulse, CERT-In advisory and ransomware record.
Plain NVD CVEs only count if they show activity (KEV / public exploit / EPSS >= nvd_min_epss) or are named by
another in-scope item: thousands of unexploited CVEs with boilerplate text are a vulnerability class, not a campaign.

Two threats are LINKED when they share: a CVE · an IOC value · an ATT&CK technique · a vendor+product · or their
title+description TF-IDF cosine similarity >= tfidf_threshold. A shared key held by more than max_key_members
threats (e.g. T1190, "microsoft windows") is too generic to mean "same campaign" and is skipped (reported in
`meta.skipped_generic_keys`). Campaigns = connected components with >= min_size members. Deterministic.
"""
import hashlib
import json
import logging
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .database import get_db

log = logging.getLogger("vectra.campaigns")
import os  # noqa: E402

CACHE = Path(os.getenv("CAMPAIGNS_CACHE", Path(__file__).resolve().parent.parent / "data" / "cache" / "campaigns.json"))
CONFIG = {
    "window_days": 30,
    "tfidf_threshold": 0.6,  # cosine of TF-IDF(title + description); 0.6 = clearly the same story
    "tfidf_max_df": 0.05,  # words in >5% (min 10) of in-scope texts are boilerplate ("contains a vulnerability that")
    "max_campaign_size": 50,  # links that would grow a group beyond this are not applied (no mega-blobs)
    "min_size": 3,
    "max_key_members": 25,  # shared keys above this are generic, not evidence of one campaign
    "max_technique_members": 8,  # ATT&CK techniques are reused by many actors: weak evidence, tighter cap
    "nvd_min_epss": 0.1,
    "emerging_min_new": 3,  # is_emerging: >= this many members in the last 7 days...
    "emerging_growth": 2.0,  # ...and at least this multiple of the previous 7 days (prev 0 counts as 1)
    "scope_sources": ["kev", "otx", "certin", "ransomware"],
}
KIND_ORDER = {"cve": 0, "ioc": 1, "product": 2, "technique": 3, "text_similarity": 4}
# Feed wording that says nothing about WHICH campaign (source names, record-type words).
BOILERPLATE = {"threatfox", "urlhaus", "malwarebazaar", "indicators", "ioc", "iocs", "ransomware", "claims",
               "vulnerability", "vulnerabilities", "cve", "cert", "advisory", "pulse", "otx", "unknown"}
_LOCK = threading.Lock()


def _scope(db: Session):
    from .models import Threat
    newest = db.scalar(select(Threat.published_at).order_by(Threat.published_at.desc()).limit(1))
    as_of = newest or datetime.now(timezone.utc)
    since = as_of - timedelta(days=CONFIG["window_days"])
    rows = list(db.scalars(select(Threat).where(or_(Threat.published_at >= since,
                                                    Threat.source.in_(CONFIG["scope_sources"]),
                                                    Threat.kev_listed.is_(True)))))
    named = {c for r in rows if r.source != "nvd" for c in (r.cve_ids or [])}
    keep = [r for r in rows if r.source != "nvd" or r.kev_listed or r.public_exploit
            or (r.epss or 0) >= CONFIG["nvd_min_epss"] or r.threat_id in named]
    return sorted(keep, key=lambda r: r.threat_id), as_of


def _fingerprint(rows, as_of) -> str:
    h = hashlib.sha256(json.dumps(CONFIG, sort_keys=True).encode())
    h.update(str(as_of).encode())
    for r in rows:
        h.update(f"{r.threat_id}|{r.retrieved_at}|{r.kev_listed}|{r.epss}|{len(r.cve_ids or [])}\n".encode())
    return h.hexdigest()


class _DSU:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, i):
        while self.p[i] != i:
            self.p[i] = self.p[self.p[i]]
            i = self.p[i]
        return i

    def union(self, a, b):
        a, b = self.find(a), self.find(b)
        if a != b:
            self.p[max(a, b)] = min(a, b)


def link_keys(row, iocs: dict[str, set]) -> list[tuple[str, str]]:
    """(kind, key) pairs this threat can share with others."""
    keys = [("cve", c) for c in sorted(set(row.cve_ids or []) | ({row.cve_id} if row.cve_id else set()))]
    keys += [("ioc", v) for v in sorted(iocs.get(row.threat_id, ()))]
    keys += [("technique", t) for t in sorted(set(row.attack_techniques or []))]
    keys += [("product", p) for p in sorted({f"{c['vendor']} {c['product']}" for c in row.affected_configurations or []
                                             if c.get("vendor") and c.get("product")})]
    return keys


def build(db: Session) -> dict:
    """Compute every campaign from the DB (pure function of the data + CONFIG)."""
    from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
    from sklearn.metrics.pairwise import linear_kernel

    from .asset_store import get_asset_store
    from .correlator import threat_from_row
    from .matcher import exposed, match_threat
    from .models import IOCRow

    rows, as_of = _scope(db)
    ids = {r.threat_id: i for i, r in enumerate(rows)}
    iocs: dict[str, set] = defaultdict(set)
    for tid, value in db.execute(select(IOCRow.related_threat_id, IOCRow.value).where(IOCRow.related_threat_id.in_(ids))):
        iocs[tid].add(value)
    holders: dict[tuple, list[int]] = defaultdict(list)
    for i, r in enumerate(rows):
        for k in link_keys(r, iocs):
            holders[k].append(i)
    cap = lambda k: CONFIG["max_technique_members"] if k[0] == "technique" else CONFIG["max_key_members"]  # noqa: E731
    skipped = sorted(f"{k[0]}:{k[1]} ({len(v)})" for k, v in holders.items() if len(v) > cap(k))
    shared = {k: v for k, v in holders.items() if 2 <= len(v) <= cap(k)}
    # Candidate links, strongest evidence first: shared CVE > IOC > product > technique > text (by similarity).
    edges = [(KIND_ORDER[k[0]], 0.0, m[0], j, k) for k, m in sorted(shared.items()) for j in m[1:]]
    text_pairs, X, terms = [], None, []
    if len(rows) > 1:
        docs = [f"{r.title} {r.description or ''}" for r in rows]
        tfidf = TfidfVectorizer(stop_words=list(ENGLISH_STOP_WORDS | BOILERPLATE), min_df=2,
                                max_df=max(int(CONFIG["tfidf_max_df"] * len(rows)), 10), sublinear_tf=True,
                                token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_]{2,}\b")  # words, not counts/versions
        try:
            X = tfidf.fit_transform(docs)
            terms = tfidf.get_feature_names_out()
        except ValueError:  # empty vocabulary (tiny test sets)
            X = None
        if X is not None:
            for start in range(0, len(rows), 1000):  # bounded memory: 1000 x n dense block
                sims = linear_kernel(X[start:start + 1000], X)
                for a, b in zip(*(sims >= CONFIG["tfidf_threshold"]).nonzero()):
                    a += start
                    if a < b:
                        sim = round(float(sims[a - start, b]), 3)
                        text_pairs.append((a, b, sim))
                        edges.append((KIND_ORDER["text_similarity"], -sim, a, b, None))
    # Single-linkage with a size cap: a link that would grow a group past max_campaign_size is not applied, so
    # boilerplate similarity can't chain thousands of unrelated advisories into one "campaign".
    dsu, size, used = _DSU(len(rows)), [1] * len(rows), set()
    for _, _, a, b, key in sorted(edges, key=lambda e: e[:4]):
        ra, rb = dsu.find(a), dsu.find(b)
        if ra == rb:
            used.add((a, b, key))
            continue
        if size[ra] + size[rb] > CONFIG["max_campaign_size"]:
            continue
        dsu.union(ra, rb)
        size[dsu.find(ra)] = size[ra] + size[rb]
        used.add((a, b, key))
    text_pairs = [(a, b, s_) for a, b, s_ in text_pairs if (a, b, None) in used]
    groups = defaultdict(list)
    for i in range(len(rows)):
        groups[dsu.find(i)].append(i)
    store = get_asset_store()
    week, fortnight = as_of - timedelta(days=7), as_of - timedelta(days=14)
    out = []
    for members in groups.values():
        if len(members) < CONFIG["min_size"]:
            continue
        mset = set(members)
        reasons = []
        for (kind, key), holders_ in shared.items():
            n = len(mset.intersection(holders_))
            if n >= 2:
                reasons.append({"type": kind, "key": key, "count": n})
        sim_n = {i for a, b, _ in text_pairs if a in mset for i in (a, b)}
        if sim_n:
            reasons.append({"type": "text_similarity", "key": f"TF-IDF cosine >= {CONFIG['tfidf_threshold']}",
                            "count": len(sim_n)})
        reasons.sort(key=lambda x: (-x["count"], x["type"], x["key"]))
        for r_ in reasons:
            r_["text"] = (f"{r_['count']} share {r_['key']}" if r_["type"] != "text_similarity"
                          else f"{r_['count']} have near-identical descriptions ({r_['key']})")
        mrows = [rows[i] for i in sorted(members, key=lambda i: rows[i].threat_id)]
        dates = sorted(r.published_at for r in mrows if r.published_at)
        last7 = sum(1 for d in dates if d > week)
        prev7 = sum(1 for d in dates if fortnight < d <= week)
        emerging = last7 >= CONFIG["emerging_min_new"] and last7 >= CONFIG["emerging_growth"] * max(prev7, 1)
        affected, kev = set(), False
        for r in mrows:
            kev = kev or bool(r.kev_listed)
            if r.affected_configurations:
                affected |= {m.asset_id for m in exposed(match_threat(threat_from_row(r), store.all()))}
        # Title: the products most members share (even generic ones), else the group's most distinctive words.
        prod = Counter(p for r in mrows for p in {f"{c['vendor']} {c['product']}" for c in r.affected_configurations or []
                                                  if c.get("vendor") and c.get("product")})
        title = [p for p, n in prod.most_common(2) if n >= 2]
        if not title and X is not None:
            weights = X[members].sum(axis=0).A1
            title = [terms[i] for i in weights.argsort()[::-1][:3] if weights[i] > 0]
        anchor = min(mrows, key=lambda r: (r.published_at or as_of, r.threat_id))
        has_iocs = any(iocs.get(r.threat_id) for r in mrows) or any(r.type == "ioc_batch" for r in mrows)
        if affected and kev:
            action = f"Patch the {len(affected)} exposed asset(s) first: the campaign includes KEV-listed vulnerabilities"
        elif affected:
            action = f"Verify and remediate the {len(affected)} asset(s) that match campaign vulnerabilities"
        elif has_iocs:
            action = "Block and hunt for the campaign's indicators in firewall/proxy/DNS logs"
        else:
            action = "Monitor: no asset in our inventory matches this campaign"
        out.append({
            "campaign_id": "CMP-" + hashlib.sha1(anchor.threat_id.encode()).hexdigest()[:8].upper(),
            "title": " · ".join(title) or anchor.title[:80],
            "size": len(mrows), "threat_ids": [r.threat_id for r in mrows],
            "sources": dict(sorted(Counter(r.source for r in mrows).items())),
            "link_reasons": reasons[:8],
            "first_seen": dates[0].isoformat() if dates else None, "last_seen": dates[-1].isoformat() if dates else None,
            "growth_7d": {"last_7d": last7, "prev_7d": prev7,
                          "ratio": round(last7 / prev7, 2) if prev7 else None},
            "is_emerging": emerging, "kev_listed_members": sum(1 for r in mrows if r.kev_listed),
            "affected_asset_ids": sorted(affected), "affected_asset_count": len(affected),
            "top_recommended_action": action,
            "is_simulated": all(r.is_simulated for r in mrows),
        })
    out.sort(key=lambda c: (not c["is_emerging"], -c["affected_asset_count"], -c["growth_7d"]["last_7d"],
                            -c["size"], c["campaign_id"]))
    return {"as_of": as_of.isoformat(), "fingerprint": _fingerprint(rows, as_of), "config": CONFIG,
            "meta": {"threats_in_scope": len(rows), "links_by_type": dict(sorted(Counter(
                k[0] for k in shared).items())) | {"text_similarity": len(text_pairs)},
                     "skipped_generic_keys": skipped[:50], "skipped_generic_keys_total": len(skipped),
                     "method": __doc__.strip().split("\n\n")[1].replace("\n", " ")},
            "campaigns": out}


def get(db: Session, refresh: bool = False) -> dict:
    """Cached result; recomputed (and the cache file rewritten) only when the in-scope data changed."""
    with _LOCK:
        rows, as_of = _scope(db)
        fp = _fingerprint(rows, as_of)
        if not refresh and CACHE.exists():
            try:
                cached = json.loads(CACHE.read_text(encoding="utf-8"))
                if cached.get("fingerprint") == fp:
                    return cached
            except ValueError:
                pass
        result = build(db)
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE.with_suffix(".tmp")
        tmp.write_text(json.dumps(result, indent=1, default=str), encoding="utf-8")
        tmp.replace(CACHE)
        log.info("campaigns recomputed: %d campaigns from %d threats", len(result["campaigns"]), len(rows))
        return result


def refresh_in_background(session_factory) -> threading.Thread:
    """At startup / after ingest: warm the cache without blocking the API."""
    def run():
        try:
            with session_factory() as db:
                get(db)
        except Exception:
            log.exception("campaign precompute failed")
    t = threading.Thread(target=run, name="campaigns", daemon=True)
    t.start()
    return t


def campaign_ids_for(db: Session, threat_id: str) -> list[str]:
    """For threat detail: campaigns containing this threat (from the cache only; never blocks on a rebuild)."""
    try:
        data = json.loads(CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [c["campaign_id"] for c in data.get("campaigns", []) if threat_id in c["threat_ids"]]


router = APIRouter(tags=["campaigns"])


@router.get("/api/campaigns")
def list_campaigns(emerging: bool | None = Query(None, description="true = emerging only"),
                   limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)) -> dict:
    """Groups of related threats, emerging first. Each lists WHY its members were grouped (link_reasons)."""
    data = get(db)
    items = [c for c in data["campaigns"] if emerging is None or c["is_emerging"] == emerging]
    return {"as_of": data["as_of"], "config": data["config"], "meta": data["meta"], "total": len(items),
            "emerging_total": sum(c["is_emerging"] for c in data["campaigns"]), "items": items[:limit]}


@router.get("/api/campaigns/{campaign_id}")
def campaign_detail(campaign_id: str, db: Session = Depends(get_db)) -> dict:
    """One campaign + its member threats, each with the shared keys that tie it to the group."""
    from .models import Threat
    data = get(db)
    c = next((x for x in data["campaigns"] if x["campaign_id"] == campaign_id), None)
    if c is None:
        raise HTTPException(404, f"campaign {campaign_id} not found")
    reason_keys = {(r["type"], r["key"]) for r in c["link_reasons"]}
    members = []
    for tid in c["threat_ids"]:
        t = db.get(Threat, tid)
        if t is None:
            continue
        members.append({"threat_id": tid, "title": t.title, "source": t.source, "type": t.type,
                        "severity": t.severity, "cvss": t.cvss, "kev_listed": t.kev_listed,
                        "published_at": t.published_at.isoformat() if t.published_at else None,
                        "is_simulated": t.is_simulated,
                        "shared_keys": [f"{k}: {v}" for k, v in link_keys(t, {}) if (k, v) in reason_keys]})
    return c | {"as_of": data["as_of"], "members": members}
