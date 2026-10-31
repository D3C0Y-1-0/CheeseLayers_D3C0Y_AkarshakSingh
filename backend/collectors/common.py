"""Shared plumbing for every collector: HTTP with retry/backoff/rate limits, raw + cache files, logging."""
import os

from dotenv import dotenv_values, find_dotenv

# Find .env by walking up from the working directory (it lives at the repo root, not in backend/).
# A non-empty shell variable wins (so `DEMO_MODE=true python -m ...` works); an empty one is filled from .env.
for _k, _v in dotenv_values(find_dotenv(usecwd=True)).items():
    if _v and not os.environ.get(_k):
        os.environ[_k] = _v

import json
import logging
import time
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

import httpx
from pydantic_core import to_jsonable_python
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from .schema import IOC, ThreatItem

BASE = Path(__file__).resolve().parent.parent  # backend/
RAW = BASE / "data" / "raw"
CACHE = BASE / "data" / "cache"

# DEMO_MODE: no network at all, everything comes from data/cache (a flaky venue wifi can't kill the demo).
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("1", "true", "yes")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("collectors")
logging.getLogger("httpx").setLevel(logging.WARNING)  # httpx logs full URLs, which can include API keys


class Skipped(Exception):
    """Raise when a source can't run by design (e.g. no API key) — reported as 'skipped', not 'failed'."""


def env(name: str) -> str | None:
    return os.getenv(name) or None


# Honest User-Agent so feed operators can see who we are. TLS certificates are always verified:
# turning verification off would let anyone on the network feed us fake threat intel.
client = httpx.Client(
    timeout=httpx.Timeout(30, read=180),
    follow_redirects=True,
    headers={"User-Agent": "D3COY-EWS/0.1 (hackathon threat-intel collector)"},
)

_last_call: dict[str, float] = {}


def _throttle(url: str, min_interval: float) -> None:
    # ponytail: per-host spacing in a single process; use a token bucket if collectors ever run in parallel.
    host = urlparse(url).netloc
    wait = _last_call.get(host, 0) + min_interval - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    _last_call[host] = time.monotonic()


def _retryable(e: BaseException) -> bool:
    # Retry network blips, rate limiting (429) and server errors (5xx). A 4xx like 401/404 won't fix itself.
    if isinstance(e, httpx.HTTPStatusError):
        return e.response.status_code == 429 or e.response.status_code >= 500
    return isinstance(e, httpx.TransportError)


@retry(retry=retry_if_exception(_retryable), stop=stop_after_attempt(4),
       wait=wait_exponential(multiplier=2, min=2, max=60), reraise=True)
def request(method: str, url: str, *, min_interval: float = 1.0, **kw) -> httpx.Response:
    if DEMO_MODE:
        raise RuntimeError("network disabled in DEMO_MODE")
    _throttle(url, min_interval)
    r = client.request(method, url, **kw)
    r.raise_for_status()
    return r


def github_headers() -> dict:
    # Optional token lifts GitHub's API limit from 60 to 5000 requests/hour.
    token = env("GITHUB_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else {}


def get(url: str, **kw) -> httpx.Response:
    return request("GET", url, **kw)


def _write(path: Path, text: str) -> None:
    # Write to a temp file then rename, so a crash mid-write never leaves a corrupt cache behind.
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def save_raw(source: str, payload, name: str = "latest") -> str:
    """Keep the untouched response under data/raw/<source>/ for debugging. Returns the path for raw_ref."""
    ext = "txt" if isinstance(payload, str) else "json"
    path = RAW / source / f"{name}.{ext}"
    _write(path, payload if isinstance(payload, str) else json.dumps(payload))
    return ref(path)


def ref(path: Path) -> str:
    return str(path.relative_to(BASE.parent))  # repo-relative, e.g. backend/data/raw/kev/latest.json


def raw_file(source: str, name: str) -> Path:
    """A saved raw payload, for collectors' from_raw() (offline rebuild of the cache from data/raw)."""
    path = RAW / source / name
    if not path.exists():
        raise Skipped(f"no raw file {ref(path)}")
    return path


def raw_pages(source: str) -> list[Path]:
    """Paged raw files (<prefix>_<n>.json) from the newest saved run of `source`, in page order.
    Older runs with another prefix (e.g. a different NVD start date) are ignored."""
    pages = [f for f in (RAW / source).glob("*_*.json") if f.stem.rsplit("_", 1)[1].isdigit()]
    if not pages:
        raise Skipped(f"no raw pages for {source}")
    prefix = max(pages, key=lambda f: f.stat().st_mtime).stem.rsplit("_", 1)[0]
    return sorted((f for f in pages if f.stem.rsplit("_", 1)[0] == prefix), key=lambda f: int(f.stem.rsplit("_", 1)[1]))


def mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)


def save_cache(source: str, items) -> Path:
    """Write normalised output (Pydantic models are fine) to data/cache/<source>.json."""
    path = CACHE / f"{source}.json"
    _write(path, json.dumps(to_jsonable_python(items), indent=1, ensure_ascii=False))
    return path


def cache_mtime(source: str) -> datetime | None:
    path = CACHE / f"{source}.json"
    return mtime(path) if path.exists() else None


def load_cache(source: str):
    path = CACHE / f"{source}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def ioc_batches(iocs: list[IOC], urls: dict[str, str], label: str) -> list[ThreatItem]:
    """One 'ioc_batch' ThreatItem per feed + malware family ("threatfox: 120 Cobalt Strike indicators"),
    and point each IOC at it so a log hit on the IOC can be traced back to a threat."""
    groups: dict[tuple[str, str], list[IOC]] = defaultdict(list)
    for i in iocs:
        groups[(i.source, i.malware_family or "unknown")].append(i)
    items = []
    for (src, family), group in groups.items():
        tid = f"{src}:{family.lower().replace(' ', '_')}"
        for i in group:
            i.related_threat_id = tid
        items.append(ThreatItem(
            threat_id=tid, source=src, type="ioc_batch", title=f"{src}: {len(group)} {family} indicators",
            description=f"{len(group)} indicators of compromise linked to {family}, reported by {label} {src}.",
            published_at=max((i.first_seen for i in group if i.first_seen), default=None),
            references=[urls[src]] if src in urls else [], tags=[label, src, family],
            raw_refs=sorted({i.raw_ref for i in group if i.raw_ref}),
        ))
    return items
