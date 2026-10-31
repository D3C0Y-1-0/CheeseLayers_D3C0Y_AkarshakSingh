"""Shared plumbing for every collector: HTTP with retry/backoff/rate limits, raw + cache files, logging."""
import json
import logging
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from pydantic_core import to_jsonable_python
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

BASE = Path(__file__).resolve().parent.parent  # backend/
RAW = BASE / "data" / "raw"
CACHE = BASE / "data" / "cache"
load_dotenv(BASE / ".env")

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
    return str(path.relative_to(BASE))


def save_cache(source: str, items) -> Path:
    """Write normalised output (Pydantic models are fine) to data/cache/<source>.json."""
    path = CACHE / f"{source}.json"
    _write(path, json.dumps(to_jsonable_python(items), indent=1, ensure_ascii=False))
    return path


def load_cache(source: str):
    path = CACHE / f"{source}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
