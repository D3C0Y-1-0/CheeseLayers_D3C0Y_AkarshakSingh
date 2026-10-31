"""Pre-generate and cache grounded LLM reports, so the offline demo shows "LLM-cached" text.

    backend/.venv/bin/python scripts/pregenerate_ai.py            # needs LLM_ALLOW_CLOUD=true + LLM_API_KEY in .env
    backend/.venv/bin/python scripts/pregenerate_ai.py --dry-run  # no LLM calls: lists what is cached / missing

Runs the demo in-process on a THROW-AWAY copy of the database (your real DB and alerts are untouched):
threat summaries for every demo CVE (data/demo_cves.json) and DEMO-VULN fixture, then every demo scenario
(inject each CVE + each behaviour scenario) and, for every resulting incident, the investigation report and
the CERT-In draft. Idempotent: anything already in backend/data/cache/ai_reports/ is served from cache, never
regenerated. Only validated LLM output is cached (rejected output falls back to the template and is not stored).
"""
import argparse
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
SCENARIOS = ("no_cve_suspicious_chain", "benign_maintenance", "missing_telemetry")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true", help="no LLM calls; report cache hits/misses")
    ap.add_argument("--lang", default="en", choices=["en", "hi"], help="also needs the cloud LLM for hi")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="vectra-pregen-"))
    for name in ("vectra.db", "netrax.db"):  # reuse a loaded DB if there is one (fast), else load from cache
        if (BACKEND / "data" / name).exists():
            shutil.copy(BACKEND / "data" / name, tmp / "pregen.db")
            break
    os.environ.update(DEMO_MODE="true", PYTHONUTF8="1", VECTRA_DB_URL=f"sqlite:///{tmp / 'pregen.db'}")
    if args.dry_run:
        os.environ["LLM_ALLOW_CLOUD"] = "false"
    sys.path.insert(0, str(BACKEND))
    os.chdir(BACKEND)

    from fastapi.testclient import TestClient
    from ai import grounded
    from app.main import app

    status = grounded.llm_status()
    if not args.dry_run and not status["cloud_enabled"]:
        print(f"Cloud LLM not enabled ({status['reason']}). Set LLM_PROVIDER=groq, LLM_MODEL, LLM_API_KEY and "
              "LLM_ALLOW_CLOUD=true in .env, or use --dry-run.")
        return 2

    seen: list[tuple[str, bool]] = []
    real_get = grounded.cache_get
    grounded.cache_get = lambda key: (lambda hit: (seen.append((key, hit is not None)), hit)[1])(real_get(key))

    rows = []
    with TestClient(app) as c:
        def run(label, method, path):
            before = len(seen)
            r = c.request(method, path)
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            hits = seen[before:]
            rows.append({"item": label, "status": r.status_code, "generated_by": body.get("generated_by"),
                         "fallback_reason": body.get("fallback_reason"),
                         "cache": "hit" if hits and all(h for _, h in hits) else "miss" if hits else "-",
                         "keys": [k[:12] for k, _ in hits]})
            return body

        demo = [t["threat_id"] for t in json.loads((ROOT / "data" / "demo_cves.json").read_text())]
        synth = [t["threat_id"] for t in json.loads((ROOT / "data" / "threats_synthetic.json").read_text())]
        q = f"?lang={args.lang}"
        for tid in demo + synth:
            run(f"threat summary {tid}", "POST", f"/api/threats/{tid}/summary{q}")
        c.post("/api/demo/reset-alerts")
        alert_ids = []
        for tid in demo + synth:
            alert_ids += c.post("/api/demo/inject-cve", json={"fixture_id": tid}).json().get("alert_ids") or []
        for sc in SCENARIOS:
            alert_ids += c.post("/api/demo/inject-behaviour", json={"scenario": sc}).json().get("alert_ids") or []
        alert_ids = sorted(set(alert_ids) | {a["alert_id"] for a in c.get("/api/alerts").json()["items"]})
        for aid in alert_ids:
            run(f"investigation {aid}", "POST", f"/api/alerts/{aid}/investigate{q}")

    w = max(len(r["item"]) for r in rows)
    for r in rows:
        print(f"{r['item']:<{w}}  {r['status']}  {str(r['generated_by']):<11} cache={r['cache']:<4} "
              f"{','.join(r['keys'])} {r['fallback_reason'] or ''}")
    print("\nby generated_by:", dict(Counter(r["generated_by"] for r in rows)),
          "| cache:", dict(Counter(r["cache"] for r in rows)), "| llm:", status)
    if args.dry_run:
        print(f"dry run: {sum(r['cache'] == 'miss' for r in rows)} item(s) would call the LLM; nothing written.")
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if all(r["status"] == 200 for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
