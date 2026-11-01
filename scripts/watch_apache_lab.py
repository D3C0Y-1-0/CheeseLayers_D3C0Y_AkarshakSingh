"""Independent collector: Docker Apache logs -> authenticated loopback Vectra API.

No findings are generated here; the API parses records and evaluates deterministic rules.
Initial capture starts now; restart uses its saved Docker timestamp checkpoint. Old records
at that timestamp may replay and are deduplicated by container/log hash.
"""
import argparse
import json
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT = ROOT / "logs/apache-collector-checkpoint.json"


def docker(*args):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, timeout=15).stdout


def collect(control, checkpoint):
    page = control.get("/lab")
    page.raise_for_status()
    control.headers["X-Vectra-Lab-Token"] = re.search(r"const token='([^']+)'", page.text).group(1)
    ids = docker("compose", "-f", str(ROOT / "lab/apache/compose.yaml"), "ps", "-q", "vulnerable", "patched").splitlines()
    for cid in ids:
        if cid not in checkpoint:
            response = control.post("/api/lab/apache/register", json={"container_id": cid})
            response.raise_for_status()
            checkpoint[cid] = datetime.now(timezone.utc).isoformat()
        lines = docker("logs", "--timestamps", "--since", checkpoint[cid], "--tail", "1000", cid).splitlines()
        if len(lines) >= 1000:
            print("Collector tail limit reached; source coverage may be incomplete", flush=True)
        if not lines:
            continue
        for begin in range(0, len(lines), 200):
            batch = lines[begin:begin + 200]
            response = control.post("/api/lab/apache/logs", json={"container_id": cid, "lines": batch})
            response.raise_for_status()
            result = response.json()
            with (ROOT / f"logs/apache-source-{cid[:12]}.jsonl").open("a", encoding="utf-8") as out:
                for line in batch:
                    out.write(json.dumps({"container_id": cid, "line": line}) + "\n")
            if result["accepted"] or result["rejected"]:
                print(json.dumps({"container": cid[:12], "accepted": len(result["accepted"]),
                    "duplicates": len(result["duplicates"]), "rejected": result["rejected"][:3]}), flush=True)
        stamp = lines[-1].partition(" ")[0]
        if stamp.endswith("Z"):
            checkpoint[cid] = stamp
    CHECKPOINT.parent.mkdir(exist_ok=True)
    CHECKPOINT.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    checkpoint = json.loads(CHECKPOINT.read_text(encoding="utf-8")) if CHECKPOINT.exists() else {}
    with httpx.Client(base_url="http://127.0.0.1:8000", trust_env=False, timeout=60) as control:
        while True:
            try:
                collect(control, checkpoint)
            except (httpx.HTTPError, subprocess.SubprocessError, OSError, ValueError) as exc:
                if args.once:
                    raise
                print(f"Collector retry after {type(exc).__name__}; source checkpoint retained", flush=True)
            if args.once:
                return
            time.sleep(1)


if __name__ == "__main__":
    main()
