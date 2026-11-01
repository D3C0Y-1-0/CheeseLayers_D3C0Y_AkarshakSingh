"""Collect a real, operator-declared ordinary traffic baseline, freeze it, then observe a burst.

Loopback lab only. Takes approximately three minutes; no feature vectors or findings are injected.
The burst result is reported as measured, not forced to be an outlier.
"""
import json
import random
import re
import time
from datetime import datetime
from pathlib import Path

import httpx


def wait_until(epoch):
    while (remaining := epoch - time.time()) > 0:
        time.sleep(min(remaining, 0.5))


def main():
    rng = random.Random(41)
    with httpx.Client(base_url="http://127.0.0.1:8000", timeout=60, trust_env=False) as control, \
         httpx.Client(base_url="http://127.0.0.1:8010", timeout=30, trust_env=False) as portal, \
         httpx.Client(base_url="http://127.0.0.1:8010", transport=httpx.HTTPTransport(local_address="127.0.0.2"),
                      timeout=30, trust_env=False) as other:
        page = control.get("/lab")
        page.raise_for_status()
        control.headers["X-Vectra-Lab-Token"] = re.search(r"const token='([^']+)'", page.text).group(1)
        reply = control.post("/api/lab/ml/start", json={"reason": "Actual varied ordinary HTTP workload from our loopback lab"})
        reply.raise_for_status()
        started = datetime.fromisoformat(reply.json()["started_at"]).timestamp()
        begin = (int(started // 5) + 1) * 5
        for i in range(32):
            wait_until(begin + 5 * i + 0.3)
            count = rng.randint(2, 12)
            errors = rng.randint(0, count // 3)
            for j in range(count):
                client = other if rng.random() < 0.25 else portal
                name = f"missing-notice-{j}.txt" if j < errors else "notice.txt"
                response = client.get("/document", params={"name": name})
                assert response.status_code == (404 if j < errors else 200), "Release active lab restrictions first"
            if (i + 1) % 5 == 0:
                print(f"Generated ordinary requests in {i + 1}/32 five-second windows", flush=True)
        wait_until(begin + 32 * 5 + 2.5)
        frozen = control.post("/api/lab/ml/freeze")
        frozen.raise_for_status()
        baseline = frozen.json()
        print(f"Frozen: {baseline['model']['training_windows']} training windows, "
              f"{len(baseline['model']['holdout_window_ids'])} later baseline holdout windows", flush=True)
        evaluation_begin = (int(time.time() // 5) + 1) * 5
        wait_until(evaluation_begin + 0.2)
        burst_start = time.time()
        for i in range(40):
            assert portal.get("/document", params={"name": f"unavailable-{i}.txt"}).status_code == 404
        wait_until((int(time.time() // 5) + 1) * 5 + 2.5)
        control.post("/api/lab/ml/tick").raise_for_status()
        result = control.get("/api/lab/state").json()["lab_ml"]
        evaluated = [w for w in result["windows"] if w["phase"] == "evaluation" and w.get("score")]
        report = dict(session_id=result["session_id"], model=result["model"],
            evaluation_windows=evaluated, burst_request_count=40, burst_started_epoch=burst_start,
            flagged=any(w["score"]["flagged"] for w in evaluated), limitations=result["limitations"])
        Path("logs").mkdir(exist_ok=True)
        Path("logs/live-ml-rehearsal.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps({"model_id": report["model"]["model_id"], "flagged": report["flagged"],
                          "holdout_flagged": report["model"]["holdout_flagged"],
                          "evaluation_windows": len(evaluated)}, indent=2), flush=True)


if __name__ == "__main__":
    main()
