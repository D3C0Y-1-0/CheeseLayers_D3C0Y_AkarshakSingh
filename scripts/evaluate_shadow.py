"""Reproducible development-only Isolation Forest comparison. Never saves/loads a pickle."""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from shadow_watch.features import FEATURES, load_windows, window_rules


def metrics(truth, predicted):
    tp = sum(a and b for a, b in zip(truth, predicted))
    fp = sum(not a and b for a, b in zip(truth, predicted))
    fn = sum(a and not b for a, b in zip(truth, predicted))
    tn = sum(not a and not b for a, b in zip(truth, predicted))
    return dict(true_positives=tp, false_positives=fp, false_negatives=fn, true_negatives=tn,
                precision=tp / (tp + fp) if tp + fp else None, recall=tp / (tp + fn) if tp + fn else None,
                false_positive_rate=fp / (fp + tn) if fp + tn else None, false_positive_denominator=fp + tn)


def evaluate(path: Path) -> dict:
    import numpy as np
    import sklearn
    from sklearn.ensemble import IsolationForest

    rows = load_windows(path)
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    train_ids, test_ids = {r["window_id"] for r in train}, {r["window_id"] for r in test}
    if train_ids & test_ids:
        raise ValueError("train/test leakage")
    x_train = np.array([[r[f] for f in FEATURES] for r in train])
    x_test = np.array([[r[f] for f in FEATURES] for r in test])
    model = IsolationForest(n_estimators=100, contamination=.02, random_state=42, n_jobs=1)
    start = perf_counter()
    model.fit(x_train)
    fit_ms = (perf_counter() - start) * 1000
    start = perf_counter()
    baseline = [window_rules(r) for r in test]
    rules_ms = (perf_counter() - start) * 1000
    start = perf_counter()
    scores = model.decision_function(x_test)
    anomaly = scores < 0
    combined = [rule or bool(flag) for rule, flag in zip(baseline, anomaly)]
    combined_ms = (perf_counter() - start) * 1000 + rules_ms
    truth = [r["label"] == "suspicious" for r in test]
    before, after = metrics(truth, baseline), metrics(truth, combined)
    improvement = after["true_positives"] > before["true_positives"] and after["false_positives"] <= before["false_positives"]
    return {"is_simulated": True, "dataset": path.name, "dataset_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "features": list(FEATURES), "feature_schema": "netrax-one-minute-v1", "seed": 42,
            "n_estimators": 100, "contamination": .02, "sklearn_version": sklearn.__version__,
            "train_count": len(train), "train_normal_count": len(train), "test_count": len(test),
            "test_normal_count": truth.count(False), "test_suspicious_count": truth.count(True),
            "train_test_overlap": sorted(train_ids & test_ids), "fit_latency_ms": fit_ms,
            "rules_only": {**before, "batch_latency_ms": rules_ms},
            "rules_plus_isolation_forest": {**after, "batch_latency_ms": combined_ms},
            "model_saved": False, "live_model_enabled": False,
            "decision": "Review independent validation before considering integration" if improvement else "Omit live ML: no recall gain without additional false positives",
            "limitations": ["Entire dataset and labels are synthetic; no real-world accuracy claim",
                            "Supplied split contains normal training rows only; test rows never used for fitting or threshold tuning",
                            "Small held-out set; no independent validation set; fixed settings were selected before evaluation",
                            "Unexpected process counts are synthetic pre-labelled features, not independent ancestry validation",
                            "No timestamps in fixture; this is a supplied row split, not a verified temporal holdout",
                            "Raw decision_function score is an outlier score, not attack probability or incident priority",
                            "Latency is one local batch measurement, not a production performance benchmark"],
            "windows": [{"window_id": r["window_id"], "label": r["label"], "rules_flag": baseline[i],
                         "is_outlier": bool(anomaly[i]), "raw_anomaly_score": float(scores[i])} for i, r in enumerate(test)]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "data/windows.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/shadow_evaluation.json")
    args = parser.parse_args()
    report = evaluate(args.dataset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "windows"}, indent=2))
