"""One-minute synthetic benchmark schema, NOT an adapter for arbitrary network datasets."""
import csv
import math
from pathlib import Path

FEATURES = ("requests_per_minute", "http_4xx_ratio", "failed_logins", "unique_client_ips",
            "new_outbound_destinations", "unexpected_child_processes")
HEADER = {"window_id", "asset_id", *FEATURES, "label", "split"}


def load_windows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        if set(reader.fieldnames or []) != HEADER:
            raise ValueError("incompatible one-minute window header")
        rows = list(reader)
    ids = set()
    for row in rows:
        if not row["window_id"] or row["window_id"] in ids or not row["asset_id"]:
            raise ValueError("duplicate/missing window ID or missing asset ID")
        ids.add(row["window_id"])
        if row["label"] not in {"normal", "suspicious"} or row["split"] not in {"train", "test"}:
            raise ValueError("unknown label/split")
        if row["split"] == "train" and row["label"] != "normal":
            raise ValueError("training split must contain only normal observations")
        for feature in FEATURES:
            value = float(row[feature])
            if not math.isfinite(value) or value < 0:
                raise ValueError("invalid feature value")
            if feature == "http_4xx_ratio":
                if value > 1:
                    raise ValueError("4xx ratio outside 0..1")
            elif not value.is_integer():
                raise ValueError("count features must be integers")
            row[feature] = value
    if not any(r["split"] == "train" for r in rows) or not any(r["split"] == "test" for r in rows):
        raise ValueError("both train and test splits required")
    return rows


def window_rules(row: dict) -> bool:
    # Aggregated process count is pre-labelled by the synthetic fixture generator.
    # Real SW-PROC-001 uses verified ancestry; this benchmark cannot validate that step.
    return bool((row["requests_per_minute"] >= 200 and row["http_4xx_ratio"] >= .6)
                or row["unexpected_child_processes"] > 0)
