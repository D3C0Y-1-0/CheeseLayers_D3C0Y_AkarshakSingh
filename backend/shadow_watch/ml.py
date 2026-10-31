"""Isolation Forest baselines learned from REAL sensor history (SecRepo, data/cache/secrepo.json), one per sensor.

Each model learns what a normal minute looks like for ONE real sensor (the secrepo.com web server, or one AWS sshd),
from the earliest `train_fraction` of that sensor's minutes (a temporal split: never trained on what it is tested on).
It only scores events from the sensor it was trained on: a baseline from one server says nothing about another.

The output is an outlier score, not an attack probability. SW-ML-001 findings are low severity and low confidence:
"unusual, needs review". They exist to catch what thresholds miss (bulk scraping, distributed low-and-slow spraying).
Trained in memory at first use (a second or so); never pickled. Evaluation: scripts/evaluate_shadow_real.py.
"""
from functools import lru_cache

CONFIG = {"n_estimators": 200, "contamination": 0.02, "train_fraction": 0.7, "random_state": 42}
SENSORS = {"secrepo:web": "web", "secrepo:ssh": "ssh"}
FEATURES = {"web": ["requests_per_minute", "http_4xx_ratio", "unique_clients", "failed_auth"],
            "ssh": ["failed_logins", "unique_sources", "unique_users", "invalid_user_ratio"]}


def window_features(kind: str, w: dict) -> list[float]:
    """Features from a cached SecRepo window."""
    if kind == "web":
        return [w["requests"], w["http_4xx"] / w["requests"] if w["requests"] else 0.0, w["unique_clients"], w["failed_auth"]]
    return [w["failed_logins"], w["unique_sources"], w["unique_users"], w["invalid_users"] / max(w["failed_logins"], 1)]


def event_features(kind: str, d) -> list[float]:
    """The same features from a normalized event's details (HTTPDetails / AuthDetails)."""
    if kind == "web":
        per_min = d.request_count * 60 / d.window_seconds
        return [per_min, d.http_4xx_count / d.request_count if d.request_count else 0.0, d.unique_client_count, d.failed_auth_count]
    return [d.failed_count, d.unique_source_count, d.unique_user_count, d.invalid_user_count / max(d.failed_count, 1)]


def split(kind: str) -> tuple[list[dict], list[dict]]:
    from collectors import secrepo
    data = secrepo.load() or {}
    windows = sorted((data.get(kind) or {}).get("windows", []), key=lambda w: w["minute"])
    cut = int(len(windows) * CONFIG["train_fraction"])
    return windows[:cut], windows[cut:]


@lru_cache(maxsize=2)
def model(kind: str):
    """(fitted model, sorted training scores, training size, last training minute) or None without data."""
    import numpy as np
    from sklearn.ensemble import IsolationForest
    train, _ = split(kind)
    if len(train) < 50:
        return None
    x = np.array([window_features(kind, w) for w in train], dtype=float)
    m = IsolationForest(n_estimators=CONFIG["n_estimators"], contamination=CONFIG["contamination"],
                        random_state=CONFIG["random_state"], n_jobs=1).fit(x)
    return m, sorted(m.decision_function(x).tolist()), len(train), train[-1]["minute"]


def score_features(kind: str, features: list[float]) -> dict | None:
    fitted = model(kind)
    if fitted is None:
        return None
    m, train_scores, n, last = fitted
    s = float(m.decision_function([features])[0])
    more_normal = sum(t > s for t in train_scores) / n  # share of training minutes that look MORE normal than this one
    return {"score": round(s, 4), "flagged": bool(m.predict([features])[0] == -1),
            "unusual_percentile": round(100 * more_normal, 1), "training_minutes": n, "trained_until": last,
            "features": dict(zip(FEATURES[kind], [round(f, 3) for f in features]))}


def score_event(event) -> dict | None:
    kind = SENSORS.get(event.source)
    if kind is None or event.event_type not in ("http_window", "auth_window"):
        return None
    return score_features(kind, event_features(kind, event.details))
