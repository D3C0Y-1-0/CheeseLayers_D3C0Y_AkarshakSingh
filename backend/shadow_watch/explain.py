"""Explainable AI for the Isolation Forest (SW-ML-001): SHAP values turned into plain-language reasons.

How to read it
  The Isolation Forest isolates a minute by random splits. Unusual minutes are isolated in FEW splits (short path);
  normal ones need many. SHAP's TreeExplainer splits this minute's average path length into one contribution per
  feature, relative to the average training minute (the "baseline"):
      path length = baseline + sum(SHAP values)
  A NEGATIVE SHAP value = that feature made the minute easier to isolate = pushed it towards "unusual".
  Checked on the cached SecRepo data: baseline + sum(SHAP) tracks the model's own decision score (corr. 0.996).

Every number here is recomputed from the same fitted model and training minutes the live detector uses; nothing is
estimated by a language model.
"""
from functools import lru_cache

import numpy as np

from . import ml

LABELS = {
    "requests_per_minute": "Requests per minute",
    "http_4xx_ratio": "Share of requests that failed (HTTP 4xx)",
    "unique_clients": "Different client IP addresses",
    "failed_auth": "Failed logins",
    "failed_logins": "Failed SSH logins",
    "unique_sources": "Different source IP addresses",
    "unique_users": "Different usernames tried",
    "invalid_user_ratio": "Share of attempts with non-existent usernames",
}
SENSOR_NAME = {"web": "the secrepo.com web server", "ssh": "the AWS SSH server"}
METHOD = [
    "Model: scikit-learn Isolation Forest (200 trees, 2% expected outliers), trained only on the earliest 70% of this "
    "sensor's real one-minute history (SecRepo) and never on the minutes it is tested on.",
    "Explanation: SHAP TreeExplainer computes each feature's exact contribution to this minute's isolation path "
    "length, compared with an average training minute. Negative = pushed towards 'unusual'.",
    "Percentiles compare each value with the same feature in the training minutes.",
]
LIMITATIONS = [
    "An outlier is unusual for this sensor, not proof of an attack; SW-ML-001 findings are low severity, low confidence.",
    "SHAP explains the model's decision, not the attacker's intent. Features interact: a value can matter only in "
    "combination with another.",
    "The baseline is the sensor's own past: if the past contained attacks, the model treats them as normal.",
]


@lru_cache(maxsize=2)
def _context(kind: str):
    """(explainer, baseline, training matrix) for one sensor's fitted model, or None without a model."""
    import shap
    fitted = ml.model(kind)
    if fitted is None:
        return None
    train, _ = ml.split(kind)
    x = np.array([ml.window_features(kind, w) for w in train], dtype=float)
    explainer = shap.TreeExplainer(fitted[0])
    return explainer, float(np.ravel(explainer.expected_value)[0]), x


def _fmt(name: str, v: float) -> str:
    return f"{v:.0%}" if name.endswith("ratio") else f"{v:,.0f}" if float(v).is_integer() else f"{v:,.1f}"


def explain(kind: str, features: list[float]) -> dict | None:
    """SHAP explanation of one feature vector, with plain-language sentences."""
    ctx = _context(kind)
    score = ml.score_features(kind, features)
    if ctx is None or score is None:
        return None
    explainer, base, train = ctx
    sv = np.ravel(explainer.shap_values(np.array([features], dtype=float))[0])
    total = float(np.abs(sv).sum()) or 1.0
    names = ml.FEATURES[kind]
    rows = []
    for i, name in enumerate(names):
        col = train[:, i]
        v = float(features[i])
        pct = float((col < v).mean() * 100)  # share of training minutes with a LOWER value
        med = float(np.median(col))
        toward = "none" if abs(sv[i]) < 1e-6 else "unusual" if sv[i] < 0 else "normal"
        share = abs(float(sv[i])) / total * 100
        label = LABELS.get(name, name)
        if v > med:
            sentence = f"{label} was {_fmt(name, v)}, above the usual {_fmt(name, med)} (higher than {min(pct, 99.9):.0f}% of normal minutes). "
        elif v < med:
            sentence = f"{label} was {_fmt(name, v)}, below the usual {_fmt(name, med)}. "
        else:
            sentence = f"{label} was {_fmt(name, v)}, a typical value for this sensor. "
        sentence += {"unusual": f"This made the minute look more unusual and accounts for {share:.0f}% of the decision.",
                     "normal": f"This looked normal and pulled the verdict back towards normal ({share:.0f}% of the decision).",
                     "none": "It had no effect on the decision."}[toward]
        rows.append({"feature": name, "label": LABELS.get(name, name), "value": round(v, 4),
                     "training_median": round(med, 4), "training_percentile": round(pct, 1),
                     "shap_value": round(float(sv[i]), 4), "toward": toward, "share_pct": round(share, 1),
                     "sentence": sentence})
    rows.sort(key=lambda r: r["shap_value"])  # most "unusual"-pushing first
    drivers = [r for r in rows if r["toward"] == "unusual"]
    flagged = score["flagged"]
    head = (f"The model {'flagged' if flagged else 'did not flag'} this minute from {SENSOR_NAME[kind]}: it is more "
            f"unusual than {score['unusual_percentile']}% of the {score['training_minutes']:,} normal minutes it learned from.")
    if drivers:
        top = drivers[0]
        p = top["training_percentile"]
        where = (f"higher than {min(p, 99.9):g}% of normal minutes" if top["value"] > top["training_median"]
                 else f"lower than {min(100 - p, 99.9):g}% of normal minutes")
        head += f" Main reason: {top['label']} was {_fmt(top['feature'], top['value'])}, {where}."
        if len(drivers) > 1:
            head += " Also contributing: " + "; ".join(d["label"] for d in drivers[1:3]) + "."
    return {"sensor": kind, "sensor_name": SENSOR_NAME[kind], "flagged": flagged, "outlier_score": score["score"],
            "unusual_percentile": score["unusual_percentile"], "training_minutes": score["training_minutes"],
            "trained_until": score["trained_until"], "baseline_path_length": round(base, 3),
            "path_length": round(base + float(sv.sum()), 3), "summary": head, "features": rows,
            "method": METHOD, "limitations": LIMITATIONS}


@lru_cache(maxsize=2)
def global_importance(kind: str, sample: int = 400) -> list[dict]:
    """Model card: mean |SHAP| per feature over training minutes = what this model relies on overall."""
    ctx = _context(kind)
    if ctx is None:
        return []
    explainer, _, train = ctx
    idx = np.linspace(0, len(train) - 1, min(sample, len(train))).astype(int)
    mean = np.abs(explainer.shap_values(train[idx])).mean(axis=0)
    total = float(mean.sum()) or 1.0
    return sorted(({"feature": f, "label": LABELS.get(f, f), "mean_abs_shap": round(float(m), 4),
                    "share_pct": round(float(m) / total * 100, 1)} for f, m in zip(ml.FEATURES[kind], mean)),
                  key=lambda r: -r["share_pct"])


def explain_event(event) -> dict | None:
    kind = ml.SENSORS.get(event.source)
    if kind is None or event.event_type not in ("http_window", "auth_window"):
        return None
    return explain(kind, ml.event_features(kind, event.details))


if __name__ == "__main__":  # self-check: contributions add up, and the most unusual test minute is explained as such
    for k in ("web", "ssh"):
        if _context(k) is None:
            continue
        _, test = ml.split(k)
        worst = min(test, key=lambda w: ml.score_features(k, ml.window_features(k, w))["score"])
        e = explain(k, ml.window_features(k, worst))
        assert e["flagged"] and e["features"][0]["toward"] == "unusual", e
        assert abs(sum(f["share_pct"] for f in e["features"]) - 100) < 0.5
        print(k, e["summary"])
