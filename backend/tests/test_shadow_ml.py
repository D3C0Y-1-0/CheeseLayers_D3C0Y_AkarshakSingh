import importlib.util
from pathlib import Path

import pytest

from shadow_watch.features import FEATURES, load_windows

ROOT = Path(__file__).resolve().parents[2]


def test_window_fixture_split_and_header():
    rows = load_windows(ROOT / "data/windows.csv")
    assert len(rows) == 500
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    assert len(train) == 350 and all(r["label"] == "normal" for r in train)
    assert len(test) == 150 and sum(r["label"] == "suspicious" for r in test) == 8
    assert not {r["window_id"] for r in train} & {r["window_id"] for r in test}
    assert len(FEATURES) == 6


def test_evaluation_uses_only_training_rows_and_fixed_features(monkeypatch):
    pytest.importorskip("sklearn")
    from sklearn.ensemble import IsolationForest
    original_fit = IsolationForest.fit
    calls = []

    def checked_fit(self, x, *args, **kwargs):
        calls.append(x.shape)
        assert x.shape == (350, 6)
        return original_fit(self, x, *args, **kwargs)

    monkeypatch.setattr(IsolationForest, "fit", checked_fit)
    spec = importlib.util.spec_from_file_location("evaluate_shadow", ROOT / "scripts/evaluate_shadow.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = module.evaluate(ROOT / "data/windows.csv")
    assert calls == [(350, 6)]
    assert report["train_test_overlap"] == []
    assert report["test_count"] == 150 and len(report["windows"]) == 150
    for name in ("rules_only", "rules_plus_isolation_forest"):
        assert report[name]["false_positive_denominator"] == 142
    assert not report["model_saved"] and not report["live_model_enabled"]
    assert all(isinstance(w["raw_anomaly_score"], float) for w in report["windows"])
    assert "probability" not in report["windows"][0]
