"""Isolation Forest on REAL sensor history (SecRepo), temporal holdout, compared with our rules. Never saves a model.

    backend/.venv/bin/python scripts/evaluate_shadow_real.py      -> artifacts/shadow_evaluation_real.json

There is no ground truth for real logs. So the comparison is with what our RULES flag on the same held-out minutes
(web: an attack signature / known-exploit path or 3+ secret-path requests; ssh: 10+ failed logins). That measures
agreement and what each finds that the other misses; it is not an accuracy figure.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from shadow_watch import ml  # noqa: E402

RULE = {"web": lambda w: w["attack_hits"] > 0 or w["recon_hits"] >= 3, "ssh": lambda w: w["failed_logins"] >= 10}
RULE_TEXT = {"web": "attack signature / known-exploit path, or 3+ secret-path requests in the minute",
             "ssh": "10+ failed logins in the minute (SW-AUTH-001)"}


def evaluate(kind: str) -> dict:
    train, test = ml.split(kind)
    scored = [(ml.score_features(kind, ml.window_features(kind, w)), w) for w in test]
    both = [w for s, w in scored if s["flagged"] and RULE[kind](w)]
    model_only = [(s, w) for s, w in scored if s["flagged"] and not RULE[kind](w)]
    rules_only = [w for s, w in scored if not s["flagged"] and RULE[kind](w)]
    return {
        "sensor": f"secrepo:{kind}", "train_minutes": len(train), "test_minutes": len(test),
        "trained_until": train[-1]["minute"], "test_from": test[0]["minute"], "test_to": test[-1]["minute"],
        "features": ml.FEATURES[kind], "rule_definition": RULE_TEXT[kind],
        "rule_flagged_test_minutes": sum(RULE[kind](w) for w in test),
        "model_flagged_test_minutes": sum(s["flagged"] for s, _ in scored),
        "both": len(both), "model_only": len(model_only), "rules_only": len(rules_only),
        "model_only_examples": [{"minute": w["minute"], "unusual_percentile": s["unusual_percentile"], **s["features"],
                                 "top_sources": w.get("top_sources", w.get("top_clients", []))[:3]}
                                for s, w in sorted(model_only, key=lambda x: x[0]["score"])[:8]],
    }


if __name__ == "__main__":
    report = {
        "is_simulated": False, "dataset": "SecRepo real logs (CC BY 4.0): secrepo.com web server Dec 2016; AWS sshd "
                                          "30 Nov - 31 Dec 2014", "model": ml.CONFIG,
        "split": f"temporal: first {int(ml.CONFIG['train_fraction'] * 100)}% of each sensor's active minutes train, rest test",
        "sensors": [evaluate("web"), evaluate("ssh")],
        "decision": "Enabled as SW-ML-001: a LOW-severity, low-confidence 'unusual, needs review' finding, only for the "
                    "real sensor each model was trained on, and only for windows no rule flagged. It never escalates "
                    "an incident by itself.",
        "limitations": ["No ground truth: agreement with our rules is not accuracy",
                        "Payload attacks hidden in normal-volume minutes are left to the rules (the model does not see payloads)",
                        "One server per sensor; a baseline does not transfer to other servers",
                        "Outlier score, not attack probability"],
        "model_saved": False,
    }
    out = ROOT / "artifacts" / "shadow_evaluation_real.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for s in report["sensors"]:
        print(f"{s['sensor']}: train {s['train_minutes']} / test {s['test_minutes']} minutes | rules flag "
              f"{s['rule_flagged_test_minutes']}, model flags {s['model_flagged_test_minutes']} | both {s['both']}, "
              f"model-only {s['model_only']}, rules-only {s['rules_only']}")
    print(f"-> {out.relative_to(ROOT)}")
