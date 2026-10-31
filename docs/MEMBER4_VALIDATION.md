# Initial Member 4 checkpoint, 31 October 2026

This records the initial standalone checkpoint. The subsequent full frontend/backend integration
and its verification are described in [INTEGRATION.md](INTEGRATION.md).

Executed in this checkout, using Python 3.14.3 and the project's installed requirements.
LLM provider responses were mocked; no live credential was used.

| Check | Result |
|---|---|
| Member 4 rules, pipeline, investigation, security and ML tests | 61 passed; one upstream TestClient deprecation warning |
| Shared `data/validate.py` | 0 errors, 0 warnings; original shared files unchanged |
| Existing app lifespan smoke | Passed; loaded 19,635 threats and 27,418 IOCs from cache |
| Suspicious scenario through API | 3 findings, 3 evidence citations, `suspected_activity`, template |
| Benign maintenance through API | 0 findings, all 3 evidence records retained, `needs_verification`, template |
| Missing telemetry through API | 2 findings, 2 evidence citations, explicit process visibility gap, template |
| Synthetic ML holdout | Rules: TP 8, FP 0; rules + IF: TP 8, FP 4; 142 negative cases; model omitted |
| `git diff --check` | Passed |

The broader backend test run completed with 87 passes and 9 failures before the final additional
Member 4 cases. All nine failures require missing ignored raw feed payloads: the threat-detail
provenance hash assertion and eight `test_from_raw_matches_cache` variants. Cache-backed API,
insight and export tests otherwise passed in that run. Those checks were not weakened or skipped.
Initial sandbox temp-file errors were resolved by running the checks with normal host permissions;
Windows cache decoding needed Python's `-X utf8` switch.

Main Member 4 command, from repository root:

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest backend/tests/test_shadow_rules.py backend/tests/test_shadow_pipeline.py backend/tests/test_shadow_investigation.py backend/tests/test_shadow_security.py backend/tests/test_shadow_ml.py -q -p no:cacheprovider
```

Rehearsal and independent checks:

```powershell
.venv/Scripts/python.exe -X utf8 scripts/smoke_shadow_api.py
.venv/Scripts/python.exe -X utf8 data/validate.py
.venv/Scripts/python.exe -X utf8 scripts/evaluate_shadow.py
```

No production authentication, durable central alert persistence or Member 3 correlation is claimed.
The documented finding sink/provider seams were tested with mocks. The optional Groq component
selects grounded wording and ranks prevalidated review steps; live model quality is unvalidated.
The synthetic window benchmark is development evidence, not a real-world accuracy estimate.
