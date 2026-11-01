"""Deterministic rules for server-observed lab traffic; no fixture-selected verdicts."""
import posixpath
from datetime import timedelta
from urllib.parse import unquote


def decoded_path(value: str) -> str:
    # The service and the detector share a bounded decoding policy.
    for _ in range(2):
        value = unquote(value)
    return value.replace("\\", "/")


def traversal(value: str) -> bool:
    return ".." in decoded_path(value).split("/")


def virtual_document(value: str, patched: bool) -> tuple[int, str]:
    """A real access-control flaw inside a virtual dummy document store, never host files.

    Vulnerable mode allows escaping /public into /internal. Patched mode enforces /public.
    A fixed outer dictionary always confines reads to these two explicitly synthetic documents.
    """
    name = decoded_path(value)
    target = posixpath.normpath("/public/" + name)
    if patched and not target.startswith("/public/"):
        return 403, "Document boundary enforced"
    docs = {"/public/notice.txt": "Fictional district portal: public service notice.",
            "/internal/dummy-records.json": '[{"application":"DEMO-001","person":"FICTIONAL CITIZEN","status":"pending"}]'}
    return (200, docs[target]) if target in docs else (404, "Document not found")


def verdict(current: dict, history: list[dict]) -> dict | None:
    """Evidence-linked rules; input is collected by the service, not supplied as a verdict."""
    if current["status"] == 429:
        return None  # Enforcement is evidence, not another successful attack.
    if current["kind"] == "document" and traversal(current["name"]):
        return dict(rule_id="LIVE-WEB-001", signal="http_anomaly", label="Path traversal attempt",
                    reason=f"Parent-directory segment in document name; service returned HTTP {current['status']}",
                    evidence_ids=[current["event_id"]], confidence="medium")
    if current["kind"] != "login":
        return None
    lower = current["at"] - timedelta(seconds=60)
    prior = [r for r in history if r["kind"] == "login" and lower <= r["at"] <= current["at"]
             and r["event_id"] != current["event_id"] and r["status"] == 401]
    same = [r for r in prior if r["peer_ip"] == current["peer_ip"]]
    if current["status"] == 200:
        same_user = [r for r in same if r["username"] == current["username"]]
        if len(same_user) >= 5:
            return dict(rule_id="LIVE-AUTH-002", signal="credential_compromise",
                        label="Login succeeded after repeated failures",
                        reason=f"Successful login after {len(same_user)} failures for the same username and TCP peer in 60s; ownership unverified",
                        evidence_ids=[r["event_id"] for r in same_user] + [current["event_id"]], confidence="medium")
        return None
    if current["status"] == 401 and len(same) + 1 >= 10:
        return dict(rule_id="LIVE-AUTH-001", signal="brute_force", label="Login failure burst",
                    reason=f"{len(same) + 1} failed logins from the same TCP peer in 60s",
                    evidence_ids=[r["event_id"] for r in same] + [current["event_id"]], confidence="medium")
    if current["status"] == 401:
        candidates = same + [current]
        if len({r["username"] for r in candidates}) >= 5:
            return dict(rule_id="LIVE-AUTH-003", signal="brute_force", label="Multi-account login failures",
                        reason="Failures against at least 5 usernames from one TCP peer in 60s; possible password spraying",
                        evidence_ids=[r["event_id"] for r in candidates], confidence="medium")
    return None
