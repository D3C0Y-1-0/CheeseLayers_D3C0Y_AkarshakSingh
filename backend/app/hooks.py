"""Integration hooks between members. Member 2 calls them; owners fill them in."""


def on_new_threat(threat_id: str) -> None:
    """Called after a threat is inserted/refreshed by POST /api/demo/inject-cve.

    TODO(Member 3): match the threat against data/assets.json, score it, create alerts.
    Must not raise: the inject endpoint has already committed the threat.
    """
