"""Strict parsing of access records produced by our isolated Apache lab configuration."""
import hashlib
import ipaddress
import re
from datetime import datetime
from urllib.parse import unquote


def parse(container_id, line):
    if len(line) > 4096:
        raise ValueError("log record exceeds 4096 characters")
    # docker logs --timestamps prepends a timestamp; Apache supplies its own aware observation time.
    raw = line.partition(" ")[2] if line.split(" ", 1)[0].endswith("Z") else line
    fields = raw.strip().split("|")
    if len(fields) != 10:
        raise ValueError("not a configured Apache access record")
    stamp, peer, port, method, request_line, status, size, asset_id, relay_peer, request_id = fields
    if not re.fullmatch(r"[a-f0-9]{32}", request_id):
        raise ValueError("missing relay-generated request ID")
    at = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S%z")
    peer = str(ipaddress.ip_address(peer))
    relay_peer = str(ipaddress.ip_address(relay_peer))
    if asset_id not in {"LAB-APACHE-VULN", "LAB-APACHE-PATCHED"}:
        raise ValueError("missing trusted lab route identity")
    port, status, size = int(port), int(status), 0 if size == "-" else int(size)
    if not 1 <= port <= 65535 or not 100 <= status <= 599 or size < 0:
        raise ValueError("invalid access record values")
    parts = request_line.split(" ")
    if len(parts) != 3 or parts[0] != method or not parts[2].startswith("HTTP/"):
        raise ValueError("original request line unavailable")
    path = parts[1].partition("?")[0]
    if not path.startswith("/") or len(path) > 2048:
        raise ValueError("invalid request target")
    decoded = unquote(unquote(path)).replace("\\", "/")
    signature = path.startswith("/documents/") and ".." in decoded.split("/")
    eid = "APACHE-" + hashlib.sha256((container_id + "|" + line).encode()).hexdigest()[:32]
    return dict(event_id=eid, observed_at=at.isoformat(), peer_ip=peer, peer_port=port,
        asset_id=asset_id, relay_observed_peer=relay_peer,
        request_id=request_id,
        method=method, path=path, status=status, response_bytes=size, signature_match=signature,
        raw_sha256=hashlib.sha256(line.encode()).hexdigest(), query_values_discarded="?" in parts[1])
