"""SecRepo (secrepo.com, Mike Sconzo, CC BY 4.0): REAL, timestamped logs from two real internet-facing servers.

  web  /self.logs/2016/access.log.2016-12-DD.gz   the secrepo.com web server's own access log (real visitors + real
                                                  scanners/attackers), every request with a timestamp
  ssh  /auth.log/auth.log.gz                      a real AWS server's sshd log, 30 Nov - 31 Dec 2014 (uploaded
                                                  31 Dec 2014; syslog has no year, so the year comes from that date)

Turned into one-minute windows (Shadow Watch's unit) for its rules and the Isolation Forest. We keep the raw lines of
the most active windows so a replay can show them. DEMO_MODE never downloads (cache only).

    DEMO_MODE=false backend/.venv/bin/python -m collectors.secrepo      # refresh data/cache/secrepo.json
"""
import gzip
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from .common import CACHE, RAW, get, ref, save_cache

SOURCE = "secrepo"
BASE = "https://www.secrepo.com"
WEB_MONTH = (2016, 12)  # every day of December 2016
SSH_YEAR = 2014  # auth.log.gz Last-Modified: Wed, 31 Dec 2014 -> its "Nov 30 .. Dec 31" lines are 2014
SAMPLE_WINDOWS = 40  # raw lines kept for the busiest windows of each kind (for replays)
LICENCE = "CC BY 4.0, Mike Sconzo / SecRepo (www.secrepo.com)"

WEB_LINE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<bytes>\S+)')
SSH_LINE = re.compile(r"^(?P<mon>\w{3}) +(?P<day>\d+) (?P<time>[\d:]{8}) \S+ sshd\[\d+\]: (?P<msg>.*)$")
INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.]+)")
TOO_MANY = re.compile(r"Too many authentication failures for (?:invalid user )?(?P<user>\S+)")
PAM_FAIL = re.compile(r"authentication failure;.*rhost=(?P<ip>[\d.]+)(?:\s+user=(?P<user>\S+))?")


def _minute(dt: datetime) -> str:
    return dt.replace(second=0, microsecond=0).astimezone(timezone.utc).isoformat()


def _download(path: str, name: str) -> bytes:
    raw = get(f"{BASE}/{path}", min_interval=0.5).content
    out = RAW / SOURCE / name
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(raw)
    return raw


def fetch() -> dict:
    year, month = WEB_MONTH
    web = []
    day = datetime(year, month, 1)
    while day.month == month:
        name = f"access.log.{day:%Y-%m-%d}.gz"
        web.append(_download(f"self.logs/{year}/{name}", name))
        day += timedelta(days=1)
    ssh = _download("auth.log/auth.log.gz", "auth.log.gz")
    return parse(web, ssh)


def from_raw() -> dict:
    files = sorted((RAW / SOURCE).glob("access.log.*.gz"))
    return parse([f.read_bytes() for f in files], (RAW / SOURCE / "auth.log.gz").read_bytes())


def web_windows(texts: list[str]) -> tuple[list[dict], dict]:
    from app.detection import RECON_PATHS, known_exploit, signature_hits
    win: dict[str, dict] = defaultdict(lambda: {"requests": 0, "http_4xx": 0, "failed_auth": 0, "attack_hits": 0,
                                                "recon_hits": 0, "clients": Counter(), "paths": Counter()})
    lines: dict[str, list[str]] = defaultdict(list)
    for text in texts:
        for line in text.splitlines():
            m = WEB_LINE.match(line)
            if not m:
                continue
            at = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
            k, status, path = _minute(at), int(m["status"]), m["path"]
            w = win[k]
            w["requests"] += 1
            w["http_4xx"] += 400 <= status < 500
            w["failed_auth"] += status in (401, 403)
            w["attack_hits"] += bool(signature_hits(path) or known_exploit(path))
            w["recon_hits"] += bool(RECON_PATHS.search(path))
            w["clients"][m["ip"]] += 1
            w["paths"][path.split("?")[0][:80]] += 1
            lines[k].append(line)
    out = [{"minute": k, "requests": w["requests"], "http_4xx": w["http_4xx"], "failed_auth": w["failed_auth"],
            "attack_hits": w["attack_hits"], "recon_hits": w["recon_hits"], "unique_clients": len(w["clients"]),
            "unique_paths": len(w["paths"]), "top_clients": [ip for ip, _ in w["clients"].most_common(3)],
            "top_paths": [p for p, _ in w["paths"].most_common(3)]} for k, w in sorted(win.items())]
    return out, lines


def ssh_windows(text: str) -> tuple[list[dict], dict]:
    win: dict[str, dict] = defaultdict(lambda: {"invalid_users": 0, "auth_failures": 0, "events": 0,
                                                "sources": Counter(), "users": Counter()})
    lines: dict[str, list[str]] = defaultdict(list)
    for line in text.splitlines():
        m = SSH_LINE.match(line)
        if not m:
            continue
        at = datetime.strptime(f"{SSH_YEAR} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        msg, k = m["msg"], _minute(at)
        w = win[k]
        w["events"] += 1
        if x := INVALID.search(msg):
            w["invalid_users"] += 1
            w["sources"][x["ip"]] += 1
            w["users"][x["user"] or "(empty)"] += 1
        elif x := TOO_MANY.search(msg):
            w["auth_failures"] += 1
            w["users"][x["user"]] += 1
        elif x := PAM_FAIL.search(msg):
            w["auth_failures"] += 1
            w["sources"][x["ip"]] += 1
        else:
            continue
        lines[k].append(line)
    out = [{"minute": k, "invalid_users": w["invalid_users"], "auth_failures": w["auth_failures"],
            "failed_logins": w["invalid_users"] + w["auth_failures"], "unique_sources": len(w["sources"]),
            "unique_users": len(w["users"]), "top_sources": [ip for ip, _ in w["sources"].most_common(3)],
            "top_users": [u for u, _ in w["users"].most_common(5)]}
           for k, w in sorted(win.items()) if w["invalid_users"] + w["auth_failures"]]
    return out, lines


def parse(web_gz: list[bytes], ssh_gz: bytes) -> dict:
    web, web_lines = web_windows([gzip.decompress(b).decode("utf-8", "replace") for b in web_gz])
    ssh, ssh_lines = ssh_windows(gzip.decompress(ssh_gz).decode("utf-8", "replace"))
    busiest_web = sorted(web, key=lambda w: (-(w["attack_hits"] + w["recon_hits"]), -w["requests"]))[:SAMPLE_WINDOWS]
    busiest_ssh = sorted(ssh, key=lambda w: -w["failed_logins"])[:SAMPLE_WINDOWS]
    return {
        "source": SOURCE, "licence": LICENCE, "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "note": "Real logs from two real servers: secrepo.com's web server (Dec 2016) and an AWS server's sshd "
                "(30 Nov - 31 Dec 2014). One-minute windows; minutes with no activity are omitted.",
        "web": {"period": f"{WEB_MONTH[0]}-{WEB_MONTH[1]:02d}", "windows": web,
                "samples": {w["minute"]: web_lines[w["minute"]][:200] for w in busiest_web}},
        "ssh": {"period": f"{SSH_YEAR}-11-30 to {SSH_YEAR}-12-31", "windows": ssh,
                "samples": {w["minute"]: ssh_lines[w["minute"]][:200] for w in busiest_ssh}},
    }


def load() -> dict | None:
    path = CACHE / f"{SOURCE}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


if __name__ == "__main__":
    data = fetch()
    path = save_cache(SOURCE, data)
    w, s = data["web"]["windows"], data["ssh"]["windows"]
    print(f"web: {len(w)} active minutes, {sum(x['requests'] for x in w)} requests | ssh: {len(s)} minutes with failures, "
          f"{sum(x['failed_logins'] for x in s)} failed logins -> {ref(path)}")
