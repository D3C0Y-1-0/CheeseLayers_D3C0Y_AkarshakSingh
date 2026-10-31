"""CERT-In (India's national CERT): latest advisories (CIAD) + vulnerability notes (CIVN), scraped from HTML.

Site layout (Oct 2026): / is a frameset -> s2cMainServlet?pageid=PUBWEL01 links to the list pages
(PUBADVLIST, VLNLIST) -> per-year pages (...02&year=YYYY) -> detail pages (...&VLCODE=CIVN-2026-0533).
We discover each hop from links instead of hardcoding, so a renamed pageid doesn't break us silently.
"""
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .common import RAW, get, log, ref, save_raw
from .schema import AffectedConfiguration, ThreatItem, severity

SOURCE = "certin"
HOME = "https://www.cert-in.org.in/"
IST = timezone(timedelta(hours=5, minutes=30))  # CERT-In dates are Indian time
LIMIT = 20  # latest N per list (advisories, vulnerability notes)
LISTS = {"PUBADVLIST": "advisory", "VLNLIST": "vulnerability_note"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _soup(url: str) -> BeautifulSoup:
    return BeautifulSoup(get(url, min_interval=1.5).text, "lxml")  # be polite: government server, slow at times


def _links(soup: BeautifulSoup, base: str, pattern: str) -> list[str]:
    # CERT-In hrefs carry leading tabs/spaces ("href=' \t/s2cMain…'"), so strip before joining.
    out = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if re.search(pattern, href) and (u := urljoin(base, href)) not in out:
            out.append(u)
    return out


def _section(lines: list[str], start: str, stops: tuple[str, ...]) -> list[str]:
    if start not in lines:
        return []
    out = []
    for line in lines[lines.index(start) + 1:]:
        if line in stops:
            break
        out.append(line)
    return out


def _affected(line: str) -> AffectedConfiguration:
    # "Mozilla Firefox versions prior to 159" -> vendor "Mozilla", product "Firefox", versions_text "prior to 159"
    # Free text doesn't fit NVD-style bounds, so it goes in versions_text (an extra) and all bounds stay None.
    # ponytail: first word = vendor is a guess; the correlator fuzzy-matches anyway. Map to CPE names if matching is weak.
    m = re.match(r"(.+?)\s+versions?\b\s*(.*)", line, re.I)
    name, ver = (m.group(1), m.group(2)) if m else (line, "")
    words = name.split()
    return AffectedConfiguration(vendor=words[0], product=" ".join(words[1:]) or name, versions_text=ver or None)


def _detail(url: str, kind: str, code: str) -> ThreatItem:
    soup = _soup(url)
    for x in soup(["script", "style"]):
        x.decompose()
    text = soup.get_text("\n", strip=True)
    body = text[text.find(code):]  # skip the site's navigation menu
    return parse(body, url, kind, code, save_raw(SOURCE, body, code))


# Detail-page URL is fixed per document type (seen Oct 2026), so it can be rebuilt for raw files.
DETAIL = {"CIAD": ("advisory", "PUBVLNOTES02"), "CIVN": ("vulnerability_note", "PUBVLNOTES01")}


def from_raw() -> dict:
    items = []
    for f in sorted((RAW / SOURCE).glob("CI*.txt")):
        kind, page = DETAIL[f.stem[:4]]
        items.append(parse(f.read_text(), f"{HOME}s2cMainServlet?pageid={page}&VLCODE={f.stem}", kind, f.stem, ref(f)))
    return {"items": items}


def parse(body: str, url: str, kind: str, code: str, raw_ref: str) -> ThreatItem:
    lines = [re.sub(r"\s+", " ", l) for l in body.splitlines()]
    title = lines[1] if len(lines) > 1 else code
    date = re.search(r"Original Issue Date:\s*([A-Za-z]+)\s+(\d{1,2}),\s*(\d{4})", body)
    sev = re.search(r"Severity Rating:\s*([A-Za-z]+)", body)
    overview = _section(lines, "Overview", ("Target Audience:", "Description", "Solution"))
    return ThreatItem(
        threat_id=code, source=SOURCE, type="advisory", title=f"{code}: {title}",
        description=" ".join(overview) or None,
        published_at=datetime.strptime(" ".join(date.groups()), "%B %d %Y").replace(tzinfo=IST) if date else None,
        references=[url], cve_ids=sorted(set(CVE_RE.findall(body))),
        severity=severity(sev.group(1)) if sev else None,
        affected_configurations=[_affected(l) for l in _section(lines, "Software Affected", ("Overview", "Description"))],
        tags=["cert-in", kind, "india"], raw_ref=raw_ref,
    )


def fetch() -> dict:
    home = _soup(HOME)
    frame = home.find("frame", src=re.compile("s2cMainServlet"))
    welcome_url = urljoin(HOME, frame["src"].strip()) if frame else urljoin(HOME, "s2cMainServlet?pageid=PUBWEL01")
    welcome = _soup(welcome_url)
    items = []
    for list_id, kind in LISTS.items():
        list_url = next(iter(_links(welcome, welcome_url, rf"pageid={list_id}$")), urljoin(HOME, f"s2cMainServlet?pageid={list_id}"))
        years = sorted(_links(_soup(list_url), list_url, r"&year=\d{4}"), key=lambda u: u[-4:], reverse=True)
        details: list[str] = []
        for year_url in years:  # newest year first; dip into last year in early January
            details += _links(_soup(year_url), year_url, r"VLCODE=")
            if len(details) >= LIMIT:
                break
        for url in details[:LIMIT]:
            code = url.split("VLCODE=")[-1]
            try:
                items.append(_detail(url, kind, code))
            except Exception as e:  # one malformed page shouldn't drop the rest
                log.warning("certin: skipping %s (%s)", code, e)
    if not items:
        raise RuntimeError("no CERT-In items parsed — site layout changed?")
    return {"items": items}
