"""Tri-state version matcher: does this asset run a version a threat says is vulnerable?

Each threat lists affected_configurations (NVD "cpeMatch" entries): a vendor + product plus version
bounds, e.g. ">= 7.2.0 and < 7.2.7". We compare every package an asset runs against those entries.

Three answers, never more confident than the data allows:
  confirmed_affected   vendor + product match, versions parse cleanly, installed version is inside a range
  confirmed_unaffected different product, OR versions parse cleanly and the installed one is outside every range
  needs_verification   product matches but something is uncertain: version unknown, non-standard version string
                       (vendor suffixes like "9.9p1", "22.6R2.2", "10.2.9-h1"), complex CPE logic, or the
                       advisory gives no usable bounds.
CRITICAL RULE: uncertainty never becomes confirmed_affected.
"""
import re
from dataclasses import dataclass, field
from typing import Literal

from packaging.version import InvalidVersion, Version

from .contracts import AffectedConfiguration, Asset, SoftwareItem, ThreatRecord

MatchDetailResult = Literal["confirmed_affected", "confirmed_unaffected", "needs_verification"]
_RANK = {"confirmed_unaffected": 0, "needs_verification": 1, "confirmed_affected": 2}


@dataclass
class MatchResult:
    asset_id: str
    threat_id: str
    match_detail: MatchDetailResult  # Member 3's 3-state answer
    match_status: str | None  # contract value: confirmed | uncertain | requires_manual_review | None (unaffected)
    reason: str
    software: dict | None = None  # the package that drove the answer
    configuration: dict | None = None  # the affected_configurations entry that drove the answer
    candidates: list[dict] = field(default_factory=list)  # every package/config pair that shared vendor+product


def norm(s: str | None) -> str:
    """NVD names are lowercase with underscores ("http_server"); normalise inventory names the same way."""
    return (s or "").strip().lower().replace(" ", "_").replace("-", "_")


def parse_version(s: str | None) -> Version | None:
    """Strict parse. Returns None for anything packaging can't read cleanly (vendor suffixes, '*', '-')."""
    if s is None or s.strip() in ("", "*", "-"):
        return None
    try:
        return Version(s.strip())
    except InvalidVersion:
        return None


def _cannot_equal(installed: Version, exact: str) -> bool:
    """True only when an EXACT advisory version provably differs from a cleanly parsed installed version.

    Non-standard exact versions ("3.7.0e", "2.0 beta9", "15.2(2)e4") still start with a plain number. If that
    numeric part differs from the installed release (17.18.2), the two can never be the same version.
    Same numeric part (installed 2.0 vs "2.0 beta9") -> False: a human has to decide.
    """
    m = re.match(r"\d+(\.\d+)*", exact)
    prefix = parse_version(m.group(0)) if m else None
    return prefix is not None and prefix != Version(installed.base_version)


def _cpe_parts(cpe: str | None) -> list[str]:
    # cpe:2.3:part:vendor:product:version:update:...  (escaped colons don't occur in our data)
    return cpe.split(":") if cpe else []


def match_configuration(installed: str | None, cfg: AffectedConfiguration) -> tuple[MatchDetailResult, str]:
    """Compare one installed version with one config. Caller has already checked vendor + product match."""
    if cfg.raw_cpe_complex:
        return "needs_verification", "advisory uses complex CPE logic (AND/OR platform conditions) we don't model"
    if installed is None or not installed.strip():
        return "needs_verification", "installed version is unknown in the asset inventory"

    v = parse_version(installed)
    if v is None:
        return "needs_verification", f"installed version '{installed}' is non-standard and can't be compared safely"

    parts = _cpe_parts(cfg.cpe)
    update = parts[6] if len(parts) > 6 else "*"
    if update not in ("*", "-", ""):
        # e.g. cpe:...:connect_secure:22.6:r2:...: the real version is "22.6 R2", which plain versions can't express.
        if len(parts) > 5 and _cannot_equal(v, parts[5]):
            return "confirmed_unaffected", f"installed {installed} is not the affected version {parts[5]} {update}"
        return "needs_verification", f"advisory version has an update qualifier '{update}' that needs manual comparison"

    bounds = {
        "start_including": cfg.version_start_including,
        "start_excluding": cfg.version_start_excluding,
        "end_including": cfg.version_end_including,
        "end_excluding": cfg.version_end_excluding,
    }
    has_bounds = any(b is not None for b in bounds.values())

    if not has_bounds:
        exact = cfg.exact_version or (parts[5] if len(parts) > 5 else None)
        if exact is None:
            hint = f" (text: '{cfg.versions_text}')" if cfg.versions_text else ""
            return "needs_verification", f"advisory gives no parseable version range{hint}"
        if exact in ("*", "-"):
            return "needs_verification", "advisory lists every version ('*') with no bounds; confirm with the vendor"
        ev = parse_version(exact)
        if ev is None:
            if _cannot_equal(v, exact):
                return "confirmed_unaffected", f"installed {installed} is not the affected version {exact}"
            return "needs_verification", f"advisory version '{exact}' is non-standard and can't be compared safely"
        if v == ev:
            return "confirmed_affected", f"installed {installed} equals affected version {exact}"
        return "confirmed_unaffected", f"installed {installed} is not the affected version {exact}"

    parsed = {k: parse_version(b) for k, b in bounds.items() if b is not None}
    bad = [bounds[k] for k, p in parsed.items() if p is None]
    if bad:
        return "needs_verification", f"advisory version bound(s) {bad} are non-standard and can't be compared safely"

    checks = {
        "start_including": lambda b: v >= b,
        "start_excluding": lambda b: v > b,
        "end_including": lambda b: v <= b,
        "end_excluding": lambda b: v < b,
    }
    symbols = {"start_including": ">=", "start_excluding": ">", "end_including": "<=", "end_excluding": "<"}
    rng = ", ".join(f"{symbols[k]} {bounds[k]}" for k in parsed)
    if all(checks[k](b) for k, b in parsed.items()):
        return "confirmed_affected", f"installed {installed} is inside the vulnerable range ({rng})"
    return "confirmed_unaffected", f"installed {installed} is outside the vulnerable range ({rng})"


def _same_product(sw: SoftwareItem, cfg: AffectedConfiguration) -> bool:
    return norm(sw.vendor) == norm(cfg.vendor) and norm(sw.product) == norm(cfg.product)


def contract_match_status(detail: MatchDetailResult, software: dict | None) -> str | None:
    """Map our 3-state answer onto the contract enum."""
    if detail == "confirmed_affected":
        return "confirmed"
    if detail == "needs_verification":
        # Unknown installed version = a human must look; anything else is a known-but-uncomparable value.
        return "requires_manual_review" if software and software.get("version") is None else "uncertain"
    return None


def match_asset(asset: Asset, threat: ThreatRecord) -> MatchResult:
    """Best answer for one asset across all its software and all the threat's configurations.

    One vulnerable range is enough for confirmed_affected (NVD lists one entry per release branch).
    confirmed_unaffected needs EVERY product-matching pair to be cleanly outside; any doubt -> needs_verification.
    """
    candidates: list[dict] = []
    best: tuple[MatchDetailResult, str, dict | None, dict | None] | None = None

    for sw in asset.software:
        for cfg in threat.affected_configurations:
            if not _same_product(sw, cfg):
                continue
            detail, reason = match_configuration(sw.version, cfg)
            sw_d, cfg_d = sw.model_dump(), cfg.model_dump()
            candidates.append({"software": sw_d, "configuration": cfg_d, "match_detail": detail, "reason": reason})
            if best is None or _RANK[detail] > _RANK[best[0]]:
                best = (detail, reason, sw_d, cfg_d)

    if best is None:
        reason = ("no software inventoried for this asset" if not asset.software
                  else "asset runs none of the affected vendor/product combinations")
        return MatchResult(asset.asset_id, threat.threat_id, "confirmed_unaffected", None, reason)

    detail, reason, sw_d, cfg_d = best
    if detail == "confirmed_unaffected" and len(candidates) > 1:
        reason = f"installed version is outside all {len(candidates)} vulnerable ranges (e.g. {reason})"
    return MatchResult(asset.asset_id, threat.threat_id, detail, contract_match_status(detail, sw_d),
                       reason, sw_d, cfg_d, candidates)


def match_threat(threat: ThreatRecord, assets: list[Asset]) -> list[MatchResult]:
    """Match one threat against every asset. Returns one result per asset (unaffected included)."""
    return [match_asset(a, threat) for a in assets]


def exposed(results: list[MatchResult]) -> list[MatchResult]:
    """Only the results worth an alert: confirmed_affected or needs_verification."""
    return [r for r in results if r.match_detail != "confirmed_unaffected"]
