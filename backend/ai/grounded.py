"""Grounded narrative: the LLM may REWORD a deterministic template, never add facts.

Flow for every AI text (investigation, threat summary, CERT-In draft, translation):
  1. caller builds `facts` (stored data only) and a deterministic `template` (works offline, always valid)
  2. cache hit (same normalised input)      -> cached LLM wording, generated_by="llm_cached"
  3. LLM disabled / unconfigured / offline  -> template, generated_by="template"
  4. LLM output: only the narrative `fields` are taken; every identifier, version, IP and URL in them must already
     appear in the input; numeric/overclaim/command filters reject obvious inventions -> else template.
     These checks do not prove semantic accuracy. Evidence-only mode bypasses model/cache entirely.
Validated LLM output is cached in backend/data/cache/ai_reports/<sha256>.json, so the demo replays it offline.
"""
import asyncio
import hashlib
import json
import os
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

from . import llm
from .llm import LLMSettings, demo_mode

Completion = Callable[[str, LLMSettings], Awaitable[str]]
CACHE_DIR = Path(os.getenv("AI_CACHE_DIR", Path(__file__).resolve().parent.parent / "data" / "cache" / "ai_reports"))
BUDGET = 48000  # bytes, prompt and output
VOLATILE = {"retrieved_at", "ingested_at", "detected_at", "updated_at", "created_at", "generated_at",
            "fallback_reason", "generated_by", "validation", "time_of_detection"}  # change on replay, not facts

# Things a model must not invent. Each match in the output must be a substring of the input.
TOKENS = re.compile(r"https?://[^\s\"'<>)\]]+"  # URLs
                    r"|\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d[A-Z0-9]*\b"  # CVE-2024-1, PWR-FW-01, EVT-0001, ALR-1A2B, DEMO-VULN-001
                    r"|\bT\d{4}(?:\.\d{3})?\b"  # ATT&CK technique
                    r"|\b\d+(?:\.\d+){2,3}\b")  # versions/IPs; other numerical claims are checked separately below
NUMBERS = re.compile(r"(?<![\w])\d+(?:\.\d+)*(?:%)?")
OVERCLAIM = re.compile(r"zero[- ]?day|\bbreach(?:ed)?\b|confirmed\s+(?:compromise|exploitation|attack|intrusion)"
                       r"|(?:has|have|was|were)\s+been\s+(?:compromised|exploited|hacked)|\battributed\s+to\b", re.I)
COMMAND = re.compile(r"`|\$\(|\b(?:sudo|rm\s+-|curl|wget|powershell|chmod|bash|cmd\.exe)\b"
                     r"|\b(?:execute|run)\s+(?:a\s+|the\s+)?(?:shell|command|script)", re.I)
INJECTION = re.compile(r"ignore\s+(?:all\s+|previous\s+|prior\s+)*instructions|system\s*prompt|<\|.*?\|>"
                       r"|execute\s+(?:shell|command)", re.I)
REASONS = ("disabled", "offline_mode", "unconfigured", "timeout", "invalid_output", "provider_error")


def normalise(x):
    if isinstance(x, dict):
        return {k: normalise(v) for k, v in sorted(x.items()) if k not in VOLATILE}
    if isinstance(x, (list, tuple)):
        return [normalise(v) for v in x]
    return x


def cache_key(kind: str, facts: dict, template: dict, fields: tuple[str, ...], lang: str = "en") -> str:
    body = json.dumps({"kind": kind, "lang": lang, "fields": list(fields), "facts": normalise(facts),
                       "template": normalise(template)}, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(body.encode()).hexdigest()


def cache_get(key: str) -> dict | None:
    p = CACHE_DIR / f"{key}.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except (OSError, ValueError):
        return None


def cache_put(key: str, record: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CACHE_DIR / f"{key}.tmp"
    tmp.write_text(json.dumps(record, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(CACHE_DIR / f"{key}.json")


def disabled_reason(settings: LLMSettings | None) -> tuple[LLMSettings | None, str | None]:
    """Cloud only with explicit consent (LLM_ALLOW_CLOUD=true) AND a key. Same rule in and out of DEMO_MODE."""
    try:
        config = settings or LLMSettings.from_env()
    except ValueError:
        return None, "unconfigured"
    if config.provider == "template" or not config.allow_cloud:
        return config, "offline_mode" if demo_mode() else "disabled"
    if config.provider != "groq" or not config.api_key or not config.model:
        return config, "unconfigured"
    return config, None


def llm_status() -> dict:
    config, reason = disabled_reason(None)
    return {"cloud_enabled": reason is None, "provider": config.provider if config else None, "reason": reason,
            "cached_reports": len(list(CACHE_DIR.glob("*.json"))) if CACHE_DIR.exists() else 0}


LOOKALIKE = str.maketrans({c: "-" for c in "‐‑‒–—―−﹣－"}
                          | {c: " " for c in "     "} | {"­": "", "​": ""})


def plain(v):
    """Fold look-alike dashes/spaces to ASCII in model text (strings, or lists of strings)."""
    if isinstance(v, str):
        return unicodedata.normalize("NFKC", v).translate(LOOKALIKE)
    if isinstance(v, list):
        return [plain(x) for x in v]
    return v


def ungrounded(texts: list[str], corpus: str) -> list[str]:
    """Identifiers/versions/URLs in `texts` that do not appear in `corpus` (the model's input)."""
    bad = []
    for text in texts:
        for tok in TOKENS.findall(text):
            tok = tok.rstrip(".,;:")
            if tok and tok not in corpus:
                bad.append(tok)
    return sorted(set(bad))


def check(narrative: dict, fields: dict[str, str], corpus: str) -> tuple[list[str], list[str]]:
    """-> (problems, ungrounded tokens). `fields` = name -> 'text' | 'list'."""
    problems, texts = [], []
    for name, kind in fields.items():
        v = narrative.get(name)
        if kind == "list":
            if not isinstance(v, list) or not 1 <= len(v) <= 10 or not all(isinstance(s, str) and 0 < len(s) <= 500 for s in v):
                problems.append(f"{name}: expected 1-10 short strings")
                continue
            texts += v
        else:
            if not isinstance(v, str) or not 0 < len(v) <= 4000:
                problems.append(f"{name}: expected text up to 4000 chars")
                continue
            texts.append(v)
    bad = ungrounded(texts, corpus)
    if bad:
        problems.append("identifiers/versions/URLs not in the input: " + ", ".join(bad[:10]))
    joined = "\n".join(texts)
    if OVERCLAIM.search(joined):
        problems.append("unsupported claim (compromise/exploitation/zero-day/attribution)")
    source_numbers = set(NUMBERS.findall(corpus))
    if any(n not in source_numbers for n in NUMBERS.findall(joined)):
        problems.append("numeric claim not present in supplied facts")
    if COMMAND.search(joined):
        problems.append("command or execution instruction")
    return problems, bad


def _validation(passed, note, checked=0, rejected=()) -> dict:
    return {"passed": passed, "checked_tokens": checked, "rejected_tokens": list(rejected), "note": note}


TEMPLATE_NOTE = "Deterministic template built only from stored facts; no language model involved."


async def narrate(kind: str, facts: dict, template: dict, fields: dict[str, str], *, lang: str = "en",
                  settings: LLMSettings | None = None, completion: Completion | None = None,
                  instruction: str | None = None, evidence_only: bool = False) -> dict:
    """-> template updated with LLM wording (or not) + generated_by, validation, fallback_reason.

    `template` is the full deterministic object; only keys in `fields` may change. If the model echoes any other
    template key with a different value, the output is rejected (it tried to change a fact)."""
    names = tuple(fields)
    key = cache_key(kind, facts, template, names, lang)
    corpus = json.dumps({"facts": facts, "template": template}, default=str, ensure_ascii=False)

    def fallback(reason, validation):
        return template | {"generated_by": "template", "fallback_reason": reason, "validation": validation}

    if evidence_only:
        return fallback("disabled", _validation(None, "Evidence-only mode: deterministic stored-fact template; model and model cache bypassed. Analyst review required."))
    hit = cache_get(key)
    if hit and isinstance(hit.get("narrative"), dict):
        narrative = {k: plain(hit["narrative"].get(k)) for k in names}
        problems, bad = check(narrative, fields, corpus)
        if not problems and set(hit["narrative"]) == set(names):
            return template | narrative | {"generated_by": "llm_cached", "fallback_reason": None,
                "validation": _validation(True, "Cached narrative rechecked against current facts; analyst review required.")}
        return fallback("invalid_output", _validation(False, "Cached output failed current checks; template shown.", rejected=bad))
    config, reason = disabled_reason(settings)
    if reason:
        return fallback(reason, _validation(None, TEMPLATE_NOTE))
    if INJECTION.search(corpus):
        return fallback("invalid_output", _validation(False, "Instruction-like text in stored data; LLM not called."))
    prompt = json.dumps({"task": kind, "language": lang, "facts": facts, "template": template,
                         "return_fields": list(names),
                         "instruction": instruction or (
                             "Rewrite only return_fields as clear analyst prose for a SOC dashboard. Use only facts "
                             "given here. Copy every ID, version, IP and URL exactly; add none. Say 'unknown' where a "
                             "fact is null. Do not claim compromise or exploitation unless the facts state it. No "
                             "commands. Return one JSON object with exactly return_fields.")},
                        default=str, ensure_ascii=False)
    if len(prompt.encode()) > BUDGET:
        return fallback("invalid_output", _validation(False, "Input exceeds the LLM byte budget; LLM not called."))
    try:
        output = await asyncio.wait_for((completion or llm.complete_json)(prompt, config), timeout=config.timeout_seconds)
        if len(output.encode()) > BUDGET:
            raise ValueError("oversized output")
        data = json.loads(output)
        if not isinstance(data, dict):
            raise ValueError("not an object")
    except (asyncio.TimeoutError, TimeoutError):
        return fallback("timeout", _validation(False, "LLM timed out; template shown."))
    except (ValueError, TypeError, KeyError):
        return fallback("invalid_output", _validation(False, "LLM returned malformed JSON; template shown."))
    except Exception:  # provider errors can echo keys/payloads: never log or return them
        return fallback("provider_error", _validation(False, "LLM provider error; template shown."))
    changed = [k for k, v in data.items() if k not in names and k not in VOLATILE and k in template
               and json.dumps(v, sort_keys=True, default=str) != json.dumps(template[k], sort_keys=True, default=str)]
    # Look-alike characters (non-breaking hyphen U+2011, en dash, NBSP...) would hide identifiers from the grounding
    # check ("GOV‑VPN‑01" is not "GOV-VPN-01"), so fold them to ASCII before checking and before display.
    narrative = {k: plain(data.get(k)) for k in names}
    # Normalise list fields to the validator's shape (1-10 strings, <=500 chars each) instead of discarding the
    # whole narrative: a capable model sometimes returns one combined string, or more/longer items than allowed.
    # Word-boundary truncation never splits an identifier; the grounding, overclaim, numeric and command checks
    # below still run on what remains.
    for name, kind in fields.items():
        if kind != "list":
            continue
        value = narrative.get(name)
        if isinstance(value, str) and value.strip():  # single string -> one action
            value = [value]
        if isinstance(value, list):
            trimmed = []
            for s in value:
                if not isinstance(s, str) or not s.strip():
                    continue
                trimmed.append(s[:500].rsplit(" ", 1)[0] if len(s) > 500 else s)
                if len(trimmed) == 10:
                    break
            narrative[name] = trimmed
    problems, bad = check(narrative, fields, corpus)
    if changed:
        problems.append("tried to change factual fields: " + ", ".join(changed))
    checked = len(TOKENS.findall(" ".join(json.dumps(v, ensure_ascii=False) for v in narrative.values())))
    if problems:
        return fallback("invalid_output", _validation(False, "LLM output rejected: " + "; ".join(problems) + ". Template shown.",
                                                      checked, bad))
    validation = _validation(True, f"All {checked} identifiers/versions/URLs found in supplied input; numeric and claim filters passed. "
                                   "These checks do not prove semantic accuracy; analyst review required.", checked)
    cache_put(key, {"key": key, "kind": kind, "lang": lang, "model": config.model,
                    "created_at": datetime.now(timezone.utc).isoformat(), "narrative": narrative,
                    "validation": validation})
    return template | narrative | {"generated_by": "llm", "fallback_reason": None, "validation": validation}
