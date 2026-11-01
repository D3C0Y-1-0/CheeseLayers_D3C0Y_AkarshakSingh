"""?lang=hi: machine-translate ONLY narrative fields of an already-grounded English result.

IDs, versions, URLs and commands must survive unchanged (same grounding check: every token in the Hindi text must
exist in the English input). No LLM -> English is returned with a note. Translations are cached like reports.
"""
from .grounded import narrate

MT_LABEL = "Machine translation — verify before use"


async def localise(kind: str, facts: dict, template: dict, fields: dict[str, str], lang: str = "en", **kw) -> dict:
    english = await narrate(kind, facts, template, fields, **kw)
    if lang == "en":
        return english | {"language": "en"}
    source = {k: english[k] for k in fields}
    out = await narrate(f"{kind}:translate", source, english, fields, lang=lang, instruction=(
        "Translate return_fields from English to Hindi (Devanagari). Translate narrative only: copy every CVE ID, "
        "asset ID, evidence ID, ATT&CK ID, version, IP address, URL, product name and command exactly as written. "
        "Add nothing and drop nothing. Return one JSON object with exactly return_fields."), **kw)
    if out["generated_by"] == "template":  # translation unavailable or rejected: English, honestly labelled
        return english | {"language": "en", "requested_language": lang, "translation": {
            "status": "unavailable", "note": ("Evidence-only mode bypasses model translation; showing English."
                if kw.get("evidence_only") else f"Hindi translation needs the cloud LLM ({out['fallback_reason']}); showing English."),
            "validation": out["validation"]}}
    return english | {k: out[k] for k in fields} | {"language": lang, "translation": {
        "status": "machine_translated", "label": MT_LABEL, "generated_by": out["generated_by"],
        "validation": out["validation"]}}
