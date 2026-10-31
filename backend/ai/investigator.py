"""One retrieval, one bounded generation, exact grounding checks, deterministic fallback."""
import asyncio
import json
import re
from collections import Counter
from typing import Awaitable, Callable

from pydantic import ValidationError

from .fallback import build_fallback_report
from .llm import LLMSettings, complete_json, demo_mode
from .schemas import IncidentContext, InvestigationReport
from .tools import ReadOnlyTools

Completion = Callable[[str, LLMSettings], Awaitable[str]]


async def investigate(incident_id: str, tools: ReadOnlyTools, *, settings: LLMSettings | None = None,
                      completion: Completion = complete_json) -> InvestigationReport:
    ctx = IncidentContext.model_validate(tools.get_incident_context(incident_id))
    fallback = build_fallback_report(ctx)
    try:
        config = settings or LLMSettings.from_env()
    except ValueError:
        return fallback.model_copy(update={"fallback_reason": "unconfigured"})
    reason = None
    if demo_mode():
        reason = "offline_mode"
    elif config.provider == "template" or not config.allow_cloud:
        reason = "disabled"
    elif config.provider != "groq" or not config.api_key or not config.model:
        reason = "unconfigured"
    if reason:
        return fallback.model_copy(update={"fallback_reason": reason})
    # Raw command lines/advisory bodies are never sent. Known instruction-like input
    # additionally disables generation. Exact output checks remain the main boundary.
    serialized = ctx.model_dump_json()
    if re.search(r"ignore\s+(all\s+|previous\s+|prior\s+)*instructions|system\s*prompt|<\|.*?\|>|execute\s+(?:shell|command)", serialized, re.I):
        return fallback.model_copy(update={"fallback_reason": "invalid_output"})
    compact = (f"{len(ctx.evidence) + len(ctx.additional_evidence)} stored observations on {', '.join(ctx.asset_ids) or 'unknown assets'} require analyst review. "
               "Compromise is not confirmed.")
    permitted_summaries = [fallback.summary, compact]
    expected = fallback.model_dump(mode="json")
    expected["generated_by"] = "llm"
    prompt = json.dumps({"report": expected, "permitted_summaries": permitted_summaries,
                         "instruction": "Return the report object with generated_by=llm. Select a permitted summary and reorder recommended_actions only."})
    if len(prompt.encode()) > 48000:
        return fallback.model_copy(update={"fallback_reason": "invalid_output"})
    try:
        output = await asyncio.wait_for(completion(prompt, config), timeout=config.timeout_seconds)
        if len(output.encode()) > 48000:
            raise ValueError("oversized output")
        report = InvestigationReport.model_validate_json(output)
        candidate = report.model_dump(mode="json")
        # No invented facts, dropped evidence, CVEs, references, priorities or patches.
        if report.summary not in permitted_summaries:
            raise ValueError("unsupported narrative")
        if Counter(report.recommended_actions) != Counter(fallback.recommended_actions):
            raise ValueError("unsupported remediation")
        for field in expected:
            if field not in {"summary", "recommended_actions"} and candidate[field] != expected[field]:
                raise ValueError("unsupported factual field")
        return report
    except (asyncio.TimeoutError, TimeoutError):
        return fallback.model_copy(update={"fallback_reason": "timeout"})
    except (ValidationError, ValueError, TypeError, KeyError):
        return fallback.model_copy(update={"fallback_reason": "invalid_output"})
    except Exception:
        # Provider exception strings can contain keys or payloads; do not echo or log them.
        return fallback.model_copy(update={"fallback_reason": "provider_error"})
