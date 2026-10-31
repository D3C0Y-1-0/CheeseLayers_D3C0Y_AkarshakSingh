"""One retrieval, one bounded generation, exact grounding checks, deterministic fallback."""
from .fallback import build_fallback_report
from .grounded import Completion, narrate
from .llm import LLMSettings
from .schemas import IncidentContext, InvestigationReport
from .tools import ReadOnlyTools

# The only fields the LLM may write. Evidence, CVEs, references, assessment and limitations stay template facts.
NARRATIVE = {"summary": "text", "why_relevant": "text", "recommended_actions": "list"}


async def investigate(incident_id: str, tools: ReadOnlyTools, *, settings: LLMSettings | None = None,
                      completion: Completion | None = None, lang: str = "en") -> InvestigationReport:
    ctx = IncidentContext.model_validate(tools.get_incident_context(incident_id))
    fallback = build_fallback_report(ctx)
    # Raw command lines/advisory bodies are never sent; narrate() also refuses instruction-like input.
    out = await narrate("investigation", ctx.model_dump(mode="json"), fallback.model_dump(mode="json"), NARRATIVE,
                        lang=lang, settings=settings, completion=completion)
    return InvestigationReport.model_validate(out)
