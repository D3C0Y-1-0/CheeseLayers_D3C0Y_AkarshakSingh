from fastapi import APIRouter, HTTPException, Request

from ai.investigator import investigate
from ai.llm import demo_mode
from ai.schemas import InvestigationReport
from ai.tools import ID, InvestigationScope, ReadOnlyTools
from .shadow_watch import get_demo_adapter

router = APIRouter(tags=["SOC Investigation"])


@router.post("/api/alerts/{id}/investigate", response_model=InvestigationReport)
async def investigate_alert(id: str, request: Request):
    try:
        ID.validate_python(id)
    except ValueError:
        raise HTTPException(422, "invalid alert ID") from None
    try:
        if demo_mode() and id.startswith("SW-DEMO-"):
            provider = get_demo_adapter(request)
            ctx = provider.get_incident(id)
            tools = ReadOnlyTools(provider, InvestigationScope(id, frozenset(ctx.asset_ids), demo_only=True))
        else:
            # Member 2/3 must authenticate request and return scoped tools here.
            # No implicit production access to arbitrary alerts or assets.
            factory = getattr(request.app.state, "investigation_tools_factory", None)
            if factory is None:
                raise HTTPException(503, "Member 3 incident provider and authorisation adapter are not connected")
            tools = factory(request, id)
        return await investigate(id, tools)
    except KeyError:
        raise HTTPException(404, "alert not found in authorised scope") from None
    except PermissionError:
        raise HTTPException(403, "incident outside authorised scope") from None
