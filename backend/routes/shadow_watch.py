from fastapi import APIRouter, HTTPException, Request

from ai.llm import demo_mode
from shadow_watch.demo import DemoAdapter, DemoRequest, DemoResult, HandoffUnavailable

router = APIRouter(tags=["Shadow Watch"])


def get_demo_adapter(request: Request) -> DemoAdapter:
    # Initialised once during app construction; application-scoped for isolated tests.
    return request.app.state.shadow_demo_adapter


@router.post("/api/demo/inject-behaviour", response_model=DemoResult)
def inject_behaviour(body: DemoRequest, request: Request):
    if not demo_mode():
        raise HTTPException(404, "demo endpoint unavailable")
    try:
        sink = getattr(request.app.state, "shadow_finding_sink", None)
        return get_demo_adapter(request).replay(body, sink=sink)
    except (ValueError, FileNotFoundError):
        raise HTTPException(503, "synthetic fixtures unavailable or invalid; regenerate them") from None
    except HandoffUnavailable:
        raise HTTPException(503, "Member 3 handoff unavailable; retry with the same run_id") from None
