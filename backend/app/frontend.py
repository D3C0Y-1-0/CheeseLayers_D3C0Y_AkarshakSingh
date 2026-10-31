"""Serve the built React app and its history routes from the same origin as the API."""
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
router = APIRouter()


@router.get("/{path:path}", include_in_schema=False)
def frontend(path: str):
    if path == "health" or path.startswith(("api/", "docs", "redoc", "openapi")) or path == "api":
        raise HTTPException(404, "unknown API endpoint")
    target = (DIST / path).resolve()
    if not target.is_relative_to(DIST.resolve()) or any(p.startswith(".") for p in Path(path).parts):
        raise HTTPException(404, "not found")
    if target.is_file():
        return FileResponse(target)
    if Path(path).suffix:
        raise HTTPException(404, "asset not found")
    index = DIST / "index.html"
    if not index.is_file():
        raise HTTPException(503, "frontend build missing; run npm run build in frontend/")
    return FileResponse(index, headers={"Cache-Control": "no-cache"})
