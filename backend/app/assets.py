from fastapi import APIRouter, HTTPException, Query

from .asset_store import get_asset_store
from .contracts import Asset, Sector

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("", response_model=list[Asset])
def list_assets(
    sector: Sector | None = None,
    criticality: int | None = Query(None, ge=1, le=5, description="Exact criticality"),
    min_criticality: int | None = Query(None, ge=1, le=5, description="Criticality at least this"),
    internet_facing: bool | None = None,
) -> list[Asset]:
    return get_asset_store().filter(sector=sector, criticality=criticality,
                                    min_criticality=min_criticality, internet_facing=internet_facing)


@router.get("/{asset_id}", response_model=Asset)
def get_asset(asset_id: str) -> Asset:
    asset = get_asset_store().get(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"asset {asset_id} not found")
    return asset
