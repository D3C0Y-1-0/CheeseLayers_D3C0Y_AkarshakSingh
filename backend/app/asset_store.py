"""In-memory asset inventory loaded from data/assets.json.

40 assets is small enough to keep in memory; every lookup below is a dict hit or a short scan.
"""
import json
from functools import lru_cache
from pathlib import Path

from .contracts import Asset

ASSETS_PATH = Path(__file__).resolve().parents[2] / "data" / "assets.json"


def _norm(s: str) -> str:
    # NVD vendor/product names are lowercase with underscores; normalise inputs the same way.
    return s.strip().lower().replace(" ", "_")


class AssetStore:
    def __init__(self, path: Path = ASSETS_PATH):
        raw = json.loads(path.read_text(encoding="utf-8"))
        self._assets: dict[str, Asset] = {}
        for item in raw:
            asset = Asset.model_validate(item)
            if asset.asset_id in self._assets:
                raise ValueError(f"duplicate asset_id {asset.asset_id} in {path}")
            self._assets[asset.asset_id] = asset

    def __len__(self) -> int:
        return len(self._assets)

    def all(self) -> list[Asset]:
        return list(self._assets.values())

    def get(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def by_sector(self, sector: str) -> list[Asset]:
        return [a for a in self._assets.values() if a.sector == sector]

    def by_product(self, vendor: str, product: str) -> list[Asset]:
        """Assets running any software with this vendor + product (case-insensitive)."""
        v, p = _norm(vendor), _norm(product)
        return [a for a in self._assets.values()
                if any(_norm(s.vendor) == v and _norm(s.product) == p for s in a.software)]

    def filter(self, sector: str | None = None, criticality: int | None = None,
               min_criticality: int | None = None, internet_facing: bool | None = None) -> list[Asset]:
        out = self.all()
        if sector is not None:
            out = [a for a in out if a.sector == sector]
        if criticality is not None:
            out = [a for a in out if a.criticality == criticality]
        if min_criticality is not None:
            out = [a for a in out if a.criticality >= min_criticality]
        if internet_facing is not None:
            out = [a for a in out if a.internet_facing == internet_facing]
        return out


@lru_cache(maxsize=1)
def _fixture_store() -> AssetStore:
    return AssetStore()


def get_asset_store() -> AssetStore:
    """Fresh overlay snapshot so inventory changes propagate across the two lab processes."""
    from sqlalchemy import select
    from sqlalchemy.exc import OperationalError
    from .database import SessionLocal
    from .models import InventoryOverride
    base = _fixture_store()
    try:
        with SessionLocal() as db:
            overlays = list(db.scalars(select(InventoryOverride)))
    except OperationalError as exc:
        # Pure matcher/asset tests can run before init_db; don't hide other DB failures.
        if "no such table: inventory_overrides" not in str(exc):
            raise
        overlays = []
    snapshot = AssetStore.__new__(AssetStore)
    snapshot._assets = dict(base._assets)
    for row in overlays:
        snapshot._assets[row.asset_id] = Asset.model_validate(row.data)
    return snapshot


get_asset_store.cache_clear = _fixture_store.cache_clear
