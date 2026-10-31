"""Export additive Member 4 DTOs for teammate validation without editing shared contracts."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from pydantic import TypeAdapter
from ai.schemas import IncidentContext, InvestigationReport
from shadow_watch.demo import DemoRequest, DemoResult
from shadow_watch.schemas import DetectionFinding, NormalizedEvent


if __name__ == "__main__":
    schemas = {"NormalizedEvent": TypeAdapter(NormalizedEvent).json_schema(),
               **{dto.__name__: dto.model_json_schema() for dto in
                  (DetectionFinding, IncidentContext, InvestigationReport, DemoRequest, DemoResult)}}
    path = ROOT / "docs/member4_schemas.json"
    path.write_text(json.dumps(schemas, indent=2) + "\n", encoding="utf-8")
    print(f"Exported {len(schemas)} Member 4 schemas to {path.name}")
