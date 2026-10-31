"""Write the scoring formula, generated from backend/app/scoring.py CONFIG, into the docs that show it.

    backend/.venv/bin/python scripts/gen_scoring_doc.py

Replaces the text between the BEGIN/END GENERATED markers. backend/tests/test_scoring_doc.py fails if they drift.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.scoring import DOC_BEGIN, DOC_END, explain_markdown  # noqa: E402

TARGETS = [ROOT / "docs" / "SCORING_AND_AI.md", ROOT / "CLAUDE.md"]


def render(text: str) -> str:
    start, end = text.index(DOC_BEGIN) + len(DOC_BEGIN), text.index(DOC_END)
    return text[:start] + "\n" + explain_markdown() + "\n" + text[end:]


if __name__ == "__main__":
    for path in TARGETS:
        path.write_text(render(path.read_text(encoding="utf-8")), encoding="utf-8")
        print(f"updated {path.relative_to(ROOT)}")
