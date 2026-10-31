"""Explainable AI for the Isolation Forest (SW-ML-001), per incident, plus a downloadable PDF report.

  GET /api/ml/model                              model card: what each sensor's model relies on overall (mean |SHAP|)
  GET /api/alerts/{alert_id}/ml-explanation      SHAP explanation of every ML-flagged minute in the incident
  GET /api/alerts/{alert_id}/ml-explanation.pdf  the same as a detailed PDF report (download)

All numbers come from shadow_watch/explain.py (SHAP TreeExplainer on the live fitted model). Read-only.
"""
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from shadow_watch import explain as xai
from shadow_watch import ml
from shadow_watch.normalize import EVENT

from .correlator import AlertRow, EventRow
from .database import get_db

router = APIRouter(tags=["explainable AI"])


def authorised(request: Request, row: AlertRow, alert_id: str) -> None:
    """Same rule as the evidence endpoint: demo mode = simulated incidents only; otherwise the authorised factory."""
    from ai.llm import demo_mode
    if demo_mode():
        if not row.data.get("is_simulated"):
            raise HTTPException(403, "demo mode permits simulated evidence only")
        return
    factory = getattr(request.app.state, "investigation_tools_factory", None)
    try:
        if factory is None:
            raise PermissionError
        factory(request, alert_id).get_incident_context(alert_id)
    except PermissionError:
        raise HTTPException(403, "evidence access denied") from None


def model_card() -> dict:
    sensors = []
    for source, kind in ml.SENSORS.items():
        fitted = ml.model(kind)
        if fitted is None:
            continue
        _, _, n, last = fitted
        sensors.append({"sensor": kind, "source": source, "sensor_name": xai.SENSOR_NAME[kind], "training_minutes": n,
                        "trained_until": last, "features": [xai.LABELS[f] for f in ml.FEATURES[kind]],
                        "global_importance": xai.global_importance(kind)})
    return {"detector_id": "SW-ML-001", "model": "Isolation Forest (scikit-learn)", "config": ml.CONFIG,
            "explainer": "SHAP TreeExplainer", "sensors": sensors, "method": xai.METHOD, "limitations": xai.LIMITATIONS}


@router.get("/api/ml/model")
def ml_model() -> dict:
    """Model card for the anomaly detector: training data, settings and global feature importance (mean |SHAP|)."""
    return model_card()


def ml_items(db: Session, a: dict) -> list[dict]:
    """SHAP explanations for every ML-flagged (SW-ML-001) event in an alert's stored evidence. Read-only."""
    records = db.scalars(select(EventRow).where(EventRow.event_id.in_(a.get("evidence_ids", [])))
                         .order_by(EventRow.timestamp, EventRow.event_id).limit(100))
    items = []
    for r in records:
        found = [f for f in r.data.get("shadow_findings", []) if f.get("detector_id") == "SW-ML-001"]
        if not found or not r.data.get("normalized_event"):
            continue
        event = EVENT.validate_python(r.data["normalized_event"])
        e = xai.explain_event(event)
        if e:
            items.append({"event_id": event.event_id, "asset_id": event.asset_id,
                          "observed_at": event.observed_at.isoformat(), "finding_id": found[0]["finding_id"],
                          "finding_reason": found[0].get("reason")} | e)
    return items


def explanation(db: Session, request: Request, alert_id: str) -> dict:
    row = db.get(AlertRow, alert_id)
    if row is None:
        raise HTTPException(404, f"alert {alert_id} not found")
    authorised(request, row, alert_id)
    a = row.data
    items = ml_items(db, a)
    return {"alert_id": alert_id, "title": a.get("title"), "priority": a.get("priority"),
            "is_simulated": a.get("is_simulated", False), "ml_findings": len(items), "explanations": items,
            "note": None if items else "No Isolation Forest (SW-ML-001) finding in this incident's evidence.",
            "model": model_card(), "generated_at": datetime.now(timezone.utc).isoformat()}


@router.get("/api/alerts/{alert_id}/ml-explanation")
def alert_ml_explanation(alert_id: str, request: Request, db: Session = Depends(get_db)) -> dict:
    """Why the Isolation Forest flagged each minute in this incident: SHAP contributions in plain language."""
    return explanation(db, request, alert_id)


@router.get("/api/alerts/{alert_id}/ml-explanation.pdf", responses={200: {"content": {"application/pdf": {}}}})
def alert_ml_explanation_pdf(alert_id: str, request: Request, db: Session = Depends(get_db)) -> Response:
    """Detailed explanation report as a PDF (verdict, per-feature SHAP chart, plain-language reasons, method, limits)."""
    data = explanation(db, request, alert_id)
    return Response(render_pdf(data), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="ml-explanation-{alert_id}.pdf"'})


# --- PDF ------------------------------------------------------------------------------------------------------------
def _bars(features: list[dict], width: float):
    """Horizontal SHAP bar chart: red = pushed towards unusual, blue = towards normal."""
    from reportlab.graphics.shapes import Drawing, Line, Rect, String
    from reportlab.lib import colors
    row_h, label_w = 18, 215
    d = Drawing(width, row_h * len(features) + 24)
    span = max(abs(f["shap_value"]) for f in features) or 1.0
    mid = label_w + (width - label_w) / 2
    half = (width - label_w) / 2 - 40
    d.add(Line(mid, 4, mid, row_h * len(features) + 8, strokeColor=colors.HexColor("#9aa3b5"), strokeWidth=0.6))
    for i, f in enumerate(features):
        y = row_h * (len(features) - i - 1) + 10
        w = abs(f["shap_value"]) / span * half
        unusual = f["toward"] == "unusual"
        x = mid - w if unusual else mid
        d.add(Rect(x, y, w, 11, fillColor=colors.HexColor("#e2574c" if unusual else "#3d8bff"), strokeColor=None))
        d.add(String(0, y + 2, f["label"][:44], fontSize=7.5, fillColor=colors.HexColor("#1f2937")))
        tx = x - 4 if unusual else x + w + 4
        d.add(String(tx, y + 2, f"{f['shap_value']:+.2f}", fontSize=7.5, textAnchor="end" if unusual else "start",
                     fillColor=colors.HexColor("#374151")))
    d.add(String(mid - 6, row_h * len(features) + 12, "<- more unusual", fontSize=7, textAnchor="end",
                 fillColor=colors.HexColor("#b91c1c")))
    d.add(String(mid + 6, row_h * len(features) + 12, "more normal ->", fontSize=7, fillColor=colors.HexColor("#1d4ed8")))
    return d


def render_pdf(data: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape as esc

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm,
                            bottomMargin=14 * mm, title=f"ML explanation {data['alert_id']}", author="Vectra")
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=15, textColor=colors.HexColor("#0f3bc4"), spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=11, textColor=colors.HexColor("#0f3bc4"), spaceBefore=8)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12.5)
    small = ParagraphStyle("s", parent=body, fontSize=8, leading=11, textColor=colors.HexColor("#4b5563"))
    width = A4[0] - 32 * mm
    out = [Paragraph("Why the anomaly model flagged this incident", h1),
           Paragraph(esc(f"Incident {data['alert_id']} · {data.get('title') or ''} · priority {data.get('priority')}"
                         + (" · simulated replay of real sensor data" if data.get("is_simulated") else "")), small),
           Paragraph(esc(f"Generated {data['generated_at'][:19]} UTC by Vectra. Detector SW-ML-001 (Isolation Forest), "
                         "explained with SHAP. Every number is computed from the live model; no language model involved."),
                     small), Spacer(1, 6)]
    if not data["explanations"]:
        out.append(Paragraph(esc(data["note"]), body))
    for i, e in enumerate(data["explanations"], 1):
        out += [Paragraph(esc(f"{i}. Minute {e['observed_at'][:16].replace('T', ' ')} on {e['asset_id']} "
                              f"(sensor: {e['sensor_name']})"), h2),
                Paragraph("<b>In simple words:</b> " + esc(e["summary"]), body), Spacer(1, 4),
                _bars(e["features"], width),
                Paragraph(esc(f"Bars: SHAP contribution of each feature to the isolation path length (baseline "
                              f"{e['baseline_path_length']} -> this minute {e['path_length']}). Shorter path = easier "
                              f"to isolate = more unusual. Outlier score {e['outlier_score']} (below 0 = flagged)."), small),
                Spacer(1, 4)]
        rows = [["Feature", "This minute", "Usual (median)", "Percentile", "SHAP", "Effect", "Share"]]
        rows += [[f["label"], f"{f['value']:g}", f"{f['training_median']:g}", f"{f['training_percentile']:g}%",
                  f"{f['shap_value']:+.3f}", {"unusual": "towards unusual", "normal": "towards normal", "none": "no effect"}[f["toward"]],
                  f"{f['share_pct']:g}%"] for f in e["features"]]
        t = Table(rows, colWidths=[width * x for x in (0.30, 0.11, 0.13, 0.11, 0.09, 0.15, 0.08)], repeatRows=1)
        t.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 7.5), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf1fd")),
                               ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c7d2e3")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        out += [t, Spacer(1, 4), Paragraph("<b>Feature by feature:</b>", body)]
        out += [Paragraph("• " + esc(f["sentence"]), body) for f in e["features"]]
    card = data["model"]
    out += [Paragraph("About the model", h2),
            Paragraph(esc(f"{card['model']}, settings {card['config']}. Explainer: {card['explainer']}."), body)]
    for s in card["sensors"]:
        imp = "; ".join(f"{g['label']} {g['share_pct']:g}%" for g in s["global_importance"])
        out.append(Paragraph(esc(f"{s['sensor_name']}: trained on {s['training_minutes']:,} real minutes up to "
                                 f"{s['trained_until']}. What it relies on overall (mean |SHAP|): {imp}."), body))
    out.append(Paragraph("How this explanation was produced", h2))
    out += [Paragraph("• " + esc(m), body) for m in card["method"]]
    out.append(Paragraph("Limitations", h2))
    out += [Paragraph("• " + esc(m), body) for m in card["limitations"]]
    out.append(Paragraph(esc("Analyst review required. This report explains a statistical model's output and is not a "
                             "finding of compromise."), small))
    doc.build(out)
    return buf.getvalue()
