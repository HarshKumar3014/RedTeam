import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from aegis import ReportCard
from aegis.report import export_html

app = FastAPI(title="Aegis — LLM Security Audit Dashboard")

_current_report: Optional[ReportCard] = None


class LoadRequest(BaseModel):
    path: str


@app.get("/", response_class=HTMLResponse)
async def index():
    if _current_report is None:
        return HTMLResponse("<html><body style='background:#0d1117;color:#00ff88;font-family:monospace;padding:48px'>"
                            "<h1>No report loaded.</h1><p>POST to /api/load with {\"path\": \"report.json\"}</p>"
                            "</body></html>")
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        tmp = f.name
    try:
        export_html(_current_report, tmp)
        return HTMLResponse(Path(tmp).read_text())
    finally:
        os.unlink(tmp)


@app.get("/api/report")
async def get_report():
    if _current_report is None:
        raise HTTPException(status_code=404, detail="No report loaded")
    return JSONResponse(json.loads(_current_report.model_dump_json()))


@app.post("/api/load")
async def load_report(req: LoadRequest):
    global _current_report
    p = Path(req.path).resolve()
    # Restrict to JSON files under the working directory
    try:
        p.relative_to(Path.cwd())
    except ValueError:
        raise HTTPException(status_code=400, detail="Path must be within the current working directory")
    if p.suffix.lower() != ".json":
        raise HTTPException(status_code=400, detail="Only .json report files are supported")
    if not p.exists():
        raise HTTPException(status_code=404, detail="File not found")
    try:
        _current_report = ReportCard.model_validate_json(p.read_text())
        return {"status": "ok", "model": _current_report.model_id}
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to parse report: invalid report format")


def serve(report: ReportCard, host: str = "127.0.0.1", port: int = 8080):
    global _current_report
    _current_report = report
    import uvicorn
    uvicorn.run(app, host=host, port=port)
