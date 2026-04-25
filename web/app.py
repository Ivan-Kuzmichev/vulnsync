"""FastAPI application — interactive demonstration of the integrated methodology."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from jinja2 import Template

from code_analysis import analyze_code
from integration import integrate
from log_analysis import analyze_logs


_BASE = Path(__file__).resolve().parent
_SAMPLES = _BASE.parent / "samples"
_TEMPLATE = Template((_BASE / "templates" / "index.html").read_text(encoding="utf-8"))

app = FastAPI(title="Интегрированный анализ уязвимостей веб-приложений")


def _read(name: str) -> str:
    path = _SAMPLES / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    html = _TEMPLATE.render(
        default_code=_read("vulnerable_app.py"),
        default_logs=_read("access.log"),
    )
    return HTMLResponse(html)


class AnalyzeRequest(BaseModel):
    code: str
    logs: str


@app.post("/analyze")
async def analyze(payload: AnalyzeRequest) -> JSONResponse:
    vulnerabilities = analyze_code(payload.code)
    log_report = analyze_logs(payload.logs)
    integrated = integrate(vulnerabilities, log_report)

    return JSONResponse(
        {
            "code": [v.to_dict() for v in vulnerabilities],
            "logs": {
                "total_events": log_report["total_events"],
                "top_attack": log_report["top_attack"],
                "aggregate_score": log_report["aggregate_score"],
                "anomalies": [a.to_dict() for a in log_report["anomalies"]],
            },
            "integration": integrated.to_dict(),
        }
    )


@app.get("/samples/{name}")
async def get_sample(name: str) -> JSONResponse:
    allowed = {
        "vulnerable_code": "vulnerable_app.py",
        "vulnerable_logs": "access.log",
        "clean_code": "clean_app.py",
        "clean_logs": "clean_access.log",
        "mixed_code": "mixed_app.py",
        "mixed_logs": "mixed_access.log",
        "admin_code": "admin_panel.py",
        "admin_logs": "admin_access.log",
    }
    if name not in allowed:
        return JSONResponse({"error": "unknown sample"}, status_code=404)
    return JSONResponse({"content": _read(allowed[name])})
