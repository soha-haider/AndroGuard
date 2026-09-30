"""Web API + UI.  Run: uvicorn app.api:app   then open http://127.0.0.1:8000"""
import re
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, Response
from app.database import Scan, Session
from app.modules.m4_risk_engine.report import render_html, render_pdf
from app.pipeline import scan

MAX_UPLOAD = 300 * 1024 * 1024
UPLOADS = Path(tempfile.gettempdir()) / "androguard_uploads"
UPLOADS.mkdir(exist_ok=True)
# ponytail: one in-process worker (jadx needs GBs of RAM). Move to Redis + RQ/Celery workers when scans must
# survive restarts or run on several machines.
worker = ThreadPoolExecutor(max_workers=1)
app = FastAPI(title="AndroGuard")

with Session() as s:  # scans that were queued or running when the server stopped will never finish
    s.query(Scan).filter(Scan.status.in_(["queued", "running"])).update(
        {"status": "failed", "error": "The server restarted during this scan"})
    s.commit()


def _update(scan_id: int, **fields):
    with Session() as s:
        s.query(Scan).filter_by(id=scan_id).update(fields)
        s.commit()


def _run(scan_id: int, path: Path, name: str):
    try:
        _update(scan_id, status="running")
        report = scan(str(path), progress=lambda msg: _update(scan_id, progress=msg[:255]))
        report["file"] = name  # the pipeline only saw the server-chosen temp name
        _update(scan_id, status="done", sha256=report["sha256"], report=report, progress="Done",
                finished_at=datetime.now(timezone.utc))
    except Exception as e:  # any failure is shown to the user instead of leaving the scan stuck
        _update(scan_id, status="failed", error=str(e)[-2000:], finished_at=datetime.now(timezone.utc))
    finally:
        path.unlink(missing_ok=True)  # privacy by design: the uploaded package never outlives its scan


def _summary(row: Scan) -> dict:
    report = row.report or {}
    return {"id": row.id, "filename": row.filename, "status": row.status, "progress": row.progress,
            "error": row.error, "sha256": row.sha256, "risk": report.get("risk"),
            "findings": len(report.get("findings", [])),
            "created_at": row.created_at.isoformat() if row.created_at else None}


def _get(scan_id: int, done: bool = False) -> Scan:
    with Session() as s:
        row = s.get(Scan, scan_id)
    if row is None:
        raise HTTPException(404, "Scan not found")
    if done and row.status != "done":
        raise HTTPException(409, "The scan has not finished")
    return row


@app.post("/api/scans", status_code=202)
async def create_scan(file: UploadFile = File(...)):
    name = Path(file.filename or "").name
    if not re.fullmatch(r"[\w .()\[\]-]{1,200}\.(apk|aab)", name, re.IGNORECASE):
        raise HTTPException(400, "Upload an .apk or .aab file")
    path = UPLOADS / f"{uuid.uuid4().hex}{Path(name).suffix.lower()}"  # server-chosen name reaches the tools
    size = 0
    with open(path, "wb") as out:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > MAX_UPLOAD:
                break
            out.write(chunk)
    if size > MAX_UPLOAD:
        path.unlink(missing_ok=True)
        raise HTTPException(413, "The file is larger than 300 MB")
    with Session() as s:
        row = Scan(filename=name, status="queued", progress="Waiting for the scanner")
        s.add(row)
        s.commit()
        scan_id = row.id
    worker.submit(_run, scan_id, path, name)
    return {"id": scan_id}


@app.get("/api/scans")
def list_scans():
    with Session() as s:
        return [_summary(r) for r in s.query(Scan).order_by(Scan.id.desc()).limit(100)]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    row = _get(scan_id)
    return {**_summary(row), "report": row.report}


@app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: int):
    return render_html(_get(scan_id, done=True).report)


@app.get("/api/scans/{scan_id}/report.pdf")
def report_pdf(scan_id: int):
    row = _get(scan_id, done=True)
    try:
        pdf = render_pdf(render_html(row.report))
    except RuntimeError as e:
        raise HTTPException(501, str(e))
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(row.filename).stem)  # headers are latin-1: no Unicode names here
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{safe}-androguard.pdf"'})


@app.get("/", response_class=HTMLResponse)
def index():
    return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
