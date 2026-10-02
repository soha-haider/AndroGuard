"""Web API + site.  Run: uvicorn app.api:app   then open http://127.0.0.1:8000
Superadmin: python -m app.manage create-superadmin you@example.com"""
import re
import tempfile
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func
from app import auth
from app.database import AuthSession, Scan, Session, User, now
from app.modules.m3_input_processor.extractor import stop_tools
from app.modules.m4_risk_engine.report import render_html, render_pdf
from app.pipeline import scan

MAX_UPLOAD = 300 * 1024 * 1024
FREE_SCANS = 3  # per browser, without an account
DEFAULT_USER_LIMIT = 20  # new accounts; admins change it per user (empty = unlimited)
STATIC = Path(__file__).parent / "static"
UPLOADS = Path(tempfile.gettempdir()) / "androguard_uploads"
UPLOADS.mkdir(exist_ok=True)
DUMMY_HASH = auth.hash_password(uuid.uuid4().hex)  # unknown emails still pay for one scrypt: no timing oracle
# ponytail: one in-process worker (jadx needs GBs of RAM). Move to Redis + RQ/Celery workers when scans must
# survive restarts or run on several machines.
worker = ThreadPoolExecutor(max_workers=1)
CANCELLED: set[int] = set()  # scan ids the user asked to stop
UNCOUNTED = ("failed", "cancelled")  # these do not use up a quota
class Static(StaticFiles):
    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"  # browsers revalidate (304 if unchanged), so an update shows at once
        return response


app = FastAPI(title="AndroGuard")
app.mount("/static", Static(directory=STATIC), name="static")

with Session() as s:  # scans that were queued or running when the server stopped will never finish
    s.query(Scan).filter(Scan.status.in_(["queued", "running"])).update(
        {"status": "failed", "error": "The server restarted during this scan"})
    s.commit()


def _utc(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=timezone.utc) if d and d.tzinfo is None else d  # SQLite hands back naive UTC


def _iso(d: datetime | None) -> str | None:
    return _utc(d).isoformat() if d else None


def _update(scan_id: int, **fields):
    with Session() as s:
        s.query(Scan).filter_by(id=scan_id).update(fields)
        s.commit()


class Cancelled(Exception):
    pass


def _friendly(e: Exception) -> str:
    text = str(e)
    low = text.lower()
    if "paging file" in low or "insufficient memory" in low or "outofmemoryerror" in low:
        return "The server ran out of memory while decompiling this app. Free some memory or disk space and scan it again."
    if "no space left" in low or "not enough space" in low:
        return "The server ran out of disk space during this scan. Free some space and scan it again."
    return text[-2000:]


def _run(scan_id: int, path: Path, name: str):
    def progress(msg: str):  # called between pipeline stages, so a cancel takes effect at the next stage at the latest
        if scan_id in CANCELLED:
            raise Cancelled
        _update(scan_id, progress=msg[:255])

    try:
        progress("Starting")
        _update(scan_id, status="running")
        report = scan(str(path), progress=progress)
        report["file"] = name  # the pipeline only saw the server-chosen temp name
        _update(scan_id, status="done", sha256=report["sha256"], report=report, progress="Done", finished_at=now())
    except Exception as e:  # any failure is shown to the user instead of leaving the scan stuck
        if scan_id in CANCELLED:
            _update(scan_id, status="cancelled", error="Cancelled by the user", finished_at=now())
        else:
            _update(scan_id, status="failed", error=_friendly(e), finished_at=now())
    finally:
        CANCELLED.discard(scan_id)
        path.unlink(missing_ok=True)  # privacy by design: the uploaded package never outlives its scan


def _user_json(u: User | None) -> dict | None:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role} if u else None


def _summary(row: Scan, owner: str | None = None) -> dict:
    report = row.report or {}
    return {"id": row.id, "filename": row.filename, "status": row.status, "progress": row.progress,
            "error": row.error, "sha256": row.sha256, "risk": report.get("risk"),
            "findings": len(report.get("findings", [])), "owner": owner, "created_at": _iso(row.created_at)}


def _quota(user: User | None, device: str) -> dict:
    with Session() as s:
        counted = s.query(Scan).filter(Scan.status.notin_(UNCOUNTED))
        if user:
            used = counted.filter(Scan.user_id == user.id).count()
            limit = None if user.role in ("admin", "superadmin") else user.scan_limit
        else:
            used, limit = counted.filter(Scan.device_id == device).count(), FREE_SCANS
    return {"used": used, "limit": limit}


def _get(scan_id: int, request: Request, done: bool = False) -> Scan:
    user, device = auth.current_user(request), request.cookies.get(auth.DEVICE_COOKIE)
    with Session() as s:
        row = s.get(Scan, scan_id)
    owned = row is not None and (
        (user is not None and (user.role in ("admin", "superadmin") or row.user_id == user.id))
        or (user is None and row.user_id is None and device is not None and row.device_id == device))
    if not owned:  # 404, not 403: other people's scan ids are not confirmed to exist
        raise HTTPException(404, "Scan not found")
    if done and row.status != "done":
        raise HTTPException(409, "The scan has not finished")
    return row


def _claim_trial_scans(user_id: int, device: str):
    with Session() as s:  # free-trial scans from this browser move into the new account
        s.query(Scan).filter(Scan.device_id == device, Scan.user_id.is_(None)).update({"user_id": user_id})
        s.commit()


# ---------- accounts ----------
class SignUp(BaseModel):
    email: str
    password: str
    name: str = ""


class SignIn(BaseModel):
    email: str
    password: str


@app.post("/api/auth/signup", status_code=201)
def signup(body: SignUp, request: Request, response: Response):
    email = auth.validate(body.email, body.password)
    with Session() as s:
        if s.query(User).filter_by(email=email).first():
            raise HTTPException(409, "An account with this email already exists")
        user = User(email=email, name=body.name.strip()[:80], password_hash=auth.hash_password(body.password),
                    scan_limit=DEFAULT_USER_LIMIT)
        s.add(user)
        s.commit()
    auth.start_session(request, response, user.id)
    _claim_trial_scans(user.id, auth.device_id(request, response))
    return {"user": _user_json(user)}


@app.post("/api/auth/login")
def login(body: SignIn, request: Request, response: Response):
    email = body.email.strip().lower()
    key = f"{request.client.host if request.client else ''}|{email}"
    auth.check_login_rate(key)
    with Session() as s:
        user = s.query(User).filter_by(email=email).first()
    if not auth.verify_password(body.password, user.password_hash if user else DUMMY_HASH) or user is None:
        auth.record_failure(key)
        raise HTTPException(401, "Wrong email or password")
    if user.status != "active":
        raise HTTPException(403, "This account is blocked. Contact the administrator.")
    auth.start_session(request, response, user.id)
    _claim_trial_scans(user.id, auth.device_id(request, response))
    return {"user": _user_json(user)}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    auth.logout(request, response)
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request, response: Response):
    user = auth.current_user(request)
    return {"user": _user_json(user), "quota": _quota(user, auth.device_id(request, response))}


# ---------- scans ----------
@app.post("/api/scans", status_code=202)
async def create_scan(request: Request, response: Response, file: UploadFile = File(...)):
    user, device = auth.current_user(request), auth.device_id(request, response)
    quota = _quota(user, device)
    if quota["limit"] is not None and quota["used"] >= quota["limit"]:
        raise HTTPException(403, "You have used your 3 free scans. Create an account to keep scanning." if user is None
                            else "You have reached your scan limit. Ask the administrator to raise it.")
    name = Path(file.filename or "").name
    if Path(name).suffix.lower() not in (".apk", ".aab"):
        raise HTTPException(400, "Upload an .apk or .aab file")
    name = name[:255]  # display-only (column is String(255)); the path on disk is server-chosen below
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
        row = Scan(filename=name, status="queued", progress="Waiting for the scanner",
                   user_id=user.id if user else None, device_id=device)
        s.add(row)
        s.commit()
        scan_id = row.id
    worker.submit(_run, scan_id, path, name)
    return {"id": scan_id}


@app.get("/api/scans")
def list_scans(request: Request, response: Response):
    user, device = auth.current_user(request), auth.device_id(request, response)
    with Session() as s:
        query = s.query(Scan)
        query = query.filter(Scan.user_id == user.id) if user else query.filter(Scan.user_id.is_(None),
                                                                                  Scan.device_id == device)
        return [_summary(r) for r in query.order_by(Scan.id.desc()).limit(100)]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, request: Request):
    row = _get(scan_id, request)
    return {**_summary(row), "report": row.report}


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, request: Request):
    row = _get(scan_id, request)
    if row.status not in ("queued", "running"):
        raise HTTPException(409, "Only a queued or running scan can be cancelled")
    CANCELLED.add(scan_id)
    if row.status == "running":
        stop_tools()  # ponytail: one worker, so the tool running now belongs to this scan
    else:
        _update(scan_id, status="cancelled", error="Cancelled by the user", finished_at=now())
    return {"ok": True}


@app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: int, request: Request):
    return render_html(_get(scan_id, request, done=True).report)


@app.get("/api/scans/{scan_id}/report.pdf")
def report_pdf(scan_id: int, request: Request):
    row = _get(scan_id, request, done=True)
    try:
        pdf = render_pdf(render_html(row.report))
    except RuntimeError as e:
        raise HTTPException(501, str(e))
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(row.filename).stem)  # headers are latin-1: no Unicode names here
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{safe}-androguard.pdf"'})


# ---------- CRM (admin and superadmin) ----------
class UserPatch(BaseModel):
    role: Optional[str] = None
    status: Optional[str] = None
    scan_limit: Optional[int] = None
    notes: Optional[str] = None


def _crm_user(u: User, used: int) -> dict:
    return {**_user_json(u), "status": u.status, "scan_limit": u.scan_limit, "scans_used": used, "notes": u.notes or "",
            "created_at": _iso(u.created_at), "last_login_at": _iso(u.last_login_at)}


@app.get("/api/admin/stats")
def stats(admin: User = Depends(auth.require_admin)):
    with Session() as s:  # ponytail: aggregates in Python; move to SQL GROUP BY once scans reach the tens of thousands
        users = s.query(User).all()
        scans = s.query(Scan).all()
        emails = {u.id: u.email for u in users}
    week, first_day = now() - timedelta(days=7), (now() - timedelta(days=13)).date()
    per_day = Counter(_utc(r.created_at).date() for r in scans if r.created_at)
    trial = {r.device_id for r in scans if r.device_id}
    return {
        "users": len(users), "new_users_7d": sum(1 for u in users if u.created_at and _utc(u.created_at) >= week),
        "scans": len(scans), "scans_7d": sum(1 for r in scans if r.created_at and _utc(r.created_at) >= week),
        "high_risk": sum(1 for r in scans if ((r.report or {}).get("risk") or {}).get("level") == "HIGH"),
        "failed": sum(1 for r in scans if r.status == "failed"),
        "trial_devices": len(trial), "converted_devices": len({r.device_id for r in scans if r.device_id and r.user_id}),
        "per_day": [{"date": (first_day + timedelta(days=i)).isoformat(), "scans": per_day.get(first_day + timedelta(days=i), 0)}
                    for i in range(14)],
        "recent": [_summary(r, emails.get(r.user_id)) for r in sorted(scans, key=lambda r: -r.id)[:8]],
    }


@app.get("/api/admin/users")
def crm_users(q: str = "", admin: User = Depends(auth.require_admin)):
    with Session() as s:
        query = s.query(User)
        if q:
            query = query.filter(User.email.ilike(f"%{q}%") | User.name.ilike(f"%{q}%"))
        rows = query.order_by(User.id.desc()).limit(200).all()
        used = dict(s.query(Scan.user_id, func.count(Scan.id)).filter(Scan.status.notin_(UNCOUNTED)).group_by(Scan.user_id).all())
    return [_crm_user(u, used.get(u.id, 0)) for u in rows]


@app.patch("/api/admin/users/{user_id}")
def crm_update_user(user_id: int, body: UserPatch, admin: User = Depends(auth.require_admin)):
    changes = body.model_dump(exclude_unset=True)
    with Session() as s:
        user = s.get(User, user_id)
        if user is None:
            raise HTTPException(404, "User not found")
        if user.role == "superadmin" and set(changes) - {"notes"}:
            raise HTTPException(403, "The superadmin account is managed from the command line")
        if user.role == "admin" and admin.role != "superadmin":
            raise HTTPException(403, "Only the superadmin can manage admins")
        if "role" in changes and (admin.role != "superadmin" or changes["role"] not in ("user", "admin")):
            raise HTTPException(403, "Only the superadmin can change roles, to user or admin")
        if "status" in changes and changes["status"] not in ("active", "blocked"):
            raise HTTPException(422, "Status must be active or blocked")
        if changes.get("scan_limit") is not None and not 0 <= changes["scan_limit"] <= 100000:
            raise HTTPException(422, "Scan limit must be between 0 and 100000, or empty for unlimited")
        if "notes" in changes:
            changes["notes"] = (changes["notes"] or "")[:2000]
        for field, value in changes.items():
            setattr(user, field, value)
        s.commit()
        used = s.query(Scan).filter(Scan.user_id == user_id, Scan.status.notin_(UNCOUNTED)).count()
    if changes.get("status") == "blocked":
        auth.end_sessions(user_id)  # a blocked user is signed out everywhere at once
    return _crm_user(user, used)


@app.delete("/api/admin/users/{user_id}")
def crm_delete_user(user_id: int, admin: User = Depends(auth.require_admin)):
    if admin.role != "superadmin":
        raise HTTPException(403, "Only the superadmin can delete accounts")
    with Session() as s:
        user = s.get(User, user_id)
        if user is None:
            raise HTTPException(404, "User not found")
        if user.role == "superadmin":
            raise HTTPException(403, "The superadmin account cannot be deleted")
        s.query(AuthSession).filter_by(user_id=user_id).delete()
        s.query(Scan).filter_by(user_id=user_id).delete()  # their reports may hold their app's secrets
        s.delete(user)
        s.commit()
    return {"ok": True}


@app.get("/api/admin/scans")
def crm_scans(q: str = "", status: str = "", admin: User = Depends(auth.require_admin)):
    with Session() as s:
        query = s.query(Scan, User.email).outerjoin(User, Scan.user_id == User.id)
        if q:
            query = query.filter(Scan.filename.ilike(f"%{q}%") | User.email.ilike(f"%{q}%"))
        if status:
            query = query.filter(Scan.status == status)
        return [_summary(r, email) for r, email in query.order_by(Scan.id.desc()).limit(300)]


@app.delete("/api/admin/scans/{scan_id}")
def crm_delete_scan(scan_id: int, admin: User = Depends(auth.require_admin)):
    with Session() as s:
        if not s.query(Scan).filter_by(id=scan_id).delete():
            raise HTTPException(404, "Scan not found")
        s.commit()
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text(encoding="utf-8")
