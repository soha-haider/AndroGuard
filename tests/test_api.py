import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
os.environ["DATABASE_URL"] = f"sqlite:///{(Path(tempfile.mkdtemp()) / 'test.db').as_posix()}"  # before app imports

from fastapi.testclient import TestClient
import app.api as api
from app import auth
from app.database import Session, User

SEEN = []
GATE = threading.Event()  # holds a "slow" scan in the worker so cancels can be tested
REPORT = {"file": "demo.apk", "type": "apk", "sha256": "ab" * 32,
          "risk": {"score": 72.0, "level": "HIGH", "exploitability": {"HIGH": 1, "MEDIUM": 0, "LOW": 0}, "in_attack_chains": []},
          "findings": [{"id": "EXPORTED-COMPONENT-1", "title": "Exported <b>component</b>", "severity": "HIGH",
                        "description": "d", "category": "Exported Components", "evidence": ["<script>alert(1)</script>"],
                        "exploitability": "HIGH", "exploit_factors": ["any app"], "risk_score": 72.0,
                        "masvs": ["MASVS-PLATFORM-1"], "maswe": ["MASWE-0018"], "remediation": "fix"}]}


def fake_scan(path, progress):
    SEEN.append(Path(path))
    progress("[*] scanning")
    body = open(path, "rb").read().decode()
    if "slow" in body:
        GATE.wait(5)
        progress("[*] next stage")  # a cancel takes effect here
    if "broken" in body:
        raise ValueError("Missing AndroidManifest.xml; not a valid APK")
    if "oom" in body:
        raise RuntimeError("jadx decompilation failed (exit code 1):\nThe paging file is too small for this operation to complete")
    return dict(REPORT)


def upload(client, name="demo.apk", body=b"fine"):
    return client.post("/api/scans", files={"file": (name, body)})


def wait(client, scan_id):
    for _ in range(50):
        s = client.get(f"/api/scans/{scan_id}").json()
        if s["status"] in ("done", "failed", "cancelled"):
            return s
        time.sleep(0.1)
    raise AssertionError("scan never finished")


def login(client, email, password):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def test_api():
    api.scan = fake_scan
    assert auth.verify_password("pw-12345678", auth.hash_password("pw-12345678"))
    assert not auth.verify_password("wrong", auth.hash_password("pw-12345678"))

    # free trial: 3 scans per browser, then an account is required
    anon = TestClient(api.app)
    assert anon.get("/static/app.js").headers["cache-control"] == "no-cache"  # an updated UI reaches browsers at once
    assert anon.get("/api/auth/me").json() == {"user": None, "quota": {"used": 0, "limit": 3}}
    assert upload(anon, "notes.txt").status_code == 400
    ids = [upload(anon).json()["id"] for _ in range(3)]
    for i in ids:
        wait(anon, i)
    blocked = upload(anon)
    assert blocked.status_code == 403 and "3 free scans" in blocked.json()["detail"]
    other = TestClient(api.app)  # another browser sees none of it
    assert other.get(f"/api/scans/{ids[0]}").status_code == 404 and other.get("/api/scans").json() == []

    # sign up: the trial scans move into the account, which gets its own quota
    r = anon.post("/api/auth/signup", json={"email": "Aisha@Example.com", "password": "correct horse", "name": "Aisha"})
    assert r.status_code == 201 and r.json()["user"]["email"] == "aisha@example.com"
    assert anon.get("/api/auth/me").json()["quota"] == {"used": 3, "limit": api.DEFAULT_USER_LIMIT}
    assert len(anon.get("/api/scans").json()) == 3
    assert anon.post("/api/auth/signup", json={"email": "aisha@example.com", "password": "another-pass"}).status_code == 409
    assert anon.post("/api/auth/signup", json={"email": "not-an-email", "password": "long-enough"}).status_code == 422

    ok = wait(anon, upload(anon, "My App (1).apk").json()["id"])
    assert ok["status"] == "done" and ok["report"]["file"] == "My App (1).apk"
    page = anon.get(f"/api/scans/{ok['id']}/report.html").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "<script>alert" not in page, "report is not escaped"
    bad = wait(anon, upload(anon, "x.apk", b"broken").json()["id"])
    assert bad["status"] == "failed" and "not a valid APK" in bad["error"]
    assert anon.get(f"/api/scans/{bad['id']}/report.html").status_code == 409

    # cancel: a running scan stops at its next stage, a queued one never starts, neither uses the quota
    used = anon.get("/api/auth/me").json()["quota"]["used"]
    slow, queued = upload(anon, "slow.apk", b"slow").json()["id"], upload(anon, "q.apk").json()["id"]
    for _ in range(50):
        if anon.get(f"/api/scans/{slow}").json()["status"] == "running":
            break
        time.sleep(0.05)
    assert anon.post(f"/api/scans/{queued}/cancel").json()["ok"] and anon.post(f"/api/scans/{slow}/cancel").json()["ok"]
    GATE.set()
    assert wait(anon, slow)["status"] == "cancelled" and wait(anon, queued)["status"] == "cancelled"
    assert anon.post(f"/api/scans/{slow}/cancel").status_code == 409
    assert anon.get("/api/auth/me").json()["quota"]["used"] == used
    oom = wait(anon, upload(anon, "big.apk", b"oom").json()["id"])
    assert oom["status"] == "failed" and oom["error"].startswith("The server ran out of memory"), oom["error"]
    assert all(not p.exists() for p in SEEN), "uploaded package outlived its scan"
    assert all(p.parent == api.UPLOADS and p.stem.isalnum() for p in SEEN), "user file name reached the tools"

    anon.post("/api/auth/logout")
    assert anon.get("/api/auth/me").json()["user"] is None
    for _ in range(5):
        assert login(anon, "aisha@example.com", "wrong-password").status_code == 401
    assert login(anon, "aisha@example.com", "correct horse").status_code == 429  # locked for 15 minutes
    auth._failures.clear()

    # CRM access: users no, admins yes, the superadmin for roles and deletes
    bilal = TestClient(api.app)
    bilal.post("/api/auth/signup", json={"email": "bilal@example.com", "password": "bilal-pass-1"})
    assert bilal.get("/api/admin/stats").status_code == 403 and TestClient(api.app).get("/api/admin/stats").status_code == 401
    with Session() as s:
        s.add(User(email="root@example.com", password_hash=auth.hash_password("root-pass-123"), role="superadmin"))
        s.commit()
    root = TestClient(api.app)
    assert login(root, "root@example.com", "root-pass-123").status_code == 200
    st = root.get("/api/admin/stats").json()
    assert st["users"] == 3 and st["scans"] == 8 and st["failed"] == 2 and st["converted_devices"] == 1
    assert len(st["per_day"]) == 14 and st["per_day"][-1]["scans"] == 8
    users = {u["email"]: u for u in root.get("/api/admin/users").json()}
    aisha_id, bilal_id, root_id = (users[e]["id"] for e in ("aisha@example.com", "bilal@example.com", "root@example.com"))
    assert users["aisha@example.com"]["scans_used"] == 4  # 3 trial + 1; failed and cancelled scans do not count

    assert root.patch(f"/api/admin/users/{bilal_id}", json={"role": "admin"}).json()["role"] == "admin"
    assert bilal.get("/api/admin/stats").status_code == 200
    patched = bilal.patch(f"/api/admin/users/{aisha_id}", json={"scan_limit": 4, "notes": "Pilot customer"}).json()
    assert patched["scan_limit"] == 4 and patched["notes"] == "Pilot customer"
    assert bilal.patch(f"/api/admin/users/{aisha_id}", json={"role": "admin"}).status_code == 403
    assert bilal.patch(f"/api/admin/users/{root_id}", json={"status": "blocked"}).status_code == 403
    assert bilal.patch(f"/api/admin/users/{bilal_id}", json={"scan_limit": None}).status_code == 403  # admins can't edit admins
    assert bilal.delete(f"/api/admin/users/{aisha_id}").status_code == 403

    aisha = TestClient(api.app)
    assert login(aisha, "aisha@example.com", "correct horse").status_code == 200
    limited = upload(aisha)
    assert limited.status_code == 403 and "scan limit" in limited.json()["detail"]
    assert len(root.get("/api/admin/scans").json()) == 8 and root.get(f"/api/scans/{ids[0]}").status_code == 200
    root.patch(f"/api/admin/users/{aisha_id}", json={"status": "blocked"})
    assert aisha.get("/api/auth/me").json()["user"] is None, "blocked user still signed in"
    assert login(aisha, "aisha@example.com", "correct horse").status_code == 403
    assert root.delete(f"/api/admin/users/{aisha_id}").json()["ok"]
    assert root.get(f"/api/scans/{ids[0]}").status_code == 404, "deleted user's scans remain"
    assert root.delete(f"/api/admin/users/{root_id}").status_code == 403
    assert "AndroGuard" in anon.get("/").text
    print("[OK] API check passed: free trial quota, ownership, signup claim, login limit, cancel, roles, block and delete")


def test_odd_filenames():  # runs after test_api: only the suffix decides, not the characters or the length
    api.scan = fake_scan
    client = TestClient(api.app)
    assert upload(client, "notes.txt").status_code == 400
    assert upload(client, "no-suffix").status_code == 400
    assert upload(client, "Some App (v2) — final & best, #1 +pro " + "x" * 300 + ".APK").status_code == 202
    assert len(client.get("/api/scans").json()[0]["filename"]) == 255  # trimmed to the column width
    print("[OK] odd filenames accepted")


if __name__ == "__main__":
    test_api()
    test_odd_filenames()
