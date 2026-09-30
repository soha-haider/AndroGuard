import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
os.environ["DATABASE_URL"] = f"sqlite:///{(Path(tempfile.mkdtemp()) / 'test.db').as_posix()}"  # before app imports

from fastapi.testclient import TestClient
import app.api as api

SEEN = []
REPORT = {"file": "demo.apk", "type": "apk", "sha256": "ab" * 32,
          "risk": {"score": 72.0, "level": "HIGH", "exploitability": {"HIGH": 1, "MEDIUM": 0, "LOW": 0}, "in_attack_chains": []},
          "findings": [{"id": "EXPORTED-COMPONENT-1", "title": "Exported <b>component</b>", "severity": "HIGH",
                        "description": "d", "category": "Exported Components", "evidence": ["<script>alert(1)</script>"],
                        "exploitability": "HIGH", "exploit_factors": ["any app"], "risk_score": 72.0,
                        "masvs": ["MASVS-PLATFORM-1"], "maswe": ["MASWE-0018"], "remediation": "fix"}]}


def fake_scan(path, progress):
    SEEN.append(Path(path))
    progress("[*] scanning")
    if "broken" in open(path, "rb").read().decode():
        raise ValueError("Missing AndroidManifest.xml; not a valid APK")
    return REPORT


def wait(client, scan_id):
    for _ in range(50):
        s = client.get(f"/api/scans/{scan_id}").json()
        if s["status"] in ("done", "failed"):
            return s
        time.sleep(0.1)
    raise AssertionError("scan never finished")


def test_api():
    api.scan = fake_scan
    client = TestClient(api.app)
    assert client.post("/api/scans", files={"file": ("notes.txt", b"x")}).status_code == 400
    assert client.post("/api/scans", files={"file": ("../evil.apk", b"x")}).status_code == 202  # path stripped to evil.apk

    ok = wait(client, client.post("/api/scans", files={"file": ("My App (1).apk", b"fine")}).json()["id"])
    assert ok["status"] == "done" and ok["report"]["risk"]["level"] == "HIGH" and ok["sha256"] == "ab" * 32
    assert ok["report"]["file"] == "My App (1).apk", "report shows the temp upload name"
    assert all(not p.exists() for p in SEEN), "uploaded package outlived its scan"
    assert all(p.parent == api.UPLOADS and p.stem.isalnum() for p in SEEN), "user file name reached the tools"

    bad = wait(client, client.post("/api/scans", files={"file": ("x.apk", b"broken")}).json()["id"])
    assert bad["status"] == "failed" and "not a valid APK" in bad["error"]

    listed = client.get("/api/scans").json()
    assert [s["status"] for s in listed][:2] == ["failed", "done"] and listed[1]["findings"] == 1
    page = client.get(f"/api/scans/{ok['id']}/report.html").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "<script>alert" not in page, "report is not escaped"
    assert client.get(f"/api/scans/{bad['id']}/report.html").status_code == 409
    assert client.get("/api/scans/9999").status_code == 404
    assert "AndroGuard" in client.get("/").text
    print(f"[OK] API check passed: {len(listed)} scans, upload -> scan -> report flow, cleanup and escaping")


if __name__ == "__main__":
    test_api()
