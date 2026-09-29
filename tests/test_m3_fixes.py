import hashlib
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.modules.m3_input_processor.validator import validate_package
from app.modules.m3_input_processor.deps import extract_dependencies, DependencyScanner
from app.modules.m3_input_processor.extractor import _run


def _zip(path: Path, entries: dict) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_m3_fixes():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        apk = _zip(d / "a.apk", {
            "AndroidManifest.xml": "x",
            "META-INF/androidx.core_core.version": "1.9.0\n",
            "META-INF/maven/com.google.code.gson/gson/pom.properties": "#c\ngroupId=com.google.code.gson\nartifactId=gson\nversion=2.8.5\n",
        })
        kind, sha = validate_package(apk)
        assert kind == "apk" and sha == hashlib.sha256(apk.read_bytes()).hexdigest()
        assert validate_package(_zip(d / "b.aab", {"base/manifest/AndroidManifest.xml": "x"}))[0] == "aab"

        for bad in [_zip(d / "c.apk", {"foo": "x"}), _zip(d / "d.zip", {"AndroidManifest.xml": "x"})]:
            try:
                validate_package(bad)
                assert False, f"{bad.name} should be rejected"
            except ValueError:
                pass
        (d / "e.apk").write_text("not a zip")
        try:
            validate_package(d / "e.apk")
            assert False, "non-zip should be rejected"
        except ValueError:
            pass

        assert extract_dependencies(apk) == {"androidx.core:core": "1.9.0", "com.google.code.gson:gson": "2.8.5"}

        fake = {"vulns": [{"id": "GHSA-x", "aliases": ["CVE-2022-25647"], "database_specific": {"severity": "MODERATE"},
                           "references": [{"url": "https://example.com"}]}]}
        with patch("app.modules.m3_input_processor.deps.requests.post") as post:
            post.return_value.status_code = 200
            post.return_value.json.return_value = fake
            f = DependencyScanner().scan_apk(apk)
        assert len(f) == 2 and f[0].severity == "MEDIUM" and f[0].cve == "CVE-2022-25647"
        assert f[0].references == ["https://example.com"]

    # jadx.bat on Windows exits 1 even for "finished with errors" (partial output is fine); real failures must raise
    fake_tool = [sys.executable, "-c"]
    _run(fake_tool + ["print('ERROR - finished with errors, count: 150'); raise SystemExit(1)"], "jadx", (0, 3),
         ok_marker="finished with errors")
    try:
        _run(fake_tool + ["print('ERROR - Process error: boom'); raise SystemExit(1)"], "jadx", (0, 3),
             ok_marker="finished with errors")
        assert False, "real jadx failure was swallowed"
    except RuntimeError as e:
        assert "exit code 1" in str(e) and "Process error: boom" in str(e)
    print("[OK] M3 fixes check passed")


if __name__ == "__main__":
    test_m3_fixes()
