"""AndroGuard scanner: python -m app <app.apk|app.aab> [report.json]"""
import json
import sys
from collections import Counter
from pathlib import Path
from app.modules.m1_apk_analyzer import analyzer as m1
from app.modules.m2_api_analyzer import analyzer as m2
from app.modules.m3_input_processor.deps import DependencyScanner
from app.modules.m3_input_processor.extractor import APKExtractor
from app.modules.m3_input_processor.validator import validate_package
from app.modules.m3_input_processor.workspace import WorkspaceManager


def log(msg: str):
    print(msg, file=sys.stderr, flush=True)  # stdout is reserved for the JSON report


def scan(file_path: str) -> dict:
    kind, sha256 = validate_package(file_path)
    log(f"[*] {Path(file_path).name}: valid {kind.upper()}, sha256 {sha256[:16]}...")
    with WorkspaceManager() as ws:  # decompiled artifacts are deleted when the block exits, even on failure
        extractor = APKExtractor(Path(file_path), ws.workspace_dir)
        log("[*] Decompiling with apktool + jadx (can take a few minutes)...")
        decompiled, sources = extractor.decode_resources(), extractor.decompile_source()
        log("[*] Running M1 APK rules, M2 API rules and the OSV dependency check...")
        findings = m1.analyze(decompiled, sources) + m2.analyze(decompiled, sources) \
            + DependencyScanner().scan_apk(extractor.apk_path)
    findings.sort(key=lambda f: m1.SEVERITIES.index(f.severity))
    return {"file": Path(file_path).name, "type": kind, "sha256": sha256,
            "findings": [f.model_dump(exclude_none=True) for f in findings]}


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("Usage: python -m app <app.apk|app.aab> [report.json]")
    result = scan(sys.argv[1])
    report = json.dumps(result, indent=2)
    if len(sys.argv) == 3:  # writing the file ourselves avoids shell redirect encodings (PowerShell 5 writes UTF-16)
        Path(sys.argv[2]).write_text(report, encoding="utf-8")
    else:
        print(report)
    counts = Counter(f["severity"] for f in result["findings"])
    log(f"[+] {len(result['findings'])} findings ({', '.join(f'{k} {v}' for k, v in counts.items())})"
        + (f" -> {sys.argv[2]}" if len(sys.argv) == 3 else ""))
