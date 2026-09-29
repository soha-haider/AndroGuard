"""M1 command-line scanner: python -m app.modules.m1_apk_analyzer <app.apk|app.aab> > findings.json"""
import json
import sys
from collections import Counter
from pathlib import Path
from app.modules.m3_input_processor.validator import validate_package
from app.modules.m3_input_processor.workspace import WorkspaceManager
from app.modules.m3_input_processor.extractor import APKExtractor
from app.modules.m1_apk_analyzer.analyzer import analyze


def scan(file_path: str) -> dict:
    kind, sha256 = validate_package(file_path)
    with WorkspaceManager() as ws:  # decompiled artifacts are deleted when the block exits, even on failure
        extractor = APKExtractor(Path(file_path), ws.workspace_dir)
        findings = analyze(extractor.decode_resources(), extractor.decompile_source())
    return {"file": Path(file_path).name, "type": kind, "sha256": sha256,
            "findings": [f.model_dump(exclude_none=True) for f in findings]}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python -m app.modules.m1_apk_analyzer <app.apk|app.aab>")
    result = scan(sys.argv[1])
    print(json.dumps(result, indent=2))
    print(f"[+] {len(result['findings'])} findings: {dict(Counter(f['severity'] for f in result['findings']))}",
          file=sys.stderr)
