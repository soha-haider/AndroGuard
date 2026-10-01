"""Scan pipeline shared by the CLI (python -m app) and the web API: M3 -> M1 + M2 + deps -> M4."""
import sys
from pathlib import Path
from app.modules.m1_apk_analyzer import analyzer as m1
from app.modules.m2_api_analyzer import analyzer as m2
from app.modules.m3_input_processor import dataflow
from app.modules.m3_input_processor.deps import DependencyScanner
from app.modules.m3_input_processor.extractor import APKExtractor
from app.modules.m3_input_processor.validator import validate_package
from app.modules.m3_input_processor.workspace import WorkspaceManager
from app.modules.m4_risk_engine.correlator import app_risk, assess
from app.modules.ml import codebert
from app.modules.ml.code_model import score_findings


def log(msg: str):
    print(msg, file=sys.stderr, flush=True)  # stdout is reserved for the JSON report


def scan(file_path: str, progress=log) -> dict:
    kind, sha256 = validate_package(file_path)
    progress(f"[*] {Path(file_path).name}: valid {kind.upper()}, sha256 {sha256[:16]}...")
    with WorkspaceManager() as ws:  # decompiled artifacts are deleted when the block exits, even on failure
        extractor = APKExtractor(Path(file_path), ws.workspace_dir)
        progress("[*] Decompiling with apktool + jadx (can take a few minutes)...")
        decompiled, sources = extractor.decode_resources(), extractor.decompile_source()
        progress("[*] Running M1 APK rules, M2 API rules, the OSV dependency check and FlowDroid data flows...")
        findings = m1.analyze(decompiled, sources) + m2.analyze(decompiled, sources) \
            + DependencyScanner().scan_apk(extractor.apk_path)
        m1._read.cache_clear()  # file texts are shared by M1/M2 only within one scan
        flows, flow_status = dataflow.run(extractor.apk_path, ws.workspace_dir)
        findings += dataflow.findings(flows)
    progress("[*] Correlating evidence, scoring exploitability (M4) and ML-assisted risk...")
    findings = codebert.annotate(score_findings(assess(findings)))
    return {"file": Path(file_path).name, "type": kind, "sha256": sha256, "risk": app_risk(findings),
            "findings": [f.model_dump(exclude_none=True) for f in findings],
            "data_flows": flows, "data_flow_status": flow_status}
