"""Selected data flows (proposal Phase 6): FlowDroid taint analysis from its default privacy sources to its sinks.
Optional: needs java and tools/flowdroid/ with soot-infoflow-cmd.jar, SourcesAndSinks.txt and platforms/android-*/.
FlowDroid 2.13 cannot parse some newer resource tables and misses some callback styles; the scan then goes on
without flows and the report says why."""
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from app.modules.m1_apk_analyzer.analyzer import _finding
from app.modules.m3_input_processor.extractor import TOOLS_DIR, _run

FD = Path(os.environ.get("FLOWDROID_DIR", TOOLS_DIR / "flowdroid"))
TIMEOUT = int(os.environ.get("ANDROGUARD_FLOWDROID_TIMEOUT", 300))  # seconds; data flows are optional, scans are not
DS, URL = "Insecure Data Storage", "Sensitive Data in URLs"
KB = {
    "DATAFLOW-LOG": (DS, "Sensitive data flows into the system log", "MEDIUM", 0.9, ["MASVS-STORAGE-2"], ["MASWE-0005"],
                     "FlowDroid traced data from a sensitive source to an android.util.Log call.",
                     "The value reaches the log, which adb, crash reporters and (on old Android) other apps can read.",
                     "Remove the log call or log a redacted value, and strip logging from release builds."),
    "DATAFLOW-STORAGE": (DS, "Sensitive data flows into local storage", "MEDIUM", 0.9, ["MASVS-STORAGE-1"], ["MASWE-0001"],
                         "FlowDroid traced data from a sensitive source to a file or SharedPreferences write.",
                         "The value is stored unencrypted on the device and can be pulled through backups, root or adb.",
                         "Do not persist the value, or encrypt it with a key from the Android Keystore."),
    "DATAFLOW-URL": (URL, "Sensitive data flows into a URL", "MEDIUM", 0.9, ["MASVS-STORAGE-2"], ["MASWE-0005"],
                     "FlowDroid traced data from a sensitive source into a java.net.URL.",
                     "URLs end up in server, proxy and analytics logs, leaking the value.",
                     "Send the value in a POST body over HTTPS instead of the URL."),
}
SINK_KIND = [("android.util.Log.", "DATAFLOW-LOG"), ("android.content.SharedPreferences", "DATAFLOW-STORAGE"),
             ("java.io.File", "DATAFLOW-STORAGE"), ("java.net.URL.", "DATAFLOW-URL")]


def _api(signature: str) -> str:
    """'<android.util.Log: int i(java.lang.String,java.lang.String)>' -> 'android.util.Log.i' (also inside a statement)"""
    m = re.search(r"<([\w.$]+): \S+ ([\w<>$]+)\(", signature or "")
    return f"{m.group(1)}.{m.group(2)}" if m else signature


def run(apk: Path, out_dir: Path) -> tuple[list[dict], str]:
    """(flows, status). One flow per source -> sink pair."""
    jar, sources_sinks, platforms = FD / "soot-infoflow-cmd.jar", FD / "SourcesAndSinks.txt", FD / "platforms"
    if not (jar.is_file() and sources_sinks.is_file() and platforms.is_dir()):
        return [], "Data-flow analysis skipped: FlowDroid is not installed"
    xml_out = Path(out_dir) / "flowdroid.xml"
    try:
        _run(["java", "-Xmx3g", "-jar", str(jar), "-a", str(apk), "-p", str(platforms), "-s", str(sources_sinks),
              "-o", str(xml_out), "-dt", "120", "-ct", "60", "-rt", "60", "-ol"], "FlowDroid", timeout=TIMEOUT)
    except RuntimeError as e:
        return [], f"Data-flow analysis stopped: {str(e).splitlines()[0]}"
    if not xml_out.is_file():
        return [], "FlowDroid found no sensitive sources it could reach in this app"
    flows = parse(xml_out.read_text(encoding="utf-8"))
    sinks = len({(f["method"], f["sink"], f["sink_line"]) for f in flows})
    plural = lambda n, word: f"{n} {word}{'' if n == 1 else 's'}"
    return flows, f"FlowDroid traced {plural(len(flows), 'source-to-sink flow')} into {plural(sinks, 'sink')}"


def parse(xml: str) -> list[dict]:
    flows = []
    for result in ET.fromstring(xml).iter("Result"):
        sink = result.find("Sink")
        for source in result.iter("Source"):
            flows.append({"source": _api(source.get("MethodSourceSinkDefinition") or source.get("Statement")), "source_line": int(source.get("LineNumber", -1)),
                          "sink": _api(sink.get("MethodSourceSinkDefinition") or sink.get("Statement")), "sink_line": int(sink.get("LineNumber", -1)),
                          "method": _api(sink.get("Method"))})
    # flows into the security sinks first: reports list only the first few dozen
    return sorted(flows, key=lambda f: not any(f["sink"].startswith(prefix) for prefix, _ in SINK_KIND))


def findings(flows: list[dict]):
    """One finding per (sink kind, class) for sinks inside the 16 categories; the rest stay in the report's flow list."""
    grouped = {}
    for f in flows:
        kind = next((k for prefix, k in SINK_KIND if f["sink"].startswith(prefix)), None)
        if kind:
            cls = f["method"].rsplit(".", 1)[0].split("$")[0]
            grouped.setdefault((kind, cls), []).append(f)
    out, counter = [], {}
    for (kind, cls), fs in grouped.items():
        counter[kind] = counter.get(kind, 0) + 1
        evidence = [f"{f['source']} (line {f['source_line']}) -> {f['sink']} (line {f['sink_line']}) in {f['method']}" for f in fs[:3]]
        out.append(_finding(kind, cls.replace(".", "/") + ".java", evidence, kb=KB))
        out[-1].id = f"{kind}-{counter[kind]}"
    return out
