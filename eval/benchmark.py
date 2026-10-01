"""Benchmark: python -m eval.benchmark [dev|heldout|benign]
Scans each APK once (report cached in data/eval/<set>/), then scores detection (app x category), scan time and peak
RAM, and how well three orderings put the documented vulnerabilities first (rule-only vs + M4 vs + ML)."""
import json
import sys
import threading
import time
from pathlib import Path
import psutil
from app.modules.m4_risk_engine.correlator import EXPLOIT_WEIGHT, SEVERITY_WEIGHT
from app.pipeline import scan

ROOT = Path(__file__).resolve().parents[1]
SETS = {"dev": ("ground_truth.json", "data/apks", "data/eval", "results.md"),
        "heldout": ("heldout.json", "data/apks/heldout", "data/eval/heldout", "results_heldout.md"),
        "benign": ("benign.json", "data/apks/benign", "data/eval/benign", "results_benign.md")}
CATEGORIES = ["Hardcoded Secrets", "Insecure Data Storage", "Insecure Cryptography", "Exported Components",
              "Insecure Permissions", "Insecure WebView", "Cleartext Traffic", "Improper SSL/TLS Validation",
              "Hardcoded API keys/secrets", "Insecure API Endpoints", "HTTP Endpoints", "Sensitive Data in URLs",
              "Weak Authentication Configuration", "Insecure SSL/TLS Configuration", "Excessive API Permissions",
              "Vulnerable Dependency"]
MERGED = {"Hardcoded API Keys": "Hardcoded API keys/secrets", "Hardcoded API Secrets": "Hardcoded API keys/secrets"}
ORDERS = {  # higher sorts first; ties broken by finding id so no ordering inherits the final one
    "Rule-only (severity, then confidence)": lambda f: (SEVERITY_WEIGHT.get(f["severity"], 0.45), f.get("confidence") or 0.6),
    "+ M4 exploitability and attack chains": lambda f: SEVERITY_WEIGHT.get(f["severity"], 0.45)
    * EXPLOIT_WEIGHT[f.get("exploitability") or "MEDIUM"] * (f.get("confidence") or 0.6),
    "+ ML-assisted risk (final score)": lambda f: f.get("risk_score") or 0,
}


def measured_scan(apk: Path) -> tuple[dict, dict]:
    """One scan, plus its wall time and the peak RAM of this process and the jadx/apktool it starts."""
    me, peak, done = psutil.Process(), [0], threading.Event()

    def sample():
        while not done.is_set():
            try:
                peak[0] = max(peak[0], me.memory_info().rss + sum(c.memory_info().rss for c in me.children(recursive=True)))
            except psutil.Error:
                pass
            time.sleep(0.2)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    start = time.time()
    try:
        report = scan(str(apk))
    finally:
        done.set()
        sampler.join()
    return report, {"seconds": round(time.time() - start, 1), "peak_mb": round(peak[0] / 1048576),
                    "apk_mb": round(apk.stat().st_size / 1048576, 1)}


def load(set_name: str, gt: dict) -> tuple[dict, dict]:
    _, apks, cache, _ = SETS[set_name]
    cache = ROOT / cache
    cache.mkdir(parents=True, exist_ok=True)
    perf_path = cache / "_perf.json"
    perf = json.loads(perf_path.read_text()) if perf_path.exists() else {}
    reports = {}
    for app in gt["apps"]:
        path = cache / f"{app}.json"
        if not path.exists() or app not in perf:
            print(f"scanning {app}...", flush=True)
            report, perf[app] = measured_scan(ROOT / apks / f"{app}.apk")
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            perf_path.write_text(json.dumps(perf, indent=1))
        reports[app] = json.loads(path.read_text(encoding="utf-8"))
    return reports, perf


def category(f: dict) -> str:
    return MERGED.get(f["category"], f["category"])


def evaluate(gt: dict, reports: dict) -> dict:
    rows, tp, fp, fn, unreviewed = [], 0, 0, 0, []
    per_cat = {c: [0, 0, 0] for c in CATEGORIES}  # tp, fp, fn
    for app, truth_app in gt["apps"].items():
        found = {category(f) for f in reports[app]["findings"]}
        for cat in CATEGORIES:
            truth = cat in truth_app["documented"] or truth_app["reviewed"].get(cat, {}).get("label", False)
            pred = cat in found
            if pred and cat not in truth_app["documented"] and cat not in truth_app["reviewed"]:
                unreviewed.append(f"{app}: {cat}")
            outcome = "TP" if pred and truth else "FP" if pred else "FN" if truth else None
            if outcome:
                rows.append((app, cat, outcome))
                k = {"TP": 0, "FP": 1, "FN": 2}[outcome]
                per_cat[cat][k] += 1
                tp, fp, fn = tp + (k == 0), fp + (k == 1), fn + (k == 2)
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3), "recall": round(r, 3),
            "f1": round(2 * p * r / (p + r), 3) if p + r else 0, "per_category": per_cat, "rows": rows,
            "unreviewed": unreviewed}


def ranking(gt: dict, reports: dict) -> dict:
    """Mean precision@5, precision@10 and average precision; relevant = category is a documented vulnerability."""
    out = {}
    for name, key in ORDERS.items():
        p5, p10, ap = [], [], []
        for app, truth_app in gt["apps"].items():
            ordered = sorted(reports[app]["findings"], key=lambda f: (key(f), f["id"]), reverse=True)
            rel = [category(f) in truth_app["documented"] for f in ordered]
            if not any(rel):
                continue
            p5.append(sum(rel[:5]) / min(5, len(rel)))
            p10.append(sum(rel[:10]) / min(10, len(rel)))
            hits = [sum(rel[:i + 1]) / (i + 1) for i, r in enumerate(rel) if r]
            ap.append(sum(hits) / len(hits))
        out[name] = [round(sum(v) / len(v), 3) for v in (p5, p10, ap)]
    return out


if __name__ == "__main__":
    set_name = sys.argv[1] if len(sys.argv) > 1 else "dev"
    gt_file, _, _, results = SETS[set_name]
    gt = json.loads((ROOT / "eval" / gt_file).read_text(encoding="utf-8"))
    reports, perf = load(set_name, gt)
    res, benign = evaluate(gt, reports), gt.get("_benign")
    summary = (f"False-positive rate **{round(res['fp'] / max(1, res['tp'] + res['fp']), 3)}** ({res['fp']} of {res['tp'] + res['fp']} reported app x category pairs are false alarms; recall is not measured on benign apps)"
               if benign else f"Precision **{res['precision']}**, recall **{res['recall']}**, F1 **{res['f1']}** "
               f"(TP {res['tp']}, FP {res['fp']}, FN {res['fn']}; unit = app x category, method in {gt_file})")
    lines = [f"# AndroGuard benchmark, {set_name} set ({', '.join(gt['apps'])})", "", summary, "",
             "| Category | TP | FP | FN |", "|---|---|---|---|"]
    lines += [f"| {c} | {t} | {f} | {n} |" for c, (t, f, n) in res["per_category"].items() if t + f + n]
    if not benign:
        lines += ["", "## Prioritization: rule-only baseline vs hybrid",
                  "Relevant = the finding's category is one of the app's documented vulnerabilities.", "",
                  "| Ordering | Precision@5 | Precision@10 | Mean average precision |", "|---|---|---|---|"]
        lines += [f"| {name} | {a} | {b} | {c} |" for name, (a, b, c) in ranking(gt, reports).items()]
    lines += ["", "## Scan time and memory", "", "| App | APK (MB) | Findings | Time (s) | Peak RAM (MB) |", "|---|---|---|---|---|"]
    lines += [f"| {app} | {perf[app]['apk_mb']} | {len(reports[app]['findings'])} | {perf[app]['seconds']} | {perf[app]['peak_mb']} |"
              for app in gt["apps"]]
    lines += ["", "| App | Category | Outcome |", "|---|---|---|"] + [f"| {a} | {c} | {o} |" for a, c, o in res["rows"]]
    lines += ["", "## Notes"] + [f"- {n}" for n in gt.get("_notes", [])]
    (ROOT / "eval" / results).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:3]))
    if res["unreviewed"]:
        print("Needs manual review (predicted but undocumented):", *res["unreviewed"], sep="\n  ")
