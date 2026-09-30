"""Benchmark: python -m eval.benchmark  (scans data/apks/<App>.apk into data/eval/<App>.json if missing)."""
import json
from pathlib import Path
from app.pipeline import scan

ROOT = Path(__file__).resolve().parents[1]
GT = json.loads((ROOT / "eval" / "ground_truth.json").read_text(encoding="utf-8"))
CATEGORIES = ["Hardcoded Secrets", "Insecure Data Storage", "Insecure Cryptography", "Exported Components",
              "Insecure Permissions", "Insecure WebView", "Cleartext Traffic", "Improper SSL/TLS Validation",
              "Hardcoded API keys/secrets", "Insecure API Endpoints", "HTTP Endpoints", "Sensitive Data in URLs",
              "Weak Authentication Configuration", "Insecure SSL/TLS Configuration", "Excessive API Permissions",
              "Vulnerable Dependency"]
MERGED = {"Hardcoded API Keys": "Hardcoded API keys/secrets", "Hardcoded API Secrets": "Hardcoded API keys/secrets"}


def report(app: str) -> dict:
    path = ROOT / "data" / "eval" / f"{app}.json"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(scan(str(ROOT / "data" / "apks" / f"{app}.apk")), indent=2), encoding="utf-8")
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate() -> dict:
    rows, tp, fp, fn, unreviewed = [], 0, 0, 0, []
    per_cat = {c: [0, 0, 0] for c in CATEGORIES}  # tp, fp, fn
    for app, gt in GT["apps"].items():
        found = {MERGED.get(f["category"], f["category"]) for f in report(app)["findings"]}
        for cat in CATEGORIES:
            truth = cat in gt["documented"] or gt["reviewed"].get(cat, {}).get("label", False)
            pred = cat in found
            if pred and cat not in gt["documented"] and cat not in gt["reviewed"]:
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


if __name__ == "__main__":
    res = evaluate()
    lines = [f"# AndroGuard benchmark ({', '.join(GT['apps'])})", "",
             f"Precision **{res['precision']}**, recall **{res['recall']}**, F1 **{res['f1']}** "
             f"(TP {res['tp']}, FP {res['fp']}, FN {res['fn']}; unit = app x category, method in ground_truth.json)", "",
             "| Category | TP | FP | FN |", "|---|---|---|---|"]
    lines += [f"| {c} | {t} | {f} | {n} |" for c, (t, f, n) in res["per_category"].items() if t + f + n]
    lines += ["", "| App | Category | Outcome |", "|---|---|---|"] + [f"| {a} | {c} | {o} |" for a, c, o in res["rows"]]
    lines += ["", "## Notes", "- Development-set scores: rules were adjusted after the first run on these same apps "
              "(first run: precision 0.727, recall 0.774, F1 0.75). Held-out apps (DIVA, Ghera, Vuldroid) are still needed.",
              "- Remaining FN: InsecureShop credentials stored as map.put(\"shopuser\", \"!ns3csh0p\") (no generic rule "
              "without false positives) and its vulnerable upload library (no OSV advisory for the bundled versions)."]
    (ROOT / "eval" / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:3]))
    if res["unreviewed"]:
        print("Needs manual review (predicted but undocumented):", *res["unreviewed"], sep="\n  ")
