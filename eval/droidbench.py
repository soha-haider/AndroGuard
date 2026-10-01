"""Checks the FlowDroid integration on DroidBench: python -m eval.droidbench
APKs in data/droidbench/<Category>/; expected leak counts are DroidBench's @number_of_leaks tags (droidbench_expected.json).
A leak = one sink statement reached by sensitive data, as DroidBench counts them."""
import json
import tempfile
from collections import defaultdict
from pathlib import Path
from app.modules.m3_input_processor import dataflow

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    expected = json.loads((ROOT / "eval" / "droidbench_expected.json").read_text())
    rows, per_cat = [], defaultdict(lambda: [0, 0, 0])
    for app, want in expected.items():
        with tempfile.TemporaryDirectory() as d:
            flows, status = dataflow.run(ROOT / "data" / "droidbench" / f"{app}.apk", Path(d))
        got = len({(f["method"], f["sink"], f["sink_line"]) for f in flows})
        tp, fp, fn = min(got, want), max(0, got - want), max(0, want - got)
        for i, v in enumerate((tp, fp, fn)):
            per_cat[app.split("/")[0]][i] += v
        rows.append((app, want, got, status))
        print(f"{app}: expected {want}, found {got}", flush=True)
    tp, fp, fn = (sum(c[i] for c in per_cat.values()) for i in range(3))
    p, r = tp / (tp + fp) if tp + fp else 0, tp / (tp + fn) if tp + fn else 0
    f1 = 2 * p * r / (p + r) if p + r else 0
    lines = [f"# FlowDroid integration on DroidBench ({len(rows)} apps)", "",
             f"Precision **{p:.3f}**, recall **{r:.3f}**, F1 **{f1:.3f}** (TP {tp}, FP {fp}, FN {fn}; unit = leaking sink)", "",
             "| Category | TP | FP | FN |", "|---|---|---|---|"]
    lines += [f"| {c} | {a} | {b} | {n} |" for c, (a, b, n) in per_cat.items()]
    lines += ["", "| App | Expected leaks | Found |", "|---|---|---|"] + [f"| {a} | {w} | {g} |" for a, w, g, _ in rows]
    lines += ["", "## Notes", "- FlowDroid 2.13 with its default sources and sinks, run through AndroGuard's wrapper "
              "(app/modules/m3_input_processor/dataflow.py). This checks the integration, not new analysis research."]
    (ROOT / "eval" / "results_droidbench.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:3]))
