"""CodeBERT (proposal Phases 4 and 8): microsoft/codebert-base fine-tuned on LVDAndro lines, with attention insights.

Train:   python -m app.modules.ml.codebert data/lvdandro/LVDAndro_SourceFiles_MobSF_Processed.csv
         (needs torch + transformers and the base model in data/models/codebert-base; ~30 min on a laptop CPU)
Runtime: optional. annotate(findings) adds a CodeBERT probability and the code tokens its last layer attended to
most. Without torch/transformers or the fine-tuned model (data/models/codebert-lvdandro, 500 MB, not in git)
scans run exactly as before. XGBoost (code_model.py) stays the model that nudges risk.
"""
import json
import re
import sys
import time
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE, TUNED = ROOT / "data/models/codebert-base", ROOT / "data/models/codebert-lvdandro"
META = Path(__file__).parent / "codebert_meta.json"
MAX_LEN = 64  # LVDAndro rows are single lines: median 46 characters


def _predict(model, tok, lines, batch=128):
    import torch
    order = sorted(range(len(lines)), key=lambda i: len(lines[i]))  # similar lengths per batch: less padding
    probs = [0.0] * len(lines)
    with torch.no_grad():
        for s in range(0, len(order), batch):
            idx = order[s:s + batch]
            enc = tok([lines[i] for i in idx], truncation=True, max_length=MAX_LEN, padding=True, return_tensors="pt")
            for i, p in zip(idx, model(**enc).logits.softmax(-1)[:, 1].tolist()):
                probs[i] = p
    return probs


def train(csv_path: str, n_pos: int = 1600, epochs: int = 1):
    import numpy as np
    import pandas as pd
    import torch
    import xgboost as xgb
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup
    from app.modules.ml import code_model

    fit_df, test_df = code_model.split(csv_path)
    # ponytail: 1,600 positives at the same 1:8 ratio as XGBoost, sized for a CPU; more data needs a GPU
    pos = fit_df[fit_df["Vulnerability_status"] == 1].sample(n=n_pos, random_state=42)
    neg = fit_df[fit_df["Vulnerability_status"] == 0].sample(n=8 * n_pos, random_state=42)
    sample = pd.concat([pos, neg]).sample(frac=1, random_state=42)
    torch.manual_seed(42)
    tok = AutoTokenizer.from_pretrained(BASE)
    model = AutoModelForSequenceClassification.from_pretrained(BASE, num_labels=2)
    steps = epochs * ((len(sample) + 15) // 16)
    opt = torch.optim.AdamW(model.parameters(), lr=2e-5, weight_decay=0.01)
    sched = get_linear_schedule_with_warmup(opt, int(0.06 * steps), steps)
    model.train()
    start, step = time.time(), 0
    for _ in range(epochs):
        for s in range(0, len(sample), 16):
            batch = sample.iloc[s:s + 16]
            enc = tok(list(batch["Code"]), truncation=True, max_length=MAX_LEN, padding=True, return_tensors="pt")
            loss = model(**enc, labels=torch.tensor(batch["Vulnerability_status"].to_numpy())).loss
            loss.backward()
            opt.step(), sched.step(), opt.zero_grad()
            step += 1
            if step % 50 == 0:
                print(f"step {step}/{steps} loss {loss.item():.3f} {time.time() - start:.0f}s", flush=True)
    train_minutes = round((time.time() - start) / 60, 1)
    model.eval()
    TUNED.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(TUNED)
    tok.save_pretrained(TUNED)

    lines, y = list(test_df["Code"]), test_df["Vulnerability_status"].to_numpy()
    print(f"scoring {len(lines)} test lines...", flush=True)
    probs = {"codebert": np.array(_predict(model, tok, lines))}
    booster, meta = code_model._load()  # the deployed XGBoost, scored on the same test lines
    probs["xgboost"] = booster.predict(xgb.DMatrix(code_model.vectorize(lines, meta["vocab"])))
    fit_X = code_model.vectorize(fit_df["Code"], meta["vocab"])
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced_subsample", n_jobs=-1, random_state=42)
    probs["random_forest"] = rf.fit(fit_X, fit_df["Vulnerability_status"]).predict_proba(code_model.vectorize(lines, meta["vocab"]))[:, 1]
    metrics = {}
    for name, p in probs.items():
        pred = (p >= 0.5).astype(int)
        metrics[name] = {k: round(float(v), 4) for k, v in {
            "precision": precision_score(y, pred), "recall": recall_score(y, pred), "f1": f1_score(y, pred),
            "roc_auc": roc_auc_score(y, p), "pr_auc": average_precision_score(y, p)}.items()}
    META.write_text(json.dumps({"base_model": "microsoft/codebert-base", "train_rows": len(sample), "epochs": epochs,
                                "max_tokens": MAX_LEN, "test_rows": len(lines), "test_positive_rate": round(float(y.mean()), 4),
                                "train_minutes": train_minutes, "metrics": metrics}, indent=1))
    return metrics


def available() -> bool:
    if not (TUNED / "config.json").exists():
        return False
    try:
        import torch, transformers  # noqa: F401
    except ImportError:
        return False
    return True


@lru_cache(maxsize=1)
def _load():
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    # eager attention: the fused kernels do not return attention weights
    return AutoTokenizer.from_pretrained(TUNED), AutoModelForSequenceClassification.from_pretrained(
        TUNED, attn_implementation="eager").eval()


def _words(tok, ids, weights):
    """Byte-pair pieces merged back into identifiers and literals, in line order: [(text, attention)]."""
    words = []
    for tid, w in zip(ids, weights):
        if tid in tok.all_special_ids:
            continue
        text = tok.convert_tokens_to_string([tok.convert_ids_to_tokens(tid)])  # 'Ġ' back to a leading space
        if words and re.match(r"\w", text) and re.search(r"\w$", words[-1][0]):
            words[-1] = (words[-1][0] + text, words[-1][1] + w)
        else:
            words.append((text, w))
    return words


def insights(lines: list[str], top: int = 5) -> list[tuple[float, list[str], list[tuple[str, float]]]]:
    """Per line: (probability of vulnerable code, identifiers the <s> token attended to most, attention map).
    Last layer, averaged over heads; the map gives every word of the line a 0-1 weight, least to most attended (lines cut at 64 tokens)."""
    import torch
    tok, model = _load()
    out = []
    for s in range(0, len(lines), 32):
        enc = tok(lines[s:s + 32], truncation=True, max_length=MAX_LEN, padding=True, return_tensors="pt")
        with torch.no_grad():
            res = model(**enc, output_attentions=True)
        cls_attention = res.attentions[-1].mean(1)[:, 0, :]  # average over heads, row of the <s> token
        for i, p in enumerate(res.logits.softmax(-1)[:, 1].tolist()):
            words = _words(tok, enc["input_ids"][i].tolist(), cls_attention[i].tolist())
            best = {}
            for text, w in words:
                if re.fullmatch(r"[A-Za-z_]\w+", text.strip()):
                    best[text.strip()] = max(best.get(text.strip(), 0), w)
            lo, hi = min((w for _, w in words), default=0), max((w for _, w in words), default=0)
            out.append((p, sorted(best, key=best.get, reverse=True)[:top],  # min-max: the map shows relative focus
                        [(t, round((w - lo) / ((hi - lo) or 1), 2)) for t, w in words]))
    return out


def annotate(findings):
    """Adds the CodeBERT view to findings with a code line as evidence; leaves risk to the XGBoost nudge."""
    if not available():
        return findings
    targets = [(f, re.sub(r"^L\d+: ", "", e)) for f in findings for e in f.evidence[:1] if re.match(r"L\d+: ", e)]
    for (f, _), (p, words, attention) in zip(targets, insights([line for _, line in targets])):
        f.codebert_score, f.codebert_tokens, f.codebert_attention = round(p, 3), words, attention
        f.exploit_factors.append(f"CodeBERT rates the evidence {p:.0%} likely vulnerable; its attention was highest on "
                                 + ", ".join(words))
    return findings


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python -m app.modules.ml.codebert <LVDAndro csv>")
    print(json.dumps(train(sys.argv[1]), indent=2))
