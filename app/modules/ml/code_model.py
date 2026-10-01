"""ML-assisted risk (proposal Phases 4 and 8): a line-level vulnerable-code classifier trained on LVDAndro.

Train:   python -m app.modules.ml.code_model data/lvdandro/LVDAndro_SourceFiles_MobSF_Processed.csv
Runtime: score_findings(findings) - rules stay the basis; the model only nudges risk and explains itself with
SHAP values computed by XGBoost's built-in TreeSHAP (pred_contribs), so no separate shap package is needed.
"""
import json
import re
import sys
from collections import Counter
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).parent
MODEL, META = HERE / "model.json", HERE / "meta.json"
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

# Hand-made API-security indicators (proposal Phase 4 feature list); their names appear in the SHAP explanations.
SIGNALS = {k: re.compile(v) for k, v in {
    "log_call": r"\bLog\.[vdiwe]\(|printStackTrace\(|System\.out\.print",
    "http_url": r"http://",
    "https_url": r"https://",
    "ip_literal": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    "key_like_literal": r"AIza[\w-]{35}|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\"[A-Za-z0-9+/=_-]{32,}\"",
    "secret_word": r"(?i)secret|passw|pwd|token|api_?key|credential",
    "crypto_api": r"Cipher\.getInstance|SecretKeySpec|MessageDigest|KeyGenerator|IvParameterSpec",
    "weak_crypto": r"(?i)\"(?:des|rc4|md5|sha-?1)\b|/ecb/|\"aes\"",
    "tls_api": r"SSLContext|TrustManager|HostnameVerifier|X509|onReceivedSslError|SSLSocketFactory",
    "webview_setting": r"setJavaScriptEnabled|addJavascriptInterface|setAllowFileAccess|setAllowUniversalAccess"
                       r"|setWebContentsDebuggingEnabled",
    "raw_sql": r"rawQuery|execSQL|SQLiteDatabase",
    "external_storage": r"getExternalStorage|getExternalFilesDir|getExternalCacheDir",
    "file_write": r"openFileOutput|FileOutputStream|FileWriter|getDir\(|createTempFile",
    "world_mode": r"MODE_WORLD_",
    "shared_prefs": r"SharedPreferences|putString\(",
    "hidden_view": r"setVisibility\(\s*(?:View\.)?(?:GONE|INVISIBLE|[48])\s*\)",
    "url_param": r"[?&]\w+=",
    "intent_ipc": r"sendBroadcast|getIntent\(|startActivity\(|registerReceiver",
    "random": r"new Random\(|Math\.random",
    "base64": r"Base64\.",
    "clipboard": r"ClipboardManager|setPrimaryClip",
    "network_api": r"HttpURLConnection|OkHttp|Retrofit|new URL\(",
}.items()}


def vectorize(lines, vocab):
    """Sparse 0/1 matrix: signals first, then vocabulary tokens (same function for training and runtime)."""
    from scipy.sparse import csr_matrix
    index = {t: len(SIGNALS) + i for i, t in enumerate(vocab)}
    rows, cols = [], []
    for r, line in enumerate(lines):
        hits = [c for c, rx in enumerate(SIGNALS.values()) if rx.search(line)]
        hits += sorted({index[t] for t in TOKEN.findall(line) if t in index})
        rows += [r] * len(hits)
        cols += hits
    return csr_matrix(([1.0] * len(rows), (rows, cols)), shape=(len(lines), len(SIGNALS) + len(vocab)))


def split(csv_path: str):
    """(fit_df, test_df): the same split for every model, so their test metrics compare."""
    import pandas as pd
    from sklearn.model_selection import train_test_split

    df = pd.read_csv(csv_path, usecols=["Code", "Vulnerability_status"]).dropna()
    df["Code"] = df["Code"].astype(str).str.strip()
    df = df[df["Code"].str.len() > 2].drop_duplicates(["Code", "Vulnerability_status"])
    train_df, test_df = train_test_split(df, test_size=0.2, stratify=df["Vulnerability_status"], random_state=42)
    # ponytail: negatives downsampled to 8:1 for training speed; the test set keeps the real ~1.8% prevalence
    pos = train_df[train_df["Vulnerability_status"] == 1]
    neg = train_df[train_df["Vulnerability_status"] == 0].sample(n=8 * len(pos), random_state=42)
    return pd.concat([pos, neg]), test_df


def train(csv_path: str):
    import numpy as np
    import xgboost as xgb
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score

    fit_df, test_df = split(csv_path)
    vocab = [t for t, _ in Counter(t for line in fit_df["Code"] for t in set(TOKEN.findall(line))).most_common(300)]
    X_fit, y_fit = vectorize(fit_df["Code"], vocab), fit_df["Vulnerability_status"].to_numpy()
    X_test, y_test = vectorize(test_df["Code"], vocab), test_df["Vulnerability_status"].to_numpy()

    models = {
        "random_forest": RandomForestClassifier(n_estimators=200, class_weight="balanced_subsample", n_jobs=-1,
                                                random_state=42).fit(X_fit, y_fit),
        "xgboost": xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.8,
                                     colsample_bytree=0.8, n_jobs=-1, random_state=42).fit(X_fit, y_fit),
    }
    metrics = {}
    for name, model in models.items():
        prob = model.predict_proba(X_test)[:, 1]
        pred = (prob >= 0.5).astype(int)
        metrics[name] = {"precision": precision_score(y_test, pred), "recall": recall_score(y_test, pred),
                         "f1": f1_score(y_test, pred), "accuracy": accuracy_score(y_test, pred),
                         "roc_auc": roc_auc_score(y_test, prob)}
        metrics[name] = {k: round(float(v), 4) for k, v in metrics[name].items()}
    models["xgboost"].save_model(MODEL)  # deployed: native TreeSHAP explanations; RF kept as the comparison baseline
    META.write_text(json.dumps({
        "dataset": Path(csv_path).name, "train_rows": int(len(fit_df)), "test_rows": int(len(test_df)),
        "test_positive_rate": round(float(np.mean(y_test)), 4), "deployed": "xgboost", "metrics": metrics,
        "features": list(SIGNALS) + [f"token:{t}" for t in vocab], "vocab": vocab}, indent=1), encoding="utf-8")
    return metrics


@lru_cache(maxsize=1)
def _load():
    import xgboost as xgb
    booster = xgb.Booster()
    booster.load_model(MODEL)
    return booster, json.loads(META.read_text(encoding="utf-8"))


def explain(lines: list[str], top: int = 3) -> list[tuple[float, list[tuple[str, float]]]]:
    """Per line: (probability of vulnerable code, top positive SHAP contributions)."""
    import xgboost as xgb
    booster, meta = _load()
    X = xgb.DMatrix(vectorize(lines, meta["vocab"]))
    probs, contribs = booster.predict(X), booster.predict(X, pred_contribs=True)
    out = []
    for p, row in zip(probs, contribs):
        best = sorted(((meta["features"][i], float(v)) for i, v in enumerate(row[:-1]) if v > 0), key=lambda x: -x[1])
        out.append((float(p), [(n, round(v, 2)) for n, v in best[:top]]))
    return out


def score_findings(findings):
    """Scores each finding's code evidence and nudges its risk by at most +/-20% (x0.8 .. x1.2)."""
    if not MODEL.exists():
        return findings  # ponytail: no trained model shipped -> rules-only risk
    targets = [(f, re.sub(r"^L\d+: ", "", e)) for f in findings for e in f.evidence[:3] if re.match(r"L\d+: ", e)]
    if targets:
        for (f, _), (p, top) in zip(targets, explain([line for _, line in targets])):
            if f.ml_score is None or p > f.ml_score:
                f.ml_score, f.ml_top = round(p, 3), top
    for f in findings:
        if f.ml_score is not None:
            f.risk_score = round(min(100.0, f.risk_score * (0.8 + 0.4 * f.ml_score)), 1)
            signals = ", ".join(f"{n} +{v}" for n, v in f.ml_top) or "none"
            f.exploit_factors.append(f"ML model rates the evidence {f.ml_score:.0%} likely vulnerable (SHAP: {signals})")
    return sorted(findings, key=lambda f: -f.risk_score)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python -m app.modules.ml.code_model <LVDAndro csv>")
    print(json.dumps(train(sys.argv[1]), indent=2))
