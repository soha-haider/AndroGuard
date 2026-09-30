# AndroGuard
An Explainable Static Security Analysis and Risk Assessment Platform for Android Applications

Pipeline: **M3** validate, SHA-256, decompile (apktool + jadx, bundletool for AAB) → **M1** 28 APK rules + **M2** 17 API
rules + OSV dependency check → **M4** evidence correlation, exploitability and risk score → **ML** XGBoost trained on
LVDAndro nudges the risk and explains itself with SHAP. Findings map to OWASP MASVS/MASWE and carry evidence and a fix.

## Setup
- Python 3.12+ and Java 11+, then `pip install -r requirements.txt`
- Put apktool (`apktool.bat`/`apktool` + `apktool_x.y.z.jar`) in `tools/apktool/` and the unzipped jadx release in
  `tools/jadx/` (or have both on PATH). For `.aab` set `BUNDLETOOL_JAR` to bundletool's jar.
- PDF reports use WeasyPrint when its Pango libraries are present (Linux/Docker), otherwise headless Edge/Chrome.

## Run
| What | Command |
|---|---|
| Scan one app | `python -m app app.apk report.json` |
| Scan a folder (PowerShell) | `Get-ChildItem C:\apks\*.apk \| ForEach-Object { python -m app $_.FullName "$($_.DirectoryName)\$($_.BaseName)-report.json" }` |
| Web app | `uvicorn app.api:app` then open http://127.0.0.1:8000 (SQLite by default, `DATABASE_URL` for PostgreSQL) |
| Create the superadmin (CRM) | `python -m app.manage create-superadmin you@example.com` (password from `ANDROGUARD_PASSWORD` or a prompt) |
| Retrain the ML model | `python -m app.modules.ml.code_model data/lvdandro/LVDAndro_SourceFiles_MobSF_Processed.csv` |
| Benchmark | `python -m eval.benchmark` (APKs in `data/apks/`, results in `eval/results.md`) |
| Tests | `python tests/test_m1.py` (also `test_m2`, `test_m3_fixes`, `test_m4`, `test_api`) |

Reports can contain real keys found in the scanned app: keep them private and out of Git.
