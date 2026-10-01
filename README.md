# AndroGuard
An Explainable Static Security Analysis and Risk Assessment Platform for Android Applications

Pipeline: **M3** validate, SHA-256, decompile (apktool + jadx, bundletool for AAB) → **M1** 28 APK rules + **M2** 17 API
rules + OSV dependency check with NVD CVSS/CWE + FlowDroid data flows → **M4** evidence correlation, exploitability and
risk score → **ML** XGBoost trained on LVDAndro nudges the risk and explains itself with SHAP; an optional fine-tuned
CodeBERT adds its own score and the code tokens its attention focused on. Findings map to OWASP MASVS/MASWE and carry
evidence and a fix. Scans stop after `ANDROGUARD_TOOL_TIMEOUT` seconds per tool (default 900) and can be cancelled.

## Run from Docker Hub (no setup)
Everything is in the image: web app, CLI, apktool, jadx, bundletool, FlowDroid, XGBoost and CodeBERT. Give Docker about
8 GB of memory (jadx alone takes up to 4 GB). Built for x86-64; Apple Silicon Macs run it under emulation, slower.
```bash
docker run -d -p 8000:8000 -v androguard-db:/srv/db --name androguard minhal128/androguard
docker exec -it androguard python -m app.manage create-superadmin you@example.com
```
Then open http://localhost:8000 (sign in with that account for the admin CRM). Scan from the command line instead:
`docker run --rm -v "${PWD}:/work" minhal128/androguard python -m app /work/app.apk /work/report.json`

## Setup
- Python 3.12+ and Java 11+, then `pip install -r requirements.txt`
- Put apktool (`apktool.bat`/`apktool` + `apktool_x.y.z.jar`) in `tools/apktool/` and the unzipped jadx release in
  `tools/jadx/` (or have both on PATH). For `.aab`, put bundletool's jar in `tools/bundletool/` (or set `BUNDLETOOL_JAR`).
- Optional data flows: FlowDroid's `soot-infoflow-cmd.jar` and `SourcesAndSinks.txt` in `tools/flowdroid/`, with
  `platforms/android-33/android.jar` beside them. Without them scans skip this step.
- Optional CodeBERT: `pip install torch transformers`, base model in `data/models/codebert-base`, then train (below).
- PDF reports use WeasyPrint when its Pango libraries are present (Linux/Docker), otherwise headless Edge/Chrome.

## Run
| What | Command |
|---|---|
| Scan one app | `python -m app app.apk report.json` |
| Scan a folder (PowerShell) | `Get-ChildItem C:\apks\*.apk \| ForEach-Object { python -m app $_.FullName "$($_.DirectoryName)\$($_.BaseName)-report.json" }` |
| Web app | `uvicorn app.api:app` then open http://127.0.0.1:8000 (SQLite by default, `DATABASE_URL` for PostgreSQL) |
| Web app in Docker with PostgreSQL | `docker compose up` then open http://localhost:8000 (pulls the published image; `--build` builds from source and needs the fine-tuned CodeBERT in `data/models/codebert-lvdandro`) |
| Create the superadmin (CRM) | `python -m app.manage create-superadmin you@example.com` (password from `ANDROGUARD_PASSWORD` or a prompt) |
| Retrain the XGBoost model | `python -m app.modules.ml.code_model data/lvdandro/LVDAndro_SourceFiles_MobSF_Processed.csv` |
| Fine-tune CodeBERT | `python -m app.modules.ml.codebert data/lvdandro/LVDAndro_SourceFiles_MobSF_Processed.csv` |
| Benchmark | `python -m eval.benchmark dev` / `heldout` / `benign` (APKs in `data/apks/`, results in `eval/results*.md`) |
| FlowDroid on DroidBench | `python -m eval.droidbench` (APKs in `data/droidbench/`, results in `eval/results_droidbench.md`) |
| Tests | `python tests/test_m1.py` (also `test_m2`, `test_m3_fixes`, `test_m4`, `test_api`) |

Reports can contain real keys found in the scanned app: keep them private and out of Git.
