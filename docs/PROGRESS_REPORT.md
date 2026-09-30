# AndroGuard progress report

30 September 2026 · branch `feat/m4-eval-web-ml` · proposal: CT-499 FYDP, "An Explainable Static Security Analysis and Risk Assessment Platform for Android Applications"

## Summary

| | |
|---|---|
| Done | **about 78%** of the proposal (77.8% weighted by effort) |
| Remaining | **about 22%**: CodeBERT, a held-out evaluation, FlowDroid data flow, Docker deployment, small items |
| Schedule | The Gantt chart runs September 2026 to May 2027. We are at the end of month one, so the work is well ahead of plan. |
| Proof | Every item under "What is done" was run on 30 September 2026. The outputs and screenshots below come from those runs. |

The accounts, free trial and admin CRM were not in the proposal. They add product value but move the proposal percentage by only about 2%.

## Progress by proposal phase

Weights are the effort share of each phase (the same weights as the earlier milestone table). "Done" is an estimate of how much of that phase exists and works.

| # | Phase | Weight | Done | What exists | What is missing |
|---|---|---|---|---|---|
| 1 | Literature review and requirements | 2 | 100% | Proposal, scope, 16 categories | |
| 2 | Environment and tool setup | 5 | 75% | Python, FastAPI, SQLAlchemy, React, apktool, jadx, bundletool, scikit-learn, XGBoost | Docker, Redis, a PostgreSQL run, FlowDroid, CodeBERT/Transformers, Ubuntu |
| 3 | Datasets and benchmarks | 10 | 80% | LVDAndro for ML; InsecureBankv2, AndroGoat, InsecureShop and OVAA with ground truth | Held-out apps (DIVA, Ghera, Vuldroid, OWApp), DroidBench, benign apps |
| 4 | API-security ML model | 13 | 70% | Random Forest vs XGBoost, SHAP, exported model | CodeBERT representations |
| 5 | Core static-analysis engine | 15 | 95% | 45 rules over 16 categories, CLI scanner | Data-flow analysis |
| 6 | Input processing and dependency matching | 10 | 85% | Validation, SHA-256, isolated workspace, AAB through bundletool, OSV | NVD, scan timeout and cancel, a real `.aab` test |
| 7 | Correlation and standardization | 8 | 90% | Standard finding schema, attack chains | Data-flow based correlation |
| 8 | Risk, exploitability and explainable AI | 12 | 60% | Exploitability with reasons, risk score, ML-assisted risk, SHAP | CodeBERT attention maps, OpenAI summaries (optional) |
| 9 | Remediation knowledge base and web app | 15 | 92% | Web app, HTML/PDF reports, accounts, CRM | Showing each finding's confidence value and the CodeBERT insights |
| 10 | Testing, evaluation and deployment | 10 | 40% | Automated tests, development-set benchmark | Held-out evaluation, rule-only baseline comparison, time and memory measurement, Docker deployment |
| | **Total** | **100** | **77.8%** | | |

## What is done, and proof that it works

### 1. Input processing (M3), phase 6
- Accepts `.apk` and `.aab`; checks the extension, the ZIP structure and the manifest entry; hashes the file with SHA-256.
- Converts AAB to APK with bundletool, then decompiles with apktool (`-s`) and jadx (`-r`, 4 GB heap cap).
- Works inside a temporary isolated workspace that is deleted after every scan.
- Reads bundled library versions and checks them against OSV (8 lookups in parallel).

Proof:
```
$ python tests/test_m3_fixes.py
[OK] M3 fixes check passed
$ python tests/test_m3.py
[✓] OSV Query completed. Retrieved 1 findings for test package.
    - [GHSA-3cqm-mf7h-prrj] Square OkHttp can accept the wrong certificate
```

### 2. APK security analyzer (M1), phase 5
28 deterministic rules over the manifest, network security config, `strings.xml`, assets and the decompiled Java. It covers the 8 APK categories: hardcoded secrets, insecure data storage, insecure cryptography, exported components, insecure permissions, insecure WebView, cleartext traffic and improper SSL/TLS validation.

Each finding carries `file:line` evidence, severity, confidence, the OWASP MASVS/MASWE mapping and the remediation.

Proof:
```
$ python tests/test_m1.py
[OK] M1 check passed: 35 findings, all 28 rules fired, negatives clean
```

### 3. API security analyzer (M2), phase 5
17 rules for the 8 API categories: hardcoded API keys and secrets, insecure API endpoints, HTTP endpoints, sensitive data in URLs, weak authentication, insecure TLS configuration and excessive API permissions. It also scans React Native / Hermes bundles.

Proof:
```
$ python tests/test_m2.py
[OK] M2 check passed: 25 findings, all 17 rules fired, negatives clean
```

### 4. Correlation, exploitability and risk (M4), phases 7 and 8
- Every finding gets an exploitability rating with its reasons, for example "any installed app can reach it" or "a network attacker can read it".
- Attack chains link findings that combine, such as cleartext allowed plus an `http://` endpoint, or a hardcoded key plus data stored on the device.
- Risk score (0 to 100) = severity x exploitability x confidence. The app risk is the worst finding.

Proof:
```
$ python tests/test_m4.py
[OK] M4 check passed: top risk EXPORTED-COMPONENT-1 (72.0), app risk HIGH
```
On InsecureBankv2 it reports 23 findings, 15 highly exploitable, 8 in attack chains, and app risk HIGH (72/100).

### 5. ML-assisted risk with explanations, phases 4 and 8
- A line-level classifier trained on LVDAndro (SourceFiles/MobSF subset): 78,516 training rows and 124,084 test rows at the real 1.76% vulnerable rate.
- Features: 22 API-security signals plus 300 code tokens.

| Model | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| Random Forest | 0.36 | 0.93 | 0.52 | 0.981 |
| **XGBoost (deployed)** | **0.65** | **0.86** | **0.74** | **0.982** |

- SHAP contributions come from XGBoost's built-in TreeSHAP, and the top signals are shown with each finding.
- The model changes a finding's risk by at most ±20%. It never creates a finding by itself; the rules stay the basis.

Source: `app/modules/ml/meta.json`.

### 6. Evaluation, phases 3 and 10
- Apps: InsecureBankv2, AndroGoat, InsecureShop and OVAA. Unit: app x category.
- Ground truth: each app's official vulnerability list.
- First run: precision 0.727, recall 0.774, F1 0.75.
- Now: **precision 1.00, recall 0.947, F1 0.973** (TP 36, FP 0, FN 2).
- The two misses, both in InsecureShop: credentials stored through `map.put`, and a library with no OSV advisory.
- **These are development-set scores.** The rules were fixed using these same apps, so a test on new apps is still needed.

Source: `eval/results.md`, and `python -m eval.benchmark` reproduces it.

### 7. Web application, phase 9
- Flow: upload, then live progress, then the report, then HTML and PDF downloads.
- The report is sorted by risk. Each finding shows its evidence, why it is exploitable, the linked findings, the OWASP mapping and the fix.
- While a scan runs, a phone mockup animates each stage: validating, decompiling (DEX bytes to Java), rules scanning the code, and scoring.
- Live run on 30 September: InsecureBankv2 uploaded through the browser finished in about a minute. The PDF downloaded at 247,771 bytes.

![Live scan with the phone mockup](screenshots/06-scan-live.jpg)

| Validating | Decompiling | Running rules | Scoring |
|---|---|---|---|
| ![](screenshots/07-phone-1-validating.jpg) | ![](screenshots/07-phone-2-decompiling.jpg) | ![](screenshots/07-phone-3-running-rules.jpg) | ![](screenshots/07-phone-4-scoring.jpg) |

![Report with a finding opened](screenshots/08-report.jpg)

### 8. Free trial, accounts and admin CRM (beyond the proposal)
- **Free trial:** 3 free scans per browser without an account. The 4th attempt asks the visitor to create an account.
- **Accounts:**
  - Sign-up moves the trial scans into the new account, which gets 20 scans.
  - Admins can change a user's limit. Admins and the superadmin have no limit.
- **Roles:**
  - user < admin < superadmin.
  - Only the superadmin changes roles or deletes accounts.
  - An admin cannot edit another admin.
  - The superadmin account is created only from the command line.
- **CRM:**
  - Overview: users, scans, high-risk results, trial-to-account conversion, a 14-day chart and recent scans.
  - Users: search, role, block and unblock, scan limit, notes, delete.
  - Scans: search, status filter, delete.
- **Security:**
  - scrypt password hashes and server-side sessions in an HttpOnly cookie.
  - 5 failed logins in 15 minutes lock that login.
  - Blocking a user signs them out.
  - Another user's scan returns 404.

Proof:
```
$ python tests/test_api.py
[OK] API check passed: free trial quota, ownership, signup claim, login limit, roles, block and delete
```
Live CRM numbers on 30 September: 2 users, 6 scans, 5 high-risk results, 1 failed scan, and 2 of 3 trial browsers converted to accounts (67%).

![My scans for a trial visitor](screenshots/09-my-scans-trial.jpg)
![CRM overview](screenshots/11-crm-overview.jpg)
![CRM users](screenshots/12-crm-users.jpg)
![CRM scans](screenshots/13-crm-scans.jpg)

### 9. Landing site
The landing page has these parts:
- a hero with an animated green grid and a real sample report
- how it works
- what every scan checks
- privacy
- why choose AndroGuard
- an auto-playing demo card
- a final call to action

It supports dark and light mode and phone widths, and respects reduced motion.

![Hero](screenshots/01-landing-hero.jpg)
![How it works](screenshots/02-landing-how.jpg)
![What every scan checks](screenshots/03-landing-checks.jpg)
![Why choose AndroGuard](screenshots/04-landing-why.jpg)
![Demo card](screenshots/05-landing-demo.jpg)

| Phone: landing | Phone: live scan |
|---|---|
| ![](screenshots/14-mobile-landing.jpg) | ![](screenshots/15-mobile-scanning.jpg) |

### 10. Privacy by design
- The uploaded file is saved under a server-chosen name and deleted when its scan ends. `tests/test_api.py` fails if any upload outlives its scan.
- The decompiled workspace is a temporary directory that is removed after every scan.
- Only the findings, the scores and the file's SHA-256 are stored.

## What remains (about 22%)

| Remaining work | Phases | Share | Size |
|---|---|---|---|
| CodeBERT representations and attention maps, shown in the report | 4, 8, 9 | ~8% | Large |
| Honest evaluation: held-out apps (DIVA, Ghera, Vuldroid, OWApp), benign apps for the false-positive rate, rule-only baseline vs the hybrid system, scan time and memory | 3, 10 | ~6% | Large |
| FlowDroid data flow for selected flows, checked on DroidBench | 2, 5, 6, 7 | ~3% | Medium |
| Docker with PostgreSQL and Redis, deployed on Ubuntu | 2, 10 | ~2% | Medium |
| Small items: NVD enrichment, a real `.aab` test, scan timeout and cancel, each finding's confidence shown in the web report, OpenAI summaries (optional) | 6, 8, 9 | ~3% | Small |

Robustness issues seen during testing:
- **No scan timeout.** If jadx hangs, the scan stays "running" until the server restarts. The proposal asks for cleanup after a timeout as well.
- **Out-of-memory failures show a raw JVM log.** On 30 September, the first scan of `Staff-App.apk` failed with "The paging file is too small for this operation to complete" while jadx was decompiling. The retry passed (9 findings, risk 72). A friendly message and one automatic retry would help.
- **The C: drive is full.** Later that day the drive had about 20 MB free, which stops Windows from growing the paging file and is the likely cause of the failure above. Scans need free space for the decompiled code, so free a few GB before a demo.

Not counted in the percentage: the final FYP report (thesis) and the presentation.

## Work log: what Claude did

Team commits before this work: project setup and the first M3 pipeline by Waleed Kashif and Soha (`60570e2`, `10fcd49`, `567fde4`, `5232e28`, `9b8e0a3`, `09d7bbe`). Everything below was done by Claude. The commits were made from the minhal128 account, with Claude as co-author.

| When | Commit | What |
|---|---|---|
| 29 Sep | | Read the proposal and the code, and reported what was done and the % progress. Recommended the architecture. |
| 29 Sep | `ed4dc9a` | M3 fixes: shell-free tool calls, bundletool AAB, package validation, SHA-256, OSV severity from real data, the Phase 7 finding schema. |
| 29 Sep | `1af3860` | M1 APK analyzer: 28 rules across 8 categories, CLI scanner, fixture test. |
| 29 Sep | `e3340d6` | Fixes from the first real run on InsecureBankv2: a key passed through a local variable, regex/UI names flagged as secrets, apktool.bat hanging the CLI. |
| 29 Sep | `d1137c5` | M2 API analyzer (17 rules), a one-command scanner for M1 + M2 + OSV, React Native support. |
| 29 Sep | | Two walkthrough videos: slides (`docs/AndroGuard_walkthrough.mp4`), and a terminal run with English voice-over of a real QuickPay APK scan (delivered as `Desktop/AndroGuard_scan_demo.mp4`, no longer at that path on 30 Sep). |
| 30 Sep | `0ab582b` | Performance: a 28 MB React Native app now scans in about 2.5 min instead of 7.5. |
| 30 Sep | `4472c89` | False positives on translated labels and React Native/Expo modules (8 of 9 HIGH findings on one real app were wrong). |
| 30 Sep | `6d6b8f0` | M4 exploitability, attack chains and risk score; the ML model (RF vs XGBoost) with SHAP. |
| 30 Sep | `9dd5b6c` | Four-app benchmark, and rule fixes from its misses (F1 0.75 to 0.973 on the development set). |
| 30 Sep | `c888fff` | Web app: FastAPI + React UI, scan database, HTML/PDF reports. |
| 30 Sep | not committed | Accounts, 3-scan free trial, roles and the admin CRM (`app/auth.py`, `app/manage.py`, `app/api.py`, `app/database`, `tests/test_api.py`). |
| 30 Sep | not committed | New site design: landing page with animated grid, green outlined cards, "Why choose" section, demo card, phone mockup on the scan page. |
| 30 Sep | not committed | Browser testing of every flow on desktop, phone, dark and light mode, and fixes for what it found. This report and its screenshots. |
| 30 Sep | | Full walkthrough video, 3 min 45 s, English voice-over and captions (`Desktop/AndroGuard_full_walkthrough.mp4`). It shows the website, a live free-trial scan with the phone mockup, the report and PDF, signup, the CRM, the phone layout, the tests, the benchmark, the ML metrics and the progress summary. |

Bugs found on real apps and fixed:
- **Scanner failures (Windows and memory):**
  - jadx exits with code 3 on most real apps, and `jadx.bat` turns every error into 1. Both used to stop the scan.
  - `apktool.bat` waited on `pause` and hung the CLI.
  - jadx used up to 70% of RAM and crashed. It is now capped at 4 GB.
- **Missed code:**
  - React Native/Hermes bundles over 1 MB were skipped, and their unquoted URLs were missed.
- **Wrong findings:**
  - Hardcoded credentials were missed in literal comparisons (`username.equals("devadmin")`), `user:pass@` URLs and promo codes.
  - AWS Cognito pool IDs were not treated as AWS keys.
  - `http://` inside protocol checks and error messages caused false alarms.
- **PDF:** Edge's launcher exits before the file is written, so PDFs were missing.
- **Website:**
  - The report showed the server's temporary file name instead of the real one.
  - The admin users table cut off the Block and Delete buttons.
  - The page overflowed sideways on phones.
  - The upload box accepted files after the free scans were used up.
  - The footer floated in the middle of short pages.

Current git state: `main` is at `4472c89`. Branch `feat/m4-eval-web-ml` has 3 commits that are not pushed yet, plus the uncommitted website work listed above.

## How to run

```bash
pip install -r requirements.txt
python -m app.manage create-superadmin you@example.com
python -m uvicorn app.api:app --port 8000
```

Open http://localhost:8000 and sign in with the superadmin to reach Admin. apktool and jadx go in `tools/` or on the PATH.

Tests:

```bash
python tests/test_m1.py
python tests/test_m2.py
python tests/test_m3_fixes.py
python tests/test_m4.py
python tests/test_api.py
```

On Windows, run `tests/test_m3.py` with `PYTHONIOENCODING=utf-8`, because it prints a ✓ that the default console encoding cannot show.
