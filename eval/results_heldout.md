# AndroGuard benchmark, heldout set (DIVA, Sieve, InjuredAndroid, Allsafe, Vuldroid)

Precision **0.875**, recall **0.946**, F1 **0.909** (TP 35, FP 5, FN 2; unit = app x category, method in heldout.json)

| Category | TP | FP | FN |
|---|---|---|---|
| Hardcoded Secrets | 1 | 1 | 2 |
| Insecure Data Storage | 5 | 0 | 0 |
| Insecure Cryptography | 2 | 0 | 0 |
| Exported Components | 5 | 0 | 0 |
| Insecure Permissions | 5 | 0 | 0 |
| Insecure WebView | 4 | 0 | 0 |
| Cleartext Traffic | 5 | 0 | 0 |
| Improper SSL/TLS Validation | 2 | 0 | 0 |
| Hardcoded API keys/secrets | 3 | 0 | 0 |
| Insecure API Endpoints | 2 | 1 | 0 |
| HTTP Endpoints | 0 | 3 | 0 |
| Excessive API Permissions | 1 | 0 | 0 |

## Prioritization: rule-only baseline vs hybrid
Relevant = the finding's category is one of the app's documented vulnerabilities.

| Ordering | Precision@5 | Precision@10 | Mean average precision |
|---|---|---|---|
| Rule-only (severity, then confidence) | 0.64 | 0.68 | 0.734 |
| + M4 exploitability and attack chains | 0.84 | 0.78 | 0.811 |
| + ML-assisted risk (final score) | 0.84 | 0.76 | 0.806 |

## Scan time and memory

| App | APK (MB) | Findings | Time (s) | Peak RAM (MB) |
|---|---|---|---|---|
| DIVA | 1.4 | 15 | 45.2 | 1114 |
| Sieve | 0.4 | 23 | 12.6 | 1517 |
| InjuredAndroid | 23.6 | 21 | 73.4 | 2522 |
| Allsafe | 10.4 | 23 | 71.1 | 4551 |
| Vuldroid | 4.6 | 17 | 26.3 | 2967 |

| App | Category | Outcome |
|---|---|---|
| DIVA | Hardcoded Secrets | FN |
| DIVA | Insecure Data Storage | TP |
| DIVA | Exported Components | TP |
| DIVA | Insecure Permissions | TP |
| DIVA | Insecure WebView | TP |
| DIVA | Cleartext Traffic | TP |
| DIVA | Improper SSL/TLS Validation | TP |
| DIVA | HTTP Endpoints | FP |
| Sieve | Hardcoded Secrets | FP |
| Sieve | Insecure Data Storage | TP |
| Sieve | Exported Components | TP |
| Sieve | Insecure Permissions | TP |
| Sieve | Cleartext Traffic | TP |
| Sieve | Improper SSL/TLS Validation | TP |
| InjuredAndroid | Hardcoded Secrets | FN |
| InjuredAndroid | Insecure Data Storage | TP |
| InjuredAndroid | Insecure Cryptography | TP |
| InjuredAndroid | Exported Components | TP |
| InjuredAndroid | Insecure Permissions | TP |
| InjuredAndroid | Insecure WebView | TP |
| InjuredAndroid | Cleartext Traffic | TP |
| InjuredAndroid | Hardcoded API keys/secrets | TP |
| InjuredAndroid | Insecure API Endpoints | TP |
| InjuredAndroid | HTTP Endpoints | FP |
| InjuredAndroid | Excessive API Permissions | TP |
| Allsafe | Hardcoded Secrets | TP |
| Allsafe | Insecure Data Storage | TP |
| Allsafe | Insecure Cryptography | TP |
| Allsafe | Exported Components | TP |
| Allsafe | Insecure Permissions | TP |
| Allsafe | Insecure WebView | TP |
| Allsafe | Cleartext Traffic | TP |
| Allsafe | Hardcoded API keys/secrets | TP |
| Allsafe | Insecure API Endpoints | TP |
| Allsafe | HTTP Endpoints | FP |
| Vuldroid | Insecure Data Storage | TP |
| Vuldroid | Exported Components | TP |
| Vuldroid | Insecure Permissions | TP |
| Vuldroid | Insecure WebView | TP |
| Vuldroid | Cleartext Traffic | TP |
| Vuldroid | Hardcoded API keys/secrets | TP |
| Vuldroid | Insecure API Endpoints | FP |

## Notes
- Held-out scores: none of these apps was used to write or tune the rules, and the rules were not changed after this run.
- Documented issues that live only in native or Flutter code are listed as out of scope: the scanner reads the manifest, resources and decompiled Java/Kotlin.
