# AndroGuard benchmark, dev set (InsecureBankv2, AndroGoat, InsecureShop, OVAA)

Precision **1.0**, recall **0.947**, F1 **0.973** (TP 36, FP 0, FN 2; unit = app x category, method in ground_truth.json)

| Category | TP | FP | FN |
|---|---|---|---|
| Hardcoded Secrets | 3 | 0 | 1 |
| Insecure Data Storage | 4 | 0 | 0 |
| Insecure Cryptography | 3 | 0 | 0 |
| Exported Components | 4 | 0 | 0 |
| Insecure Permissions | 4 | 0 | 0 |
| Insecure WebView | 4 | 0 | 0 |
| Cleartext Traffic | 3 | 0 | 0 |
| Improper SSL/TLS Validation | 3 | 0 | 0 |
| Hardcoded API keys/secrets | 2 | 0 | 0 |
| Insecure API Endpoints | 1 | 0 | 0 |
| HTTP Endpoints | 3 | 0 | 0 |
| Sensitive Data in URLs | 1 | 0 | 0 |
| Excessive API Permissions | 1 | 0 | 0 |
| Vulnerable Dependency | 0 | 0 | 1 |

## Prioritization: rule-only baseline vs hybrid
Relevant = the finding's category is one of the app's documented vulnerabilities.

| Ordering | Precision@5 | Precision@10 | Mean average precision |
|---|---|---|---|
| Rule-only (severity, then confidence) | 0.95 | 0.95 | 0.954 |
| + M4 exploitability and attack chains | 1.0 | 0.975 | 0.964 |
| + ML-assisted risk (final score) | 1.0 | 1.0 | 0.965 |

## Scan time and memory

| App | APK (MB) | Findings | Time (s) | Peak RAM (MB) |
|---|---|---|---|---|
| InsecureBankv2 | 3.3 | 23 | 75.1 | 2071 |
| AndroGoat | 6.8 | 23 | 61.7 | 3910 |
| InsecureShop | 4.5 | 22 | 52.5 | 3134 |
| OVAA | 4.0 | 19 | 35.0 | 3446 |

| App | Category | Outcome |
|---|---|---|
| InsecureBankv2 | Hardcoded Secrets | TP |
| InsecureBankv2 | Insecure Data Storage | TP |
| InsecureBankv2 | Insecure Cryptography | TP |
| InsecureBankv2 | Exported Components | TP |
| InsecureBankv2 | Insecure Permissions | TP |
| InsecureBankv2 | Insecure WebView | TP |
| InsecureBankv2 | Cleartext Traffic | TP |
| InsecureBankv2 | Improper SSL/TLS Validation | TP |
| InsecureBankv2 | HTTP Endpoints | TP |
| InsecureBankv2 | Excessive API Permissions | TP |
| AndroGoat | Hardcoded Secrets | TP |
| AndroGoat | Insecure Data Storage | TP |
| AndroGoat | Insecure Cryptography | TP |
| AndroGoat | Exported Components | TP |
| AndroGoat | Insecure Permissions | TP |
| AndroGoat | Insecure WebView | TP |
| AndroGoat | Cleartext Traffic | TP |
| AndroGoat | Improper SSL/TLS Validation | TP |
| AndroGoat | Hardcoded API keys/secrets | TP |
| AndroGoat | HTTP Endpoints | TP |
| InsecureShop | Hardcoded Secrets | FN |
| InsecureShop | Insecure Data Storage | TP |
| InsecureShop | Exported Components | TP |
| InsecureShop | Insecure Permissions | TP |
| InsecureShop | Insecure WebView | TP |
| InsecureShop | Cleartext Traffic | TP |
| InsecureShop | Improper SSL/TLS Validation | TP |
| InsecureShop | Hardcoded API keys/secrets | TP |
| InsecureShop | Vulnerable Dependency | FN |
| OVAA | Hardcoded Secrets | TP |
| OVAA | Insecure Data Storage | TP |
| OVAA | Insecure Cryptography | TP |
| OVAA | Exported Components | TP |
| OVAA | Insecure Permissions | TP |
| OVAA | Insecure WebView | TP |
| OVAA | Insecure API Endpoints | TP |
| OVAA | HTTP Endpoints | TP |
| OVAA | Sensitive Data in URLs | TP |

## Notes
- Development-set scores: rules were adjusted after the first run on these same apps (first run: precision 0.727, recall 0.774, F1 0.75). results_heldout.md has the held-out test on apps never used for the rules.
- Remaining FN: InsecureShop credentials stored as map.put("shopuser", "!ns3csh0p") (no generic rule without false positives) and its vulnerable upload library (no OSV advisory for the bundled versions).
