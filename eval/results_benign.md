# AndroGuard benchmark, benign set (BinaryEye, PrivacyFriendlyNotes, Markor)

False-positive rate **0.375** (6 of 16 reported app x category pairs are false alarms; recall is not measured on benign apps)

| Category | TP | FP | FN |
|---|---|---|---|
| Hardcoded Secrets | 0 | 1 | 0 |
| Insecure Data Storage | 3 | 0 | 0 |
| Insecure Cryptography | 0 | 1 | 0 |
| Exported Components | 1 | 2 | 0 |
| Insecure Permissions | 3 | 0 | 0 |
| Insecure WebView | 1 | 0 | 0 |
| Cleartext Traffic | 2 | 0 | 0 |
| HTTP Endpoints | 0 | 2 | 0 |

## Scan time and memory

| App | APK (MB) | Findings | Time (s) | Peak RAM (MB) |
|---|---|---|---|---|
| BinaryEye | 8.3 | 18 | 79.6 | 2161 |
| PrivacyFriendlyNotes | 8.1 | 6 | 84.7 | 3893 |
| Markor | 11.5 | 49 | 71.3 | 3724 |

| App | Category | Outcome |
|---|---|---|
| BinaryEye | Insecure Data Storage | TP |
| BinaryEye | Insecure Cryptography | FP |
| BinaryEye | Exported Components | FP |
| BinaryEye | Insecure Permissions | TP |
| BinaryEye | Cleartext Traffic | TP |
| BinaryEye | HTTP Endpoints | FP |
| PrivacyFriendlyNotes | Insecure Data Storage | TP |
| PrivacyFriendlyNotes | Exported Components | TP |
| PrivacyFriendlyNotes | Insecure Permissions | TP |
| Markor | Hardcoded Secrets | FP |
| Markor | Insecure Data Storage | TP |
| Markor | Exported Components | FP |
| Markor | Insecure Permissions | TP |
| Markor | Insecure WebView | TP |
| Markor | Cleartext Traffic | TP |
| Markor | HTTP Endpoints | FP |

## Notes
- Rules were not changed after this run.
- A true label means the code or configuration really has the weakness; it does not mean the app is unsafe to use.
- Noisiest rules on benign apps: HTTP-ENDPOINT (URLs inside bundled JavaScript and hint strings), STORAGE-EXTERNAL (path lookups, not writes) and EXPORTED-COMPONENT (intended entry points such as widgets).
