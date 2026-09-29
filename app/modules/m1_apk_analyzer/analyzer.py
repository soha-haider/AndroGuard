import re
import xml.etree.ElementTree as ET
from collections import Counter
from functools import lru_cache
from pathlib import Path
from app.schemas.finding import StandardFinding

A = "{http://schemas.android.com/apk/res/android}"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
HS, DS, CR, EC, IP, WV, CT, TLS = ("Hardcoded Secrets", "Insecure Data Storage", "Insecure Cryptography",
                                   "Exported Components", "Insecure Permissions", "Insecure WebView",
                                   "Cleartext Traffic", "Improper SSL/TLS Validation")

# Rule knowledge base. MASWE IDs and MASVS mappings follow github.com/OWASP/maswe (weakness front matter).
# rule_id: (category, title, severity, confidence, masvs, maswe, cause, description, remediation)
KB = {
    "SECRET-PRIVATE-KEY": (HS, "Private key embedded in app", "HIGH", 0.95, ["MASVS-STORAGE-1"], ["MASWE-0004"],
        "A PEM private key block is shipped inside the package.",
        "Anyone can extract the key from the APK and impersonate the app/server or decrypt protected data.",
        "Remove the key from the package; keep private keys server-side or generate them in the Android Keystore."),
    "SECRET-CREDENTIAL": (HS, "Hardcoded password", "HIGH", 0.6, ["MASVS-STORAGE-1"], ["MASWE-0004"],
        "A password-named variable or string resource holds a literal value (API secrets are covered by M2).",
        "Hardcoded credentials are recoverable by decompiling the APK and give attackers direct access.",
        "Remove hardcoded credentials; authenticate against a server and keep user secrets in the Android Keystore."),
    "STORAGE-BACKUP": (DS, "Application data backup enabled", "MEDIUM", 0.9, ["MASVS-STORAGE-2"], ["MASWE-0006"],
        "android:allowBackup is true or not set (defaults to true).",
        "App-private data (tokens, databases, preferences) can be extracted via backup and restored elsewhere.",
        "Set android:allowBackup=\"false\" or exclude sensitive files with dataExtractionRules/fullBackupContent."),
    "STORAGE-WORLD-MODE": (DS, "World-readable/writable file mode", "HIGH", 0.9, ["MASVS-STORAGE-2"], ["MASWE-0001"],
        "A file, preference or database is created with MODE_WORLD_READABLE/WRITEABLE.",
        "Any app on the device can read or modify the data.",
        "Use MODE_PRIVATE and share data through a permission-protected ContentProvider or FileProvider."),
    "STORAGE-EXTERNAL": (DS, "Data written to shared external storage", "MEDIUM", 0.6,
        ["MASVS-STORAGE-1", "MASVS-STORAGE-2"], ["MASWE-0002"],
        "Code uses public external storage (getExternalStorageDirectory/getExternalStoragePublicDirectory).",
        "Files on shared storage are readable by other apps and the user, and survive uninstall.",
        "Keep sensitive files in internal storage (getFilesDir) and encrypt them if needed."),
    "STORAGE-PREFS-SECRET": (DS, "Sensitive value stored in SharedPreferences", "MEDIUM", 0.6, ["MASVS-STORAGE-1"],
        ["MASWE-0001"],
        "A password/token/secret-named key is written with SharedPreferences.putString().",
        "SharedPreferences are plaintext XML; values leak via root access, backups or other storage flaws.",
        "Use EncryptedSharedPreferences or encrypt values with a key held in the Android Keystore."),
    "STORAGE-SQL-SECRET": (DS, "Credentials stored in local SQLite database", "MEDIUM", 0.5, ["MASVS-STORAGE-1"],
        ["MASWE-0001"],
        "A CREATE TABLE statement defines password or credit-card columns.",
        "SQLite databases are unencrypted files; stored credentials are exposed if the database is extracted.",
        "Do not store credentials locally; if required, encrypt the database with a Keystore-backed key."),
    "STORAGE-LOG-SECRET": (DS, "Sensitive data written to logs", "MEDIUM", 0.5, ["MASVS-STORAGE-2"], ["MASWE-0005"],
        "An android.util.Log call references password/token/secret data.",
        "Logs are readable via adb, crash reporters and (on old Android) other apps.",
        "Remove sensitive values from log calls and strip debug logging from release builds."),
    "CRYPTO-WEAK-CIPHER": (CR, "Weak encryption algorithm", "HIGH", 0.9, ["MASVS-CRYPTO-1"], ["MASWE-0007"],
        "Cipher.getInstance() uses DES, 3DES, RC4, RC2 or Blowfish.",
        "These algorithms are broken or deprecated and can be brute-forced or cryptanalysed.",
        "Use AES-256-GCM or ChaCha20-Poly1305."),
    "CRYPTO-ECB": (CR, "Block cipher in ECB mode", "HIGH", 0.9, ["MASVS-CRYPTO-1"], ["MASWE-0007"],
        "Cipher.getInstance() uses ECB mode, or bare \"AES\" which defaults to ECB.",
        "ECB encrypts identical blocks identically, leaking plaintext patterns.",
        "Use an authenticated mode such as AES/GCM/NoPadding with a random IV per message."),
    "CRYPTO-RSA-PADDING": (CR, "RSA without OAEP padding", "MEDIUM", 0.8, ["MASVS-CRYPTO-1"], ["MASWE-0007"],
        "Cipher.getInstance() uses RSA with PKCS#1 v1.5 padding or no padding.",
        "PKCS#1 v1.5 and raw RSA are open to padding-oracle and malleability attacks.",
        "Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding."),
    "CRYPTO-WEAK-HASH": (CR, "Weak hash algorithm", "MEDIUM", 0.6, ["MASVS-CRYPTO-1"], ["MASWE-0008"],
        "MessageDigest.getInstance() uses MD2, MD4, MD5 or SHA-1.",
        "These hashes are collision-prone and unsuitable for integrity checks or password storage.",
        "Use SHA-256 or stronger; for passwords use PBKDF2, scrypt or Argon2."),
    "CRYPTO-HARDCODED-KEY": (CR, "Hardcoded cryptographic key", "HIGH", 0.85, ["MASVS-CRYPTO-2", "MASVS-STORAGE-1"],
        ["MASWE-0003"],
        "SecretKeySpec is built from a string or byte-array literal in the code.",
        "The key can be extracted from the APK, so all data encrypted with it can be decrypted.",
        "Generate and keep keys in the Android Keystore instead of embedding them."),
    "CRYPTO-STATIC-IV": (CR, "Static or zero initialization vector", "MEDIUM", 0.8, ["MASVS-CRYPTO-1"], ["MASWE-0007"],
        "IvParameterSpec is built from a constant string/byte array or an all-zero array.",
        "A reused IV makes encryption deterministic and, for CTR/GCM, breakable.",
        "Generate a fresh random IV per encryption with SecureRandom and store it with the ciphertext."),
    "EXPORTED-COMPONENT": (EC, "Exported component without permission protection", "MEDIUM", 0.9, ["MASVS-PLATFORM-1"],
        ["MASWE-0018"],
        "Component is exported (explicitly or via an intent-filter) and not protected by a strong permission.",
        "Any app on the device can start, bind to or query it, reaching internal functionality or data.",
        "Set android:exported=\"false\" or protect it with a signature-level permission and validate incoming intents."),
    "PERM-WEAK-CUSTOM": (IP, "Custom permission with weak protection level", "MEDIUM", 0.8, ["MASVS-PLATFORM-1"],
        ["MASWE-0018"],
        "A custom <permission> uses protectionLevel normal/dangerous (or none, which defaults to normal).",
        "Any installed app can obtain it, so components it guards are effectively open.",
        "Use android:protectionLevel=\"signature\" for permissions that guard app components."),
    "PERM-HIGH-RISK": (IP, "High-risk permissions requested", "LOW", 0.6, ["MASVS-PRIVACY-1"], ["MASWE-0066"],
        "The app requests permissions granting access to sensitive data or powerful capabilities.",
        "Raises the impact of any compromise and the privacy exposure of users.",
        "Remove permissions not strictly required; request the rest at runtime only when needed."),
    "WEBVIEW-JS": (WV, "JavaScript enabled in WebView", "LOW", 0.7, ["MASVS-PLATFORM-2"], ["MASWE-0035"],
        "WebSettings.setJavaScriptEnabled(true) is called.",
        "If the WebView renders untrusted or cleartext content, injected scripts run inside the app.",
        "Enable JavaScript only for trusted HTTPS content and restrict navigation in shouldOverrideUrlLoading."),
    "WEBVIEW-JS-BRIDGE": (WV, "JavaScript interface exposed to WebView", "HIGH", 0.8, ["MASVS-PLATFORM-2"], ["MASWE-0033"],
        "addJavascriptInterface() exposes a Java object to web content.",
        "Page scripts can call native methods; with untrusted content this leads to data theft or code execution.",
        "Avoid JS bridges or expose minimal @JavascriptInterface methods to trusted HTTPS origins only."),
    "WEBVIEW-FILE-ACCESS": (WV, "WebView file access enabled", "MEDIUM", 0.8, ["MASVS-PLATFORM-2"], ["MASWE-0034"],
        "WebSettings.setAllowFileAccess(true) is called.",
        "Web content can read local files through file:// URLs.",
        "Call setAllowFileAccess(false) and serve local content through WebViewAssetLoader."),
    "WEBVIEW-FILE-URL-ACCESS": (WV, "WebView lets file URLs access other origins", "HIGH", 0.9, ["MASVS-PLATFORM-2"],
        ["MASWE-0034"],
        "setAllowFileAccessFromFileURLs(true) or setAllowUniversalAccessFromFileURLs(true) is called.",
        "A malicious local HTML file can read app files and send them to any origin.",
        "Keep both settings false (the default since API 16)."),
    "WEBVIEW-DEBUGGING": (WV, "WebView remote debugging enabled", "MEDIUM", 0.9,
        ["MASVS-PLATFORM-2", "MASVS-RESILIENCE-4"], ["MASWE-0063"],
        "WebView.setWebContentsDebuggingEnabled(true) is called.",
        "Anyone with adb access can inspect and manipulate WebView content, cookies and JavaScript state.",
        "Enable it only in debug builds (guard with BuildConfig.DEBUG)."),
    "WEBVIEW-MIXED-CONTENT": (WV, "WebView allows mixed content", "MEDIUM", 0.8, ["MASVS-NETWORK-1", "MASVS-PLATFORM-2"],
        ["MASWE-0026"],
        "setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW) is called.",
        "HTTPS pages may load HTTP scripts and resources that a network attacker can modify.",
        "Use MIXED_CONTENT_NEVER_ALLOW."),
    "CLEARTEXT-TRAFFIC": (CT, "Cleartext HTTP traffic permitted", "MEDIUM", 0.9, ["MASVS-NETWORK-1"], ["MASWE-0026"],
        "The manifest or network security config allows unencrypted HTTP traffic.",
        "Traffic can be read and modified by anyone on the network path.",
        "Disable cleartext (usesCleartextTraffic / cleartextTrafficPermitted = false) and use HTTPS everywhere."),
    "TLS-TRUST-ALL": (TLS, "TrustManager accepts all certificates", "HIGH", 0.9, ["MASVS-NETWORK-1"], ["MASWE-0027"],
        "A custom X509TrustManager has an empty checkServerTrusted().",
        "Every certificate is accepted, enabling trivial man-in-the-middle attacks on HTTPS.",
        "Remove the custom TrustManager; use the network security config for custom CAs or pinning."),
    "TLS-HOSTNAME-ALL": (TLS, "Hostname verification disabled", "HIGH", 0.9, ["MASVS-NETWORK-1"], ["MASWE-0027"],
        "A HostnameVerifier always returns true, or ALLOW_ALL/Noop hostname verifiers are used.",
        "A valid certificate for any domain is accepted, enabling man-in-the-middle attacks.",
        "Use the default HostnameVerifier (HttpsURLConnection.getDefaultHostnameVerifier())."),
    "TLS-WEBVIEW-SSL-ERROR": (TLS, "WebView ignores SSL errors", "HIGH", 0.85, ["MASVS-NETWORK-1"], ["MASWE-0027"],
        "WebViewClient.onReceivedSslError() calls handler.proceed().",
        "The WebView loads pages despite invalid certificates, enabling man-in-the-middle attacks.",
        "Call handler.cancel() (the default) and fix the server certificate instead."),
    "TLS-USER-CA": (TLS, "User-installed CA certificates trusted", "MEDIUM", 0.9, ["MASVS-NETWORK-1"], ["MASWE-0027"],
        "The network security config trusts user CAs, or targetSdkVersion < 24 trusts them by default.",
        "A CA installed by the user or by malware can intercept the app's HTTPS traffic.",
        "Trust only system CAs (no <certificates src=\"user\"/> outside debug-overrides) and target API 24+."),
}

# Rules matched against decompiled Java, string resources and assets. A named group "ref" means the match
# points at an identifier that only counts if the same file assigns it a literal (see _assigned_literal).
CODE_RULES = {k: re.compile(v) for k, v in {
    "SECRET-PRIVATE-KEY": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    "SECRET-CREDENTIAL":  # skips validation/UI names such as PASSWORD_PATTERN or passwordHint
        # (?=\w+\s*=\s*") rejects the ~99% of words that are not assigned a string literal before the costlier checks
        r'(?i)\b(?=\w+\s*=\s*")(?!\w*(?:pattern|regex|format|hint|label|message|msg|error|title|text|field|view)\w*\s*=)'
        r'\w*(?:password|passwd|pwd|passphrase)\w*\s*=\s*"'
        r'(?!(?-i:[a-z_.]*(?:pass|pwd|secret)[a-z_.]*)")(?![^"]*\s)[^"]{4,}"'  # skip key names like "pref_password"
        r'|<string name="[^"]*(?:password|passwd|pwd)[^"]*">(?![^<]*(?:pass|pwd|secret))(?![^<]*\s)[^<]{4,}</string>',
    "STORAGE-WORLD-MODE":
        r"MODE_WORLD_(?:READABLE|WRITEABLE)"
        r"|\b(?:openFileOutput|getSharedPreferences|openOrCreateDatabase|getDir)\([^,;]+,\s*[123]\s*[,)]",
    "STORAGE-EXTERNAL": r"\bgetExternalStorage(?:Directory|PublicDirectory)\(",
    "STORAGE-PREFS-SECRET": r'(?i)\.putString\(\s*[\w."]*(?:password|passwd|pwd|token|secret|credential)',
    "STORAGE-SQL-SECRET": r"(?i)create\s+table[^;]*?(?:password|passwd|pwd|credit_?card)",
    "STORAGE-LOG-SECRET": r"(?i)\bLog\.[vdiwe]\([^;]*?(?:password|passwd|pwd|token|secret|credential)",
    "CRYPTO-WEAK-CIPHER": r'(?i)Cipher\.getInstance\(\s*"(?:DES|DESede|TripleDES|RC4|ARCFOUR|RC2|Blowfish)\b',
    "CRYPTO-ECB": r'(?i)Cipher\.getInstance\(\s*"(?:AES"|(?!RSA)[^"]*/ECB/)',
    "CRYPTO-RSA-PADDING": r'(?i)Cipher\.getInstance\(\s*"RSA(?:/[^/"]*/(?:PKCS1Padding|NoPadding))?"',
    "CRYPTO-WEAK-HASH": r'(?i)MessageDigest\.getInstance\(\s*"(?:MD2|MD4|MD5|SHA-?1)"',
    "CRYPTO-HARDCODED-KEY":
        r'new SecretKeySpec\(\s*(?:\w+\.decode\(\s*)?(?:"|(?:\w+\.)?(?P<ref>\w+)(?:\.getBytes\([^)]*\))?\s*[,)])',
    "CRYPTO-STATIC-IV":
        r'new IvParameterSpec\(\s*(?:"|new byte\[\s*\d+\s*\]\s*\)|(?:\w+\.)?(?P<ref>\w+)(?:\.getBytes\([^)]*\))?\s*[,)])',
    "WEBVIEW-JS": r"setJavaScriptEnabled\(\s*true\s*\)",
    "WEBVIEW-JS-BRIDGE": r"\.addJavascriptInterface\(",
    "WEBVIEW-FILE-ACCESS": r"\.setAllowFileAccess\(\s*true\s*\)",
    "WEBVIEW-FILE-URL-ACCESS": r"\.setAllow(?:Universal|File)AccessFromFileURLs\(\s*true\s*\)",
    "WEBVIEW-DEBUGGING": r"setWebContentsDebuggingEnabled\(\s*true\s*\)",
    "WEBVIEW-MIXED-CONTENT": r"setMixedContentMode\(\s*(?:0|[\w.]*MIXED_CONTENT_ALWAYS_ALLOW)\s*\)",
    "TLS-TRUST-ALL": r"checkServerTrusted\([^)]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*\}",
    "TLS-HOSTNAME-ALL":
        r"boolean verify\(\s*String\s+\w+,\s*SSLSession\s+\w+\)\s*\{\s*return\s+true;\s*\}"
        r"|ALLOW_ALL_HOSTNAME_VERIFIER|\bAllowAllHostnameVerifier\b|\bNoopHostnameVerifier\b",
    "TLS-WEBVIEW-SSL-ERROR": r"onReceivedSslError\([^)]*\)\s*\{[^}]*?\.proceed\(\)",
}.items()}
JADX_LOCAL = re.compile(r"(?:str|bArr|obj)\d*")  # jadx-generated local names; too generic to resolve by name
# Substring pre-check for rules whose regex has no literal prefix (they would otherwise probe every word of every file)
HINTS = {"SECRET-CREDENTIAL": ("pass", "pwd")}

# ponytail: prefix skip list for bundled libraries; swap for real library detection if FP/FN rates demand it
LIBRARY_PREFIXES = ("android/", "androidx/", "kotlin/", "kotlinx/", "com/google/", "okhttp3/", "okio/", "retrofit2/",
                    "com/squareup/", "org/apache/", "org/jetbrains/", "org/intellij/", "io/reactivex/", "com/facebook/",
                    "org/bouncycastle/", "org/spongycastle/", "javax/", "j$/", "org/json/", "com/fasterxml/")

HIGH_RISK_PERMISSIONS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "READ_CONTACTS",
    "WRITE_CONTACTS", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "READ_PHONE_STATE",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES", "WRITE_SETTINGS", "QUERY_ALL_PACKAGES", "GET_ACCOUNTS",
}
COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")
LAUNCHER_CATEGORIES = {"android.intent.category.LAUNCHER", "android.intent.category.LEANBACK_LAUNCHER"}


def _finding(rule_id, component, evidence, severity=None, kb=KB) -> StandardFinding:
    category, title, sev, confidence, masvs, maswe, cause, description, remediation = kb[rule_id]
    return StandardFinding(id=rule_id, title=title, severity=severity or sev, description=description,
                           category=category, cause=cause, evidence=evidence, affected_component=component,
                           confidence=confidence, masvs=masvs, maswe=maswe, remediation=remediation)


def _target_sdk(man, decompiled_dir: Path):
    sdk = man.find("uses-sdk")
    value = sdk.get(A + "targetSdkVersion") if sdk is not None else None
    yml = decompiled_dir / "apktool.yml"  # apktool moves uses-sdk out of the manifest into apktool.yml
    if value is None and yml.is_file():
        m = re.search(r"targetSdkVersion:\s*[\"']?(\d+)", yml.read_text(errors="ignore"))
        value = m.group(1) if m else None
    return int(value) if value and value.isdigit() else None


def _is_launcher(component) -> bool:
    for f in component.findall("intent-filter"):
        actions = {a.get(A + "name") for a in f.findall("action")}
        categories = {c.get(A + "name") for c in f.findall("category")}
        if "android.intent.action.MAIN" in actions and categories & LAUNCHER_CATEGORIES:
            return True
    return False


def _manifest_findings(man, decompiled_dir: Path) -> list[StandardFinding]:
    app = man.find("application")
    if app is None:
        app = ET.Element("application")
    target = _target_sdk(man, decompiled_dir)
    out = []

    backup = app.get(A + "allowBackup")
    if backup != "false":  # adb backup of app data is off by default from targetSdk 31
        out.append(_finding("STORAGE-BACKUP", "AndroidManifest.xml <application>",
                            [f"android:allowBackup={backup or 'not set (defaults to true)'}, targetSdkVersion={target}"],
                            "LOW" if target and target >= 31 else None))

    requested = sorted({p.get(A + "name", "") for p in man if p.tag in ("uses-permission", "uses-permission-sdk-23")})
    risky = [p for p in requested if p.removeprefix("android.permission.") in HIGH_RISK_PERMISSIONS]
    if risky:
        out.append(_finding("PERM-HIGH-RISK", "AndroidManifest.xml <uses-permission>", risky))

    weak = set()
    for p in man.findall("permission"):
        level = p.get(A + "protectionLevel") or "normal"
        if "signature" not in level and "privileged" not in level:
            weak.add(p.get(A + "name"))
            out.append(_finding("PERM-WEAK-CUSTOM", p.get(A + "name"), [f"protectionLevel={level}"]))

    def strong(perm):
        return perm is not None and perm not in weak

    for c in app:
        if c.tag not in COMPONENTS or c.get(A + "enabled") == "false" or _is_launcher(c):
            continue
        exported, has_filter = c.get(A + "exported"), c.find("intent-filter") is not None
        if exported in ("true", "false"):
            is_exported = exported == "true"
        elif c.tag == "provider":  # providers default to exported only for API <= 16
            is_exported = target is not None and target <= 16
        else:
            is_exported = has_filter
        perm = c.get(A + "permission")
        protected = strong(perm) or (c.tag == "provider" and strong(c.get(A + "readPermission"))
                                     and strong(c.get(A + "writePermission")))
        if not is_exported or protected:
            continue
        name = c.get(A + "name")
        how = exported or ("implicit (has intent-filter)" if has_filter else f"default for targetSdk {target}")
        evidence = [f"<{c.tag} android:name=\"{name}\">", f"exported={how}", f"permission={perm or 'none'}"]
        if c.tag == "provider":
            evidence.append(f"readPermission={c.get(A + 'readPermission') or 'none'}, "
                            f"writePermission={c.get(A + 'writePermission') or 'none'}")
        out.append(_finding("EXPORTED-COMPONENT", name, evidence, "HIGH" if c.tag == "provider" else None))

    nsc, ref = None, app.get(A + "networkSecurityConfig") or ""
    nsc_path = decompiled_dir / "res" / "xml" / f"{ref.removeprefix('@xml/')}.xml"
    if ref.startswith("@xml/") and nsc_path.is_file():
        nsc = ET.parse(nsc_path).getroot()
    old = target is not None and target < 28  # cleartext was allowed by default before API 28
    if nsc is None:  # the manifest flag only applies when no network security config overrides it
        flag = app.get(A + "usesCleartextTraffic")
        if flag == "true" or (flag is None and old):
            out.append(_finding("CLEARTEXT-TRAFFIC", "AndroidManifest.xml <application>",
                                [f"android:usesCleartextTraffic={flag or 'not set'}, targetSdkVersion={target}"]))
        if target is not None and target < 24:
            out.append(_finding("TLS-USER-CA", "AndroidManifest.xml",
                                [f"targetSdkVersion={target} (< 24) trusts user-installed CAs by default"]))
    else:
        where = f"res/xml/{nsc_path.name}"
        base = nsc.find("base-config")
        permitted = base.get("cleartextTrafficPermitted") if base is not None else None
        if permitted == "true" or (permitted is None and old):
            out.append(_finding("CLEARTEXT-TRAFFIC", where,
                                [f"base-config cleartextTrafficPermitted={permitted or 'not set'}, targetSdkVersion={target}"]))
        domains = [d.text.strip() for dc in nsc.iter("domain-config") if dc.get("cleartextTrafficPermitted") == "true"
                   for d in dc.findall("domain") if d.text]
        if domains:
            out.append(_finding("CLEARTEXT-TRAFFIC", where, [f"cleartext allowed for: {', '.join(domains)}"], "LOW"))
        configs = [base, *nsc.iter("domain-config")]  # debug-overrides is deliberately not checked
        if any(cfg is not None and cfg.find("trust-anchors/certificates[@src='user']") is not None for cfg in configs):
            out.append(_finding("TLS-USER-CA", where, ['<certificates src="user"/> outside debug-overrides']))
    return out


def _text_files(decompiled_dir: Path, java_dir: Path, app_prefix: str):
    src = java_dir / "sources" if (java_dir / "sources").is_dir() else java_dir
    for p in src.rglob("*.java"):
        rel = p.relative_to(src).as_posix()
        if not rel.startswith(LIBRARY_PREFIXES) or rel.startswith(app_prefix):
            yield rel, p
    resources = [decompiled_dir / "AndroidManifest.xml", *(decompiled_dir / "res").glob("values*/strings.xml"),
                 *(decompiled_dir / "assets").rglob("*")]  # manifest: API keys often sit in <meta-data>
    for p in resources:  # 32 MB cap: React Native/Hermes bundles (the app's whole JS logic) sit in assets at several MB
        if p.is_file() and p.stat().st_size < 32_000_000:
            yield p.relative_to(decompiled_dir).as_posix(), p


@lru_cache(maxsize=None)  # M1, M2 and the permission check read the same files; the scanner clears it after each scan
def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:  # a decompiled file can vanish or be locked (seen on Windows): skip it rather than fail the scan
        return ""


def _assigned_literal(name: str, text: str, hops: int = 1) -> bool:
    """True if the file assigns `name` a string/array literal, directly or via one `name = other.getBytes(..)` hop."""
    # ponytail: same-file name matching, no real data flow; FlowDroid/taint analysis is the upgrade path
    if JADX_LOCAL.fullmatch(name):
        return False
    m = re.search(rf'\b{name}\s*=\s*(?:"|\{{|new byte\[\]\s*\{{|(?:this\.)?(\w+)\.getBytes\()', text)
    return bool(m) and (m.group(1) is None or (hops > 0 and _assigned_literal(m.group(1), text, hops - 1)))


def _code_findings(decompiled_dir: Path, java_dir: Path, app_prefix: str, rules=CODE_RULES, kb=KB,
                   hints=HINTS) -> list[StandardFinding]:
    out = []
    for rel, path in _text_files(decompiled_dir, java_dir, app_prefix):
        text = _read(path)
        lines, low = text.split("\n"), text.lower()
        for rule_id, rx in rules.items():
            if rule_id in hints and not any(h in low for h in hints[rule_id]):
                continue
            hits = []
            for m in rx.finditer(text):
                ref = m.groupdict().get("ref")
                if ref and not _assigned_literal(ref, text):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                snippet = lines[line - 1].strip()
                if len(snippet) > 200:  # minified JS / bytecode: show the match's surroundings, not the line start
                    snippet = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", text[max(0, m.start() - 40):m.start() + 160])
                hits.append(f"L{line}: {snippet}")
            if hits:
                out.append(_finding(rule_id, rel, hits[:5] + ([f"... {len(hits) - 5} more"] if len(hits) > 5 else []),
                                    kb=kb))
    return out


def _rank(findings: list[StandardFinding]) -> list[StandardFinding]:
    """Sorts by severity and numbers ids per rule, e.g. EXPORTED-COMPONENT-2."""
    findings.sort(key=lambda f: SEVERITIES.index(f.severity))
    seen = Counter()
    for f in findings:
        seen[f.id] += 1
        f.id = f"{f.id}-{seen[f.id]}"
    return findings


def analyze(decompiled_dir: Path, java_dir: Path) -> list[StandardFinding]:
    """Runs the M1 APK rules on apktool output (manifest/res/assets) and jadx output (Java sources)."""
    decompiled_dir, java_dir = Path(decompiled_dir), Path(java_dir)
    man = ET.parse(decompiled_dir / "AndroidManifest.xml").getroot()
    app_prefix = man.get("package", "").replace(".", "/") + "/"
    return _rank(_manifest_findings(man, decompiled_dir) + _code_findings(decompiled_dir, java_dir, app_prefix))
