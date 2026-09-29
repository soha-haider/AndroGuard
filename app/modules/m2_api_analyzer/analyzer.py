import re
import xml.etree.ElementTree as ET
from pathlib import Path
from app.modules.m1_apk_analyzer.analyzer import A, _code_findings, _finding, _rank, _read  # shared rule engine
from app.schemas.finding import StandardFinding

KEY, SEC, EP, HTTP, URL, AUTH, TLS, PERM = ("Hardcoded API Keys", "Hardcoded API Secrets", "Insecure API Endpoints",
                                            "HTTP Endpoints", "Sensitive Data in URLs",
                                            "Weak Authentication Configuration", "Insecure SSL/TLS Configuration",
                                            "Excessive API Permissions")

# Same layout as the M1 knowledge base; MASWE/MASVS from github.com/OWASP/maswe.
# rule_id: (category, title, severity, confidence, masvs, maswe, cause, description, remediation)
KB = {
    "API-KEY-GOOGLE": (KEY, "Google API key in app", "MEDIUM", 0.95, ["MASVS-STORAGE-1"], ["MASWE-0004"],
        "A Google API key (AIza...) is embedded in code, resources or the manifest.",
        "Anyone can extract the key; if it is not restricted to this app and specific APIs it can be abused for "
        "quota theft, billing or data access.",
        "Restrict the key to the app's package/SHA-1 and the required APIs in Google Cloud Console."),
    "API-KEY-AWS": (KEY, "AWS access key ID in app", "HIGH", 0.9, ["MASVS-STORAGE-1"], ["MASWE-0004"],
        "An AWS access key ID (AKIA/ASIA...) is embedded in the package.",
        "Together with its secret key it gives direct access to AWS resources under that IAM identity.",
        "Remove long-term AWS keys; use Cognito or a backend that issues short-lived, least-privilege credentials."),
    "API-KEY-GENERIC": (KEY, "Hardcoded API key", "MEDIUM", 0.6, ["MASVS-STORAGE-1"], ["MASWE-0004"],
        "An api_key/app_key-named field, string resource or manifest meta-data holds a literal key.",
        "Keys shipped in the APK are public and can be reused to call the API as this app.",
        "Treat embedded keys as public: restrict them server-side or proxy the calls through a backend."),
    "API-SECRET-TOKEN": (SEC, "Hardcoded service token or secret key", "HIGH", 0.9, ["MASVS-STORAGE-1"], ["MASWE-0004"],
        "A token in a known secret format (Stripe, Slack, GitHub, SendGrid, OpenAI, FCM server key, JWT...) is embedded.",
        "These tokens grant privileged API access (payments, messaging, repositories, push to all users).",
        "Revoke and rotate the token, then move the call to a backend; apps must not hold secret keys."),
    "API-SECRET-GENERIC": (SEC, "Hardcoded API secret or access token", "HIGH", 0.7, ["MASVS-STORAGE-1"], ["MASWE-0004"],
        "A secret/token-named field, string resource or meta-data holds a literal credential-like value.",
        "Client secrets and access tokens in the APK let attackers impersonate the app or its users.",
        "Remove and rotate the secret; use a backend or OAuth with PKCE instead of embedded secrets."),
    "ENDPOINT-IP": (EP, "API endpoint addressed by raw IP", "MEDIUM", 0.7, ["MASVS-STORAGE-1"], ["MASWE-0004"],
        "A URL points to a hardcoded IP address instead of a domain name.",
        "Raw-IP endpoints usually lack hostname-based certificate validation and often reveal internal or staging servers.",
        "Use a domain name with a valid TLS certificate and drop internal addresses from release builds."),
    "ENDPOINT-DEBUG": (EP, "Development or staging endpoint in app", "LOW", 0.5, ["MASVS-STORAGE-1"], ["MASWE-0004"],
        "A URL host or path contains dev/staging/test/qa/uat/sandbox/debug/internal/admin markers.",
        "Non-production backends are often weaker protected and expose extra functionality or data.",
        "Strip non-production endpoints from release builds using build variants."),
    "ENDPOINT-CLOUD": (EP, "Direct cloud database or storage endpoint", "LOW", 0.5, ["MASVS-STORAGE-1"], ["MASWE-0004"],
        "The app references a Firebase Realtime Database or AWS S3 endpoint directly.",
        "Misconfigured database rules or bucket policies expose all stored data to anyone who knows the URL.",
        "Verify Firebase security rules and S3 bucket policies deny unauthenticated read and write."),
    "HTTP-ENDPOINT": (HTTP, "Cleartext HTTP endpoint", "MEDIUM", 0.8, ["MASVS-NETWORK-1"], ["MASWE-0026"],
        "A hardcoded http:// URL is used by the app.",
        "Requests and responses to this endpoint can be read and modified by anyone on the network path.",
        "Switch the endpoint to https:// and disable cleartext traffic."),
    "URL-SENSITIVE-PARAM": (URL, "Sensitive data sent in URL", "MEDIUM", 0.7, ["MASVS-STORAGE-2"], ["MASWE-0005"],
        "Passwords, tokens or keys are placed in URL query parameters.",
        "URLs end up in server, proxy and analytics logs and in history, leaking the credentials.",
        "Send credentials in the request body or Authorization header over HTTPS, never in the URL."),
    "AUTH-HARDCODED-BASIC": (AUTH, "Hardcoded HTTP authentication credentials", "HIGH", 0.85,
        ["MASVS-AUTH-1", "MASVS-STORAGE-1"], ["MASWE-0004"],
        "A Basic Authorization header or an HTTP auth username/password is built from literals.",
        "Shared static credentials let anyone who decompiles the app authenticate as it.",
        "Authenticate users individually (OAuth 2.0/OIDC with PKCE, session tokens) instead of static credentials."),
    "AUTH-IMPLICIT-GRANT": (AUTH, "OAuth implicit grant used", "MEDIUM", 0.7, ["MASVS-AUTH-1"], ["MASWE-0018"],
        "An OAuth authorization request uses response_type=token (implicit flow).",
        "Access tokens come back in the redirect URL where other apps can intercept them; the flow is deprecated.",
        "Use the authorization code flow with PKCE (e.g. AppAuth for Android)."),
    # No MASWE is dedicated to TLS versions/cipher suites; MASWE-0047 (overriding platform security APIs) is closest.
    "TLS-WEAK-PROTOCOL": (TLS, "Deprecated SSL/TLS protocol version", "MEDIUM", 0.8, ["MASVS-NETWORK-1"], ["MASWE-0047"],
        "SSLv3, TLS 1.0 or TLS 1.1 is explicitly selected (SSLContext, enabled protocols, OkHttp TlsVersion/COMPATIBLE_TLS).",
        "Deprecated protocols have known attacks (POODLE, BEAST) and weaken the connection.",
        "Use TLS 1.2+ only: SSLContext.getInstance(\"TLS\") with platform defaults, or OkHttp MODERN_TLS."),
    "TLS-WEAK-CIPHER": (TLS, "Weak TLS cipher suite configured", "MEDIUM", 0.8, ["MASVS-NETWORK-1"], ["MASWE-0047"],
        "A cipher suite with RC4, DES/3DES, NULL, EXPORT or anonymous key exchange is configured.",
        "Weak suites allow decryption or tampering of the TLS session.",
        "Keep the platform default cipher suites or restrict to AEAD suites (AES-GCM, ChaCha20-Poly1305)."),
    "PERM-UNUSED": (PERM, "Permission requested but not used", "LOW", 0.5, ["MASVS-PRIVACY-1"], ["MASWE-0066"],
        "A sensitive permission is requested but no code using the related Android API was found.",
        "Unneeded permissions widen the attack surface and what a compromised app or SDK can reach.",
        "Remove permissions the app does not need (check what SDKs merge into the manifest too)."),
    "PERM-OAUTH-SCOPE": (PERM, "Broad OAuth scope requested", "MEDIUM", 0.6, ["MASVS-PRIVACY-1"], ["MASWE-0066"],
        "The app requests full-access OAuth scopes (e.g. Drive, Gmail, cloud-platform).",
        "Tokens with broad scopes expose far more user data if the app or token is compromised.",
        "Request the narrowest scopes needed (e.g. drive.file instead of drive) with incremental authorization."),
    "PERM-SERVICE-ACCOUNT": (PERM, "Service-account credentials embedded", "HIGH", 0.9, ["MASVS-STORAGE-1"],
        ["MASWE-0004"],
        "A Google Cloud service-account key (\"type\": \"service_account\") is shipped in the app.",
        "Service accounts carry server-level API permissions; anyone who extracts the file gets them.",
        "Delete the key in Google Cloud Console, remove the file and call those APIs from a backend."),
}

SKIP_HOSTS = (r"(?!schemas\.android\.com|www\.w3\.org|xmlpull\.org|ns\.adobe\.com|java\.sun\.com|(?:www\.)?apache\.org"
              r"|purl\.org|json-schema\.org|localhost|127\.0\.0\.1|10\.0\.2\.2)")  # XML namespaces, loopback, emulator
SENSITIVE = r"(?:password|passwd|pwd|pass|token|access_token|auth_token|api_?key|apikey|secret|client_secret|pin|cvv)"
# (?=\w+\s*=\s*") first: cheaply rejects words that are not assigned a string literal (see M1 SECRET-CREDENTIAL)
UI_NAMES = r'(?=\w+\s*=\s*")(?!\w*(?:pattern|regex|format|hint|label|message|msg|error|title|text|field|view|url|type|name|header)\w*\s*=)'

CODE_RULES = {k: re.compile(v) for k, v in {
    "API-KEY-GOOGLE": r"AIza[0-9A-Za-z_\-]{35}",
    "API-KEY-AWS": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "API-KEY-GENERIC":
        rf'(?i)\b{UI_NAMES}\w*(?:api_?key|app_?key|consumer_?key)\w*\s*=\s*"(?!AIza)(?![^"]*(?:key|api))[\w\-]{{16,}}"'
        r'|<string name="[^"]*(?:api_?key|app_?key|consumer_?key)[^"]*">(?!AIza)[\w\-]{16,}</string>'
        r'|android:name="[^"]*(?:api_?key|app_?key|consumer_?key)[^"]*"\s+android:value="(?!AIza)[\w\-]{16,}"',
    "API-SECRET-TOKEN":
        r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}|\bxox[baprs]-[0-9A-Za-z-]{10,}|\bgh[pousr]_[A-Za-z0-9]{36,}"
        r"|\bSG\.[\w-]{22}\.[\w-]{43}|\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}|\bAAAA[\w-]{7}:[\w-]{140}"
        r"|\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}|\bkey-[0-9a-f]{32}\b|\bSK[0-9a-f]{32}\b",
    "API-SECRET-GENERIC":  # values containing the keyword itself are key names, not secrets
        rf'(?i)\b{UI_NAMES}\w*(?:secret|token|bearer|private_?key|auth_?key)\w*\s*=\s*"(?![^"]*(?:secret|token|key))'
        r'[\w\-+/=.]{16,}"'
        r'|<string name="[^"]*(?:secret|token|private_?key)[^"]*">(?![^<]*(?:secret|token|key))[\w\-+/=.]{16,}</string>'
        r'|android:name="[^"]*(?:secret|token)[^"]*"\s+android:value="(?![^"]*(?:secret|token|key))[\w\-+/=.]{16,}"',
    "ENDPOINT-IP": r"https?://(?!127\.|10\.0\.2\.2|0\.0\.0\.0)(?:\d{1,3}\.){3}\d{1,3}\b",
    "ENDPOINT-DEBUG":
        r"https?://[^/\"'<\s]*\b(?:dev|develop|staging|stage|test|testing|qa|uat|sandbox|debug|internal)\b[^/\"'<\s]*"
        r"|https?://[^\"'<\s]*/(?:debug|admin|internal)\b",
    "ENDPOINT-CLOUD": r"https?://[\w-]+\.(?:firebaseio\.com|firebasedatabase\.app)|\bs3[\w.-]*\.amazonaws\.com",
    "HTTP-ENDPOINT": rf"http://{SKIP_HOSTS}[^\"'<\s]*",  # no quote required: Hermes bytecode stores strings unquoted
    "URL-SENSITIVE-PARAM":
        rf'(?i)[?&]{SENSITIVE}=|@Query\(\s*"{SENSITIVE}"|appendQueryParameter\(\s*"{SENSITIVE}"',
    "AUTH-HARDCODED-BASIC":
        r'(?i)"basic [a-z0-9+/]{8,}={0,2}"'
        r'|(?:Credentials\.basic|setBasicAuth|UsernamePasswordCredentials|PasswordAuthentication)\(\s*"[^"]*"\s*,\s*"[^"]+"'
        r'|\.proceed\(\s*"[^"]*"\s*,\s*"[^"]+"\s*\)',  # WebView HttpAuthHandler.proceed(user, pass)
    "AUTH-IMPLICIT-GRANT": r'(?i)response_type=token\b|ResponseTypeValues\.TOKEN\b|"response_type"\s*,\s*"token"',
    "TLS-WEAK-PROTOCOL":
        r'SSLContext\.getInstance\(\s*"(?:SSLv2|SSLv3|TLSv1|TLSv1\.1)"|TlsVersion\.(?:SSL_3_0|TLS_1_0|TLS_1_1)\b'
        r'|ConnectionSpec\.COMPATIBLE_TLS\b|setEnabledProtocols\([^;]*"(?:SSLv2|SSLv3|TLSv1|TLSv1\.1)"',
    "TLS-WEAK-CIPHER": r"\b(?:TLS|SSL)_\w*?(?:_anon_|EXPORT|_WITH_(?:RC4|DES|3DES|NULL))\w*",
    "PERM-OAUTH-SCOPE":
        r"https://www\.googleapis\.com/auth/(?:drive|gmail\.\w+|cloud-platform|contacts|calendar|admin\.[\w.]+)(?![\w.])"
        r"|https://mail\.google\.com/",
    "PERM-SERVICE-ACCOUNT": r'"type"\s*:\s*"service_account"',
}.items()}
HINTS = {"API-KEY-GENERIC": ("apikey", "api_key", "appkey", "app_key", "consumerkey", "consumer_key"),
         "API-SECRET-GENERIC": ("secret", "token", "bearer", "privatekey", "private_key", "authkey", "auth_key")}

# Permission -> Android API markers that show it is actually used. Searched across ALL code, libraries included,
# because an SDK can be the legitimate user. ponytail: marker list, not a full API-permission map (PScout/Axplorer).
PERMISSION_APIS = {
    "READ_SMS": r"Telephony.Sms|content://sms",
    "RECEIVE_SMS": r"SMS_RECEIVED|SmsMessage|Telephony.Sms",
    "SEND_SMS": r"SmsManager",
    "READ_CONTACTS": r"ContactsContract|content://com.android.contacts",
    "WRITE_CONTACTS": r"ContactsContract|content://com.android.contacts",
    "READ_CALL_LOG": r"CallLog",
    "WRITE_CALL_LOG": r"CallLog",
    "CALL_PHONE": r"ACTION_CALL\b|android.intent.action.CALL\b",
    "READ_PHONE_STATE": r"TelephonyManager|SubscriptionManager|PhoneStateListener",
    "CAMERA": r"android.hardware.camera2|android.hardware.Camera|androidx.camera|IMAGE_CAPTURE|VIDEO_CAPTURE",
    "RECORD_AUDIO": r"AudioRecord|MediaRecorder|SpeechRecognizer",
    "ACCESS_FINE_LOCATION": r"LocationManager|FusedLocationProvider|LocationServices|requestLocationUpdates|setMyLocationEnabled",
    "ACCESS_COARSE_LOCATION": r"LocationManager|FusedLocationProvider|LocationServices|requestLocationUpdates|setMyLocationEnabled",
    "ACCESS_BACKGROUND_LOCATION": r"LocationManager|FusedLocationProvider|LocationServices|requestLocationUpdates",
    "GET_ACCOUNTS": r"AccountManager",
    "READ_CALENDAR": r"CalendarContract",
    "WRITE_CALENDAR": r"CalendarContract",
}


def _unused_permissions(man, java_dir: Path) -> list[StandardFinding]:
    requested = {p.get(A + "name", "").removeprefix("android.permission.")
                 for p in man if p.tag in ("uses-permission", "uses-permission-sdk-23")}
    pending = {p: re.compile(rx) for p, rx in PERMISSION_APIS.items() if p in requested}
    src = java_dir / "sources" if (java_dir / "sources").is_dir() else java_dir
    for path in src.rglob("*.java"):
        if not pending:
            break
        text = _read(path)
        pending = {p: rx for p, rx in pending.items() if not rx.search(text)}
    out = []
    for p in sorted(pending):
        markers = PERMISSION_APIS[p].replace("|", ", ").replace("\\b", "")
        out.append(_finding("PERM-UNUSED", f"android.permission.{p}",
                            [f'<uses-permission android:name="android.permission.{p}"/>',
                             f"no reference to {markers} in the decompiled code"], kb=KB))
    return out


def analyze(decompiled_dir: Path, java_dir: Path) -> list[StandardFinding]:
    """Runs the M2 API rules on the same apktool/jadx output that M1 uses."""
    decompiled_dir, java_dir = Path(decompiled_dir), Path(java_dir)
    man = ET.parse(decompiled_dir / "AndroidManifest.xml").getroot()
    app_prefix = man.get("package", "").replace(".", "/") + "/"
    return _rank(_code_findings(decompiled_dir, java_dir, app_prefix, CODE_RULES, KB, HINTS)
                 + _unused_permissions(man, java_dir))
