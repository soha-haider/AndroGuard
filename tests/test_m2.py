import sys
import tempfile
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.modules.m2_api_analyzer.analyzer import analyze, KB

# Fake tokens are assembled at runtime so no secret-shaped literal lives in the repo (GitHub push protection).
GOOGLE = "AIza" + "Sy" + "A" * 33
AWS_ID = "AKIA" + "Z" * 16
STRIPE = "sk_" + "live_" + "a1B2" * 6
SLACK = "xox" + "b-" + "1234567890-abcdefghij"
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + ".sig_part_1234567890"

MANIFEST = f"""<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.api">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <application>
        <meta-data android:name="com.google.android.geo.API_KEY" android:value="{GOOGLE}"/>
        <meta-data android:name="io.sdk.ApiKey" android:value="k3y9f8e7d6c5b4a3210z"/>
        <meta-data android:name="io.sdk.ClientToken" android:value="0a1b2c3d4e5f60718293a4b5c6d7e8f9"/>
    </application>
</manifest>"""

STRINGS = f"""<resources>
    <string name="google_api_key">{GOOGLE}</string>
    <string name="firebase_database_url">https://demo-app.firebaseio.com</string>
    <string name="payment_key">{STRIPE}</string>
    <string name="privacy_url">http://example.com/privacy</string>
</resources>"""

API = f"""package com.test.api;
public class Api {{
    public static final String AWS_ID = "{AWS_ID}";
    private static final String API_KEY = "Zx9Qw8Er7Ty6Ui5Op4As";
    static final String SLACK = "{SLACK}";
    static final String SESSION_JWT = "{JWT}";
    private String clientSecret = "Qm9zU2VjcmV0VmFsdWUxMjM0";
    String base = "http://api.example.com/v1/";
    String ipApi = "https://203.0.113.10:8443/api";
    String staging = "https://staging.example.com/api";
    String bucket = "https://assets-demo.s3.amazonaws.com/img.png";
    String auth = "Basic dXNlcjpwYXNzd29yZA==";
    String oauth = "https://accounts.example.com/authorize?response_type=token&client_id=abc";
    String scope = "https://www.googleapis.com/auth/drive";
    String login(String u, String p) {{
        return "https://example.com/login?user=" + u + "&password=" + p;
    }}
    void tls() throws Exception {{
        SSLContext.getInstance("TLSv1");
        String[] suites = {{"TLS_RSA_WITH_RC4_128_SHA"}};
        String cam = "android.hardware.camera2.CameraManager";
    }}
}}"""

SAFE = """package com.test.api;
public class Safe {
    static final String NS = "http://schemas.android.com/apk/res/android";
    static final String LOCAL = "http://10.0.2.2:8080/";
    static final String DOCS = "https://developer.android.com/latest/test-guide";
    static final String PREF_API_KEY = "pref_api_key_name_value";
    static final String ACCESS_TOKEN_KEY = "com.test.api.ACCESS_TOKEN";
    String tokenUrl = "https://example.com/oauth/token";
    void x() throws Exception {
        SSLContext.getInstance("TLSv1.2");
        SSLContext.getInstance("TLS");
        String narrow = "https://www.googleapis.com/auth/drive.file";
        String codeFlow = "https://accounts.example.com/authorize?response_type=code";
    }
}"""


def _write(root: Path, rel: str, text: str):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_m2():
    with tempfile.TemporaryDirectory() as d:
        dec, jadx = Path(d) / "decompiled", Path(d) / "jadx_src"
        _write(dec, "AndroidManifest.xml", MANIFEST)
        _write(dec, "res/values/strings.xml", STRINGS)
        _write(dec, "assets/sa.json", '{"type": "service_account", "project_id": "demo"}')
        _write(jadx, "sources/com/test/api/Api.java", API)
        _write(jadx, "sources/com/test/api/Safe.java", SAFE)
        _write(jadx, "sources/com/lib/SmsHelper.java", "import android.telephony.SmsManager;")  # SDK uses SEND_SMS
        _write(jadx, "sources/okhttp3/ConnectionSpec.java", 'TlsVersion.TLS_1_0; "http://example.org";')  # library
        # React Native Hermes bundle: > 1 MB, binary, strings stored unquoted and back to back
        (dec / "assets/index.android.bundle").write_bytes(
            bytes.fromhex("c61fbc03c103191f") + b"\x00abc" * 300_000 + b"fooBarhttp://api.demo-shop.com/v1/usersNext" + b"\x01" * 8)

        findings = analyze(dec, jadx)
        rules = {f.id.rsplit("-", 1)[0] for f in findings}
        assert rules == set(KB), f"missing: {set(KB) - rules}, unexpected: {rules - set(KB)}"

        flagged = {f.affected_component for f in findings}
        assert not flagged & {"com/test/api/Safe.java", "okhttp3/ConnectionSpec.java"}, "negative cases were flagged"
        unused = {f.affected_component for f in findings if f.id.startswith("PERM-UNUSED")}
        assert unused == {"android.permission.READ_CONTACTS"}, unused
        bundle = [f for f in findings if f.affected_component == "assets/index.android.bundle"]
        assert [f.id.rsplit("-", 1)[0] for f in bundle] == ["HTTP-ENDPOINT"], "Hermes bundle URL missed"
        assert "http://api.demo-shop.com/v1/users" in bundle[0].evidence[0] and len(bundle[0].evidence[0]) < 230
        manifest_rules = {f.id.rsplit("-", 1)[0] for f in findings if f.affected_component == "AndroidManifest.xml"}
        assert manifest_rules == {"API-KEY-GOOGLE", "API-KEY-GENERIC", "API-SECRET-GENERIC"}, manifest_rules
        assert all(f.maswe and f.masvs and f.remediation and f.evidence for f in findings)
    print(f"[OK] M2 check passed: {len(findings)} findings, all {len(KB)} rules fired, negatives clean")


if __name__ == "__main__":
    test_m2()
