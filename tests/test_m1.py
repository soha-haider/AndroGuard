import sys
import tempfile
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.modules.m1_apk_analyzer.analyzer import analyze, KB

MANIFEST = """<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.vuln">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <permission android:name="com.test.vuln.WEAK" android:protectionLevel="normal"/>
    <permission android:name="com.test.vuln.SIG" android:protectionLevel="signature"/>
    <application android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".Main">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name=".Transfer" android:exported="true"/>
        <activity android:name=".Internal"/>
        <service android:name=".SigService" android:exported="true" android:permission="com.test.vuln.SIG"/>
        <service android:name=".WeakService" android:exported="true" android:permission="com.test.vuln.WEAK"/>
        <receiver android:name=".Recv"><intent-filter><action android:name="com.test.ACTION"/></intent-filter></receiver>
        <receiver android:name=".Disabled" android:exported="true" android:enabled="false"/>
        <provider android:name=".Prov" android:authorities="com.test.prov" android:exported="true"
                  android:readPermission="com.test.vuln.SIG"/>
    </application>
</manifest>"""

NSC = """<network-security-config>
    <base-config><trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors></base-config>
    <domain-config cleartextTrafficPermitted="true"><domain includeSubdomains="true">example.com</domain></domain-config>
</network-security-config>"""

VULN = """package com.test.vuln;
public class Vuln {
    private String adminPassword = "Adm1n@123";
    String key = "This is the super secret key 123";
    byte[] ivBytes = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    void run() throws Exception {
        openFileOutput("data.txt", 1);
        File f = Environment.getExternalStorageDirectory();
        editor.putString("superSecurePassword", pw);
        db.execSQL("CREATE TABLE users (id INTEGER, user_password TEXT)");
        Log.d("TAG", "token=" + token);
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        Cipher.getInstance("AES");
        Cipher.getInstance("RSA/ECB/PKCS1Padding");
        MessageDigest.getInstance("MD5");
        new SecretKeySpec(this.key.getBytes("UTF-8"), "AES");
        new IvParameterSpec(this.ivBytes);
        settings.setJavaScriptEnabled(true);
        webView.addJavascriptInterface(new Bridge(), "Android");
        settings.setAllowFileAccess(true);
        settings.setAllowUniversalAccessFromFileURLs(true);
        WebView.setWebContentsDebuggingEnabled(true);
        settings.setMixedContentMode(0);
    }
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
    }
    public boolean verify(String str, SSLSession sSLSession) {
        return true;
    }
    public void onReceivedSslError(WebView webView, SslErrorHandler sslErrorHandler, SslError sslError) {
        sslErrorHandler.proceed();
    }
}"""

SAFE = """package com.test.vuln;
public class Safe {
    public static final String PREF_PASSWORD = "pref_password";
    String passwordHint = "Min 8 chars";
    private static final String PASSWORD_PATTERN = "((?=.*[0-9])(?=.*[a-z]).{6,20})";
    String dynamicKey = loadKey();
    void run() throws Exception {
        String str = "abc";
        byte[] kb = this.dynamicKey.getBytes("UTF-8");
        new SecretKeySpec(kb, "AES");
        openFileOutput("x", 0);
        getSharedPreferences("prefs", 32768);
        Cipher.getInstance("AES/GCM/NoPadding");
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        MessageDigest.getInstance("SHA-256");
        new SecretKeySpec(bArr, "AES");
        new SecretKeySpec(str.getBytes(), "AES");
        new IvParameterSpec(cipher.getIV());
        settings.setJavaScriptEnabled(false);
    }
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str) {
    }
    public void checkServerTrusted(X509Certificate[] chain, String str) throws CertificateException {
        this.delegate.checkServerTrusted(chain, str);
    }
}"""

# InsecureBankv2 shape: the key reaches SecretKeySpec through a local and a method parameter
TWO_HOP_KEY = """package com.test.vuln;
public class CryptoClass {
    String key = "This is the super secret key 123";
    public static byte[] enc(byte[] keyBytes, byte[] data) throws Exception {
        SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
        return data;
    }
    public byte[] run(byte[] data) throws Exception {
        byte[] keyBytes = this.key.getBytes("UTF-8");
        return enc(keyBytes, data);
    }
}"""

STRINGS = """<resources>
    <string name="prompt_password">Password</string>
    <string name="db_password">s3cr3tP@ss</string>
</resources>"""


def _write(root: Path, rel: str, text: str):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_m1():
    with tempfile.TemporaryDirectory() as d:
        dec, jadx = Path(d) / "decompiled", Path(d) / "jadx_src"
        _write(dec, "AndroidManifest.xml", MANIFEST)
        _write(dec, "apktool.yml", "sdkInfo:\n  minSdkVersion: '16'\n  targetSdkVersion: '23'\n")
        _write(dec, "res/xml/network_security_config.xml", NSC)
        _write(dec, "res/values/strings.xml", STRINGS)
        _write(dec, "res/values-ja/strings.xml", '<resources><string name="password">パスワード</string></resources>')
        _write(jadx, "sources/expo/modules/webview/Lib.java", "WebView.setWebContentsDebuggingEnabled(true);")
        _write(dec, "assets/key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n")
        _write(jadx, "sources/com/test/vuln/Vuln.java", VULN)
        _write(jadx, "sources/com/test/vuln/Safe.java", SAFE)
        _write(jadx, "sources/com/test/vuln/CryptoClass.java", TWO_HOP_KEY)
        _write(jadx, "sources/androidx/crypto/Lib.java", 'Cipher.getInstance("DES");')

        findings = analyze(dec, jadx)
        rules = {f.id.rsplit("-", 1)[0] for f in findings}
        assert rules == set(KB), f"missing: {set(KB) - rules}, unexpected: {rules - set(KB)}"

        by_component = {f.affected_component: f for f in findings}
        assert not any(f.affected_component in ("Safe.java", "com/test/vuln/Safe.java", "androidx/crypto/Lib.java",
                                                "res/values-ja/strings.xml", "expo/modules/webview/Lib.java")
                       for f in findings), "negative cases were flagged"
        assert [f.id.rsplit("-", 1)[0] for f in findings if f.affected_component == "com/test/vuln/CryptoClass.java"] \
            == ["CRYPTO-HARDCODED-KEY"], "two-hop hardcoded key not detected"
        exported = {f.affected_component for f in findings if f.category == "Exported Components"}
        assert exported == {".Transfer", ".WeakService", ".Recv", ".Prov"}, exported
        assert by_component[".Prov"].severity == "HIGH"
        assert by_component["com.test.vuln.WEAK"].category == "Insecure Permissions"
        assert {f.severity for f in findings if f.id.startswith("CLEARTEXT")} == {"MEDIUM", "LOW"}
        assert next(f for f in findings if f.id.startswith("STORAGE-BACKUP")).severity == "MEDIUM"  # targetSdk 23
        creds = next(f for f in findings if f.id.startswith("SECRET-CREDENTIAL") and "strings" in f.affected_component)
        assert creds.evidence == ['L3: <string name="db_password">s3cr3tP@ss</string>'], creds.evidence
        assert all(f.maswe and f.masvs and f.remediation and f.evidence for f in findings)
        assert [f.severity for f in findings] == sorted((f.severity for f in findings),
                                                         key=["CRITICAL", "HIGH", "MEDIUM", "LOW"].index)
    print(f"[OK] M1 check passed: {len(findings)} findings, all {len(KB)} rules fired, negatives clean")


if __name__ == "__main__":
    test_m1()
