"""M4: evidence correlation, exploitability and risk prioritisation (deterministic and explainable)."""
from app.schemas.finding import StandardFinding

SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.55, "LOW": 0.3, "INFO": 0.1, "UNKNOWN": 0.45}
EXPLOIT_WEIGHT = {"HIGH": 1.0, "MEDIUM": 0.7, "LOW": 0.4}

# Who can exploit a finding and from where. First matching rule-id prefix wins, so specific prefixes come first.
BASE = [
    ("EXPORTED-COMPONENT", "HIGH", "Any installed app can reach it: exported without a strong permission"),
    ("PERM-WEAK-CUSTOM", "HIGH", "Any installed app can obtain the weak custom permission"),
    ("STORAGE-WORLD-MODE", "HIGH", "Any app on the device can read or modify the file"),
    ("PERM-SERVICE-ACCOUNT", "HIGH", "Key file is extractable from the APK and grants server-level API access"),
    ("API-SECRET", "HIGH", "Extractable offline from the APK and usable remotely against the API"),
    ("API-KEY-AWS", "HIGH", "Extractable offline from the APK and usable against AWS"),
    ("AUTH-HARDCODED-BASIC", "HIGH", "Static credentials are extractable from the APK"),
    ("SECRET-", "HIGH", "Extractable offline from the APK by decompiling it"),
    ("API-KEY", "MEDIUM", "Extractable from the APK; impact depends on server-side key restrictions"),
    ("TLS-", "MEDIUM", "Needs a network position (shared Wi-Fi, rogue access point) to intercept traffic"),
    ("CLEARTEXT-", "MEDIUM", "Needs a network position to read or modify cleartext traffic"),
    ("HTTP-ENDPOINT", "MEDIUM", "Needs a network position to read or modify cleartext traffic"),
    ("URL-SENSITIVE-PARAM", "MEDIUM", "Leaks through server, proxy and analytics logs"),
    ("DATAFLOW-URL", "MEDIUM", "Leaks through server, proxy and analytics logs; FlowDroid traced the data flow"),
    ("DATAFLOW-", "LOW", "Needs adb, root or backup access to the device; FlowDroid traced the data flow"),
    ("AUTH-", "MEDIUM", "Needs a malicious app on the device to intercept the OAuth redirect"),
    ("WEBVIEW-JS-BRIDGE", "MEDIUM", "Exploitable once the WebView renders attacker-controlled content"),
    ("WEBVIEW-FILE-URL-ACCESS", "MEDIUM", "Exploitable once the WebView loads an attacker-controlled file"),
    ("WEBVIEW-", "LOW", "Needs attacker-controlled content inside the WebView"),
    ("CRYPTO-HARDCODED-KEY", "MEDIUM", "Key is extractable from the APK; the attacker still needs the encrypted data"),
    ("CRYPTO-", "LOW", "The attacker first needs access to the encrypted or hashed data"),
    ("STORAGE-EXTERNAL", "MEDIUM", "Apps with storage access (and the user) can read shared storage"),
    ("STORAGE-", "LOW", "Needs root, backup or adb access to the device"),
    ("ENDPOINT-", "LOW", "Endpoint found in the APK; exploitation depends on the backend's configuration"),
    ("PERM-", "LOW", "Raises the impact of other issues; not exploitable on its own"),
]

# Attack chains: when every group has at least one finding, the targets become HIGH and point to the evidence.
CHAINS = [
    (("HTTP-ENDPOINT", "URL-SENSITIVE-PARAM", "DATAFLOW-URL"), [("CLEARTEXT-TRAFFIC",)],
     "The network config allows cleartext and the app uses http:// endpoints, so the traffic can be intercepted"),
    (("TLS-TRUST-ALL", "TLS-HOSTNAME-ALL", "TLS-WEBVIEW-SSL-ERROR"),
     [("HTTP-ENDPOINT", "ENDPOINT-", "API-KEY", "API-SECRET", "URL-SENSITIVE-PARAM", "AUTH-")],
     "Certificate checks are disabled for an app that calls API endpoints: any man-in-the-middle sees the traffic"),
    (("API-SECRET", "API-KEY", "AUTH-HARDCODED-BASIC", "SECRET-"),
     [("HTTP-ENDPOINT", "CLEARTEXT-TRAFFIC", "TLS-TRUST-ALL", "TLS-HOSTNAME-ALL")],
     "The credential can also be captured on the network, without decompiling the app"),
    (("WEBVIEW-JS-BRIDGE",), [("HTTP-ENDPOINT", "CLEARTEXT-TRAFFIC", "WEBVIEW-MIXED-CONTENT", "TLS-WEBVIEW-SSL-ERROR")],
     "Page content can be injected over the network and then call the exposed native bridge"),
    (("WEBVIEW-FILE-URL-ACCESS", "WEBVIEW-FILE-ACCESS"), [("EXPORTED-COMPONENT",)],
     "Other apps can drive an exported component and may make the WebView load a malicious file URL"),
    (("CRYPTO-HARDCODED-KEY", "CRYPTO-STATIC-IV"),
     [("STORAGE-PREFS-SECRET", "STORAGE-SQL-SECRET", "STORAGE-EXTERNAL", "STORAGE-WORLD-MODE", "STORAGE-BACKUP")],
     "The key and the stored data are both on the device, so the encryption can be reversed"),
    (("STORAGE-PREFS-SECRET", "STORAGE-SQL-SECRET", "STORAGE-LOG-SECRET", "DATAFLOW-STORAGE"), [("STORAGE-BACKUP", "STORAGE-WORLD-MODE")],
     "Stored secrets can be pulled through an app backup or a world-readable file"),
]


def assess(findings: list[StandardFinding]) -> list[StandardFinding]:
    """Adds exploitability, explainable factors, attack-chain links and a 0-100 risk score; sorts by risk."""
    for f in findings:
        if f.category == "Vulnerable Dependency":
            f.exploitability, factor = "MEDIUM", "Known advisory for the bundled library version; reachability not verified"
        else:
            f.exploitability, factor = next(((e, why) for p, e, why in BASE if f.id.startswith(p)),
                                            ("MEDIUM", "No specific exploitability rule"))
        f.exploit_factors = [factor]
    for targets, groups, why in CHAINS:
        evidence = [[f.id for f in findings if f.id.startswith(group)] for group in groups]
        if all(evidence):
            for f in findings:
                if f.id.startswith(targets):
                    f.exploitability = "HIGH"
                    f.exploit_factors.append(why)
                    f.related += [i for ids in evidence for i in ids if i != f.id and i not in f.related]
    for flow in (f for f in findings if f.id.startswith("DATAFLOW-")):  # a traced flow backs the rule hits in its class
        for f in findings:
            if not f.id.startswith("DATAFLOW-") and f.affected_component == flow.affected_component and f.category == flow.category:
                f.confidence = max(f.confidence or 0, 0.8)
                f.exploit_factors.append("FlowDroid traced sensitive data into this class")
                f.related += [flow.id] if flow.id not in f.related else []
    for f in findings:
        f.risk_score = round(100 * SEVERITY_WEIGHT.get(f.severity, 0.45) * EXPLOIT_WEIGHT[f.exploitability]
                             * (f.confidence if f.confidence is not None else 0.6), 1)
    return sorted(findings, key=lambda f: -f.risk_score)


def app_risk(findings: list[StandardFinding]) -> dict:
    """App-level summary: the worst finding sets the level; counts show the spread."""
    top = max((f.risk_score or 0 for f in findings), default=0)
    level = "HIGH" if top >= 50 else "MEDIUM" if top >= 25 else "LOW"
    by_expl = {e: sum(f.exploitability == e for f in findings) for e in EXPLOIT_WEIGHT}
    chains = sorted({f.id for f in findings if f.related})
    return {"score": top, "level": level, "exploitability": by_expl, "in_attack_chains": chains}
