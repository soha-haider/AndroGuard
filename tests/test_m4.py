import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.modules.m3_input_processor import dataflow
from app.modules.m4_risk_engine.correlator import app_risk, assess
from app.schemas.finding import StandardFinding


def _f(fid, severity="MEDIUM", category="x", confidence=0.8):
    return StandardFinding(id=fid, title=fid, severity=severity, description="d", category=category, confidence=confidence)


def test_m4():
    findings = assess([
        _f("EXPORTED-COMPONENT-1", "HIGH", confidence=0.9),
        _f("CLEARTEXT-TRAFFIC-1"), _f("HTTP-ENDPOINT-1"), _f("API-KEY-GOOGLE-1", confidence=0.95),
        _f("CRYPTO-HARDCODED-KEY-1", "HIGH", confidence=0.85), _f("STORAGE-PREFS-SECRET-1", confidence=0.6),
        _f("WEBVIEW-JS-1", "LOW", confidence=0.7), _f("PERM-HIGH-RISK-1", "LOW", confidence=0.6),
        _f("GHSA-xxxx", "HIGH", category="Vulnerable Dependency", confidence=None),
    ])
    by_id = {f.id: f for f in findings}
    assert by_id["EXPORTED-COMPONENT-1"].exploitability == "HIGH"            # base rule
    assert by_id["HTTP-ENDPOINT-1"].exploitability == "HIGH"                 # chain: cleartext allowed + http://
    assert by_id["HTTP-ENDPOINT-1"].related == ["CLEARTEXT-TRAFFIC-1"]
    assert by_id["API-KEY-GOOGLE-1"].exploitability == "HIGH"                # chain: key + interceptable channel
    assert by_id["CRYPTO-HARDCODED-KEY-1"].exploitability == "HIGH"          # chain: key + stored secrets
    assert by_id["STORAGE-PREFS-SECRET-1"].exploitability == "LOW"           # no backup/exported/world-readable
    assert by_id["CLEARTEXT-TRAFFIC-1"].exploitability == "MEDIUM"           # not a chain target
    assert by_id["WEBVIEW-JS-1"].exploitability == by_id["PERM-HIGH-RISK-1"].exploitability == "LOW"
    assert by_id["GHSA-xxxx"].exploitability == "MEDIUM" and by_id["GHSA-xxxx"].risk_score == 100 * 0.8 * 0.7 * 0.6
    assert all(f.exploit_factors for f in findings)
    assert [f.risk_score for f in findings] == sorted((f.risk_score for f in findings), reverse=True)
    assert findings[0].id == "CRYPTO-HARDCODED-KEY-1" or findings[0].id == "EXPORTED-COMPONENT-1"
    risk = app_risk(findings)
    assert risk["level"] == "HIGH" and risk["score"] == findings[0].risk_score
    assert set(risk["in_attack_chains"]) == {"HTTP-ENDPOINT-1", "API-KEY-GOOGLE-1", "CRYPTO-HARDCODED-KEY-1"}

    # FlowDroid: XML -> flows -> findings; a traced flow backs rule hits in the same class
    xml = ('<DataFlowResults><Results><Result><Sink Statement="s" LineNumber="9" Method="&lt;a.b.Login: void ok()&gt;" '
           'MethodSourceSinkDefinition="&lt;android.app.Activity: void setResult(int,android.content.Intent)&gt;"/><Sources>'
           '<Source Statement="t" LineNumber="8" Method="m" MethodSourceSinkDefinition="&lt;a.b.Login: android.view.View '
           'findViewById(int)&gt;"/></Sources></Result>'
           '<Result><Sink Statement="s" LineNumber="35" Method="&lt;a.b.Login$1: void onClick(x)&gt;" '
           'MethodSourceSinkDefinition="&lt;android.util.Log: int i(java.lang.String,java.lang.String)&gt;"/><Sources>'
           '<Source Statement="t" LineNumber="27" Method="m" MethodSourceSinkDefinition="&lt;android.telephony.TelephonyManager: '
           'java.lang.String getDeviceId()&gt;"/></Sources></Result></Results></DataFlowResults>')
    flows = dataflow.parse(xml)
    assert flows[0] == {"source": "android.telephony.TelephonyManager.getDeviceId", "source_line": 27, "sink": "android.util.Log.i",
                        "sink_line": 35, "method": "a.b.Login$1.onClick"}, flows  # security sinks sort first
    assert len(flows) == 2 and flows[1]["sink"] == "android.app.Activity.setResult"
    ui_source = "$r6 = virtualinvoke $r5.<android.widget.EditText: android.text.Editable getText()>()"
    assert dataflow._api(ui_source) == "android.widget.EditText.getText"  # UI sources come without a definition
    log_rule = StandardFinding(id="STORAGE-LOG-SECRET-1", title="t", severity="MEDIUM", description="d",
                               category="Insecure Data Storage", confidence=0.5, affected_component="a/b/Login.java")
    by_id = {f.id: f for f in assess([log_rule] + dataflow.findings(flows))}
    assert by_id["DATAFLOW-LOG-1"].affected_component == "a/b/Login.java" and by_id["DATAFLOW-LOG-1"].exploitability == "LOW"
    assert by_id["STORAGE-LOG-SECRET-1"].related == ["DATAFLOW-LOG-1"] and by_id["STORAGE-LOG-SECRET-1"].confidence == 0.8
    print(f"[OK] M4 check passed: top risk {findings[0].id} ({findings[0].risk_score}), app risk {risk['level']}, data flows linked")


if __name__ == "__main__":
    test_m4()
