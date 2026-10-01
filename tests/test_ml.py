import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.modules.m4_risk_engine.report import render_html
from app.modules.ml import code_model, codebert
from app.schemas.finding import StandardFinding


def test_ml():
    line = 'Log.d(TAG, "String entered: " + this.workingPassword);'
    lime = code_model.lime(line)
    assert lime == code_model.lime(line), "LIME must give the same answer every time"
    assert lime[0][0] == "Log" and lime[0][1] > 0.3, lime  # without the log call most of the risk is gone
    assert all(abs(v) < 0.05 for _, v in code_model.lime("textView.setText(R.string.app_name);")), "harmless line"

    f = StandardFinding(id="STORAGE-LOG-SECRET-1", title="t", severity="MEDIUM", description="d", category="c",
                        confidence=0.5, risk_score=50.0, evidence=["L78: " + line])
    [f] = code_model.score_findings([f])
    assert f.ml_top[0][0] == "log_call" and f.ml_lime == lime and "LIME: Log +" in f.exploit_factors[-1], f.exploit_factors

    if codebert.available():  # optional model: the attention map covers the whole line, in order
        p, top, attention = codebert.insights([line])[0]
        assert "".join(t for t, _ in attention) == line and max(w for _, w in attention) == 1.0, attention

    page = render_html({"file": "a.apk", "findings": [{"id": "X-1", "title": "t", "severity": "LOW", "description": "d",
                                                      "codebert_score": 0.5, "codebert_attention": [["<b>", 1.0], ["x", 0.2]]}]})
    assert "&lt;b&gt;" in page and "rgba(10,122,85,0.50)" in page  # escaped, and shaded by attention
    print(f"[OK] ML check passed: SHAP {f.ml_top[0][0]}, LIME {lime[0][0]} {lime[0][1]:+}, attention map covers the line")


if __name__ == "__main__":
    test_ml()
