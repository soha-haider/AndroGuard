"""Security report (proposal Phase 9): self-contained HTML, printed to PDF with WeasyPrint or a headless browser."""
import html
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

CSS = """body{font:13px/1.5 "Segoe UI",system-ui,sans-serif;color:#1b1b1b;margin:32px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:24px 0 8px}h3{font-size:14px;margin:0 0 4px}
.muted{color:#5f5e5a}.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;
border:1px solid currentColor}.CRITICAL,.HIGH{color:#a32d2d}.MEDIUM{color:#854f0b}.LOW,.INFO,.UNKNOWN{color:#444441}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #e1e0d9;padding:4px 6px;text-align:left;
vertical-align:top}.f{border:1px solid #e1e0d9;border-radius:8px;padding:10px 14px;margin:10px 0;break-inside:avoid}
code{font:11px Consolas,monospace;word-break:break-all}ul{margin:4px 0;padding-left:18px}"""


def render_html(report: dict) -> str:
    """Every value comes from the scanned APK or the report, so everything is escaped."""
    e = lambda v: html.escape("" if v is None else str(v))
    risk, findings = report.get("risk", {}), report["findings"]
    top = "".join(f"<tr><td>{e(f.get('risk_score'))}</td><td><span class='pill {e(f['severity'])}'>{e(f['severity'])}</span>"
                  f"</td><td>{e(f.get('exploitability'))}</td><td>{e(f['title'])}</td><td>{e(f.get('affected_component'))}</td></tr>"
                  for f in findings[:10])
    cards = "".join(
        f"<div class='f'><h3><span class='pill {e(f['severity'])}'>{e(f['severity'])}</span> {e(f['title'])} "
        f"<span class='muted'>{e(f['id'])}</span></h3>"
        f"<div class='muted'>{e(f.get('category'))} · exploitability {e(f.get('exploitability'))} · risk "
        f"{e(f.get('risk_score'))} · confidence {e(f.get('confidence'))}"
        f"{' · ML ' + e(f['ml_score']) if f.get('ml_score') is not None else ''}</div>"
        f"<p><b>Affected:</b> {e(f.get('affected_component'))}</p><p>{e(f['description'])}</p>"
        f"<b>Evidence</b><ul>{''.join(f'<li><code>{e(x)}</code></li>' for x in f.get('evidence', []))}</ul>"
        f"<b>Why this exploitability</b><ul>{''.join(f'<li>{e(x)}</li>' for x in f.get('exploit_factors', []))}</ul>"
        + (f"<p><b>Related findings:</b> {e(', '.join(f['related']))}</p>" if f.get("related") else "")
        + f"<p><b>OWASP:</b> {e(', '.join(f.get('masvs', []) + f.get('maswe', [])))}</p>"
        f"<p><b>Remediation:</b> {e(f.get('remediation'))}</p></div>" for f in findings)
    expl = risk.get("exploitability", {})
    flows = "".join(f"<tr><td><code>{e(f['source'])}</code> line {e(f['source_line'])}</td><td><code>{e(f['sink'])}</code> "
                    f"line {e(f['sink_line'])}</td><td><code>{e(f['method'])}</code></td></tr>" for f in report.get("data_flows", [])[:50])
    flow_section = (f"<h2>Data flows (FlowDroid)</h2><p class='muted'>{e(report['data_flow_status'])}</p>"
                    + (f"<table><tr><th>Source</th><th>Sink</th><th>Sink is in</th></tr>{flows}</table>" if flows else "")
                    if report.get("data_flow_status") else "")
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>AndroGuard report - {e(report['file'])}</title>"
            f"<style>{CSS}</style></head><body><h1>AndroGuard security report</h1>"
            f"<div class='muted'>{e(report['file'])} ({e(report.get('type', '').upper())}) · SHA-256 {e(report.get('sha256'))}</div>"
            f"<h2>App risk: <span class='{e(risk.get('level'))}'>{e(risk.get('level'))}</span> ({e(risk.get('score'))}/100)</h2>"
            f"<div>{len(findings)} findings · exploitability HIGH {e(expl.get('HIGH', 0))}, MEDIUM {e(expl.get('MEDIUM', 0))}, "
            f"LOW {e(expl.get('LOW', 0))} · {len(risk.get('in_attack_chains', []))} in attack chains</div>"
            f"<h2>Top risks</h2><table><tr><th>Risk</th><th>Severity</th><th>Exploitability</th><th>Finding</th>"
            f"<th>Affected</th></tr>{top}</table><h2>All findings</h2>{cards}{flow_section}</body></html>")


def render_pdf(page: str) -> bytes:
    try:
        from weasyprint import HTML  # the proposal's engine; needs the Pango/GTK libraries (Linux/Docker)
        return HTML(string=page).write_pdf()
    except (ImportError, OSError):
        pass
    browsers = [shutil.which(n) for n in ("msedge", "chrome", "chromium", "google-chrome")] + [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe"]
    browser = next((b for b in browsers if b and Path(b).exists()), None)
    if not browser:
        raise RuntimeError("No PDF engine: install WeasyPrint (with Pango) or Chrome/Edge")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:  # the browser may still hold its profile
        src, out = Path(d) / "report.html", Path(d) / "report.pdf"
        src.write_text(page, encoding="utf-8")
        # own profile folder: never touches the user's browser session
        subprocess.run([browser, "--headless=new", "--disable-gpu", "--no-first-run", "--no-pdf-header-footer",
                        f"--user-data-dir={Path(d) / 'profile'}", f"--print-to-pdf={out}", src.as_uri()],
                       capture_output=True, timeout=120, stdin=subprocess.DEVNULL)
        size, deadline = -1, time.monotonic() + 60  # msedge.exe's launcher exits before the browser writes the PDF
        while time.monotonic() < deadline:
            if out.exists() and out.stat().st_size == size > 0:  # same size twice in a row: writing has finished
                return out.read_bytes()
            size = out.stat().st_size if out.exists() else -1
            time.sleep(0.5)
        raise RuntimeError("PDF rendering failed")
