"""AndroGuard scanner: python -m app <app.apk|app.aab> [report.json]"""
import json
import sys
from collections import Counter
from pathlib import Path
from app.pipeline import log, scan

if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("Usage: python -m app <app.apk|app.aab> [report.json]")
    result = scan(sys.argv[1])
    report = json.dumps(result, indent=2)
    if len(sys.argv) == 3:  # writing the file ourselves avoids shell redirect encodings (PowerShell 5 writes UTF-16)
        Path(sys.argv[2]).write_text(report, encoding="utf-8")
    else:
        print(report)
    counts = Counter(f["severity"] for f in result["findings"])
    log(f"[+] {len(result['findings'])} findings ({', '.join(f'{k} {v}' for k, v in counts.items())}), "
        f"app risk {result['risk']['level']} ({result['risk']['score']})"
        + (f" -> {sys.argv[2]}" if len(sys.argv) == 3 else ""))
