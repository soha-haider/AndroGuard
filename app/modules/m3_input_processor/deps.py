import requests
from typing import List
from app.schemas.finding import StandardFinding

class DependencyScanner:
    OSV_URL = "https://api.osv.dev/v1/query"

    def query_osv(self, package_name: str, version: str) -> List[StandardFinding]:
        payload = {
            "version": version,
            "package": {"name": package_name, "ecosystem": "Maven"}
        }
        findings = []
        try:
            res = requests.post(self.OSV_URL, json=payload, timeout=10)
            if res.status_code == 200:
                data = res.json()
                for vuln in data.get("vulns", []):
                    findings.append(StandardFinding(
                        id=vuln.get("id", "UNKNOWN"),
                        title=vuln.get("summary", "Dependency Vulnerability"),
                        severity="HIGH",
                        description=vuln.get("details", "No description provided."),
                        package_name=package_name,
                        version=version,
                        raw_data=vuln
                    ))
        except Exception as e:
            print(f"[!] OSV lookup error for {package_name}: {e}")
        return findings