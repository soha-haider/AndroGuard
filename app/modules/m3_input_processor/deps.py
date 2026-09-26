import requests
from typing import List, Dict, Any
from app.schemas.finding import StandardFinding

class DependencyScanner:
    OSV_API_URL = "https://api.osv.dev/v1/query"

    @classmethod
    def query_osv(cls, package_name: str, version: str) -> List[Dict[str, Any]]:
        """Queries OSV API for CVEs matching a specific library dependency."""
        payload = {
            "package": {"name": package_name, "ecosystem": "Maven"},
            "version": version
        }
        try:
            response = requests.post(cls.OSV_API_URL, json=payload, timeout=10)
            if response.status_code == 200:
                return response.json().get("vulns", [])
        except requests.RequestException:
            pass
        return []

    def scan_dependencies(self, dependencies: Dict[str, str]) -> List[StandardFinding]:
        """Scans a dict of {lib_name: version} and converts matches to StandardFinding instances."""
        findings = []
        for lib, version in dependencies.items():
            vulns = self.query_osv(lib, version)
            for v in vulns:
                vuln_id = v.get("id", "UNKNOWN-CVE")
                summary = v.get("summary", "Vulnerable third-party dependency detected.")
                findings.append(
                    StandardFinding(
                        finding_id=f"M3-DEP-{vuln_id}",
                        title=f"Vulnerable Dependency: {lib} ({version})",
                        category="Insecure Dependencies",
                        description=summary,
                        cause=f"Library {lib}:{version} contains publicly known vulnerability {vuln_id}.",
                        supporting_evidence=[f"OSV ID: {vuln_id}", f"Package: {lib}:{version}"],
                        affected_file_or_component=lib,
                        severity="HIGH",
                        confidence=0.95,
                        exploitability="MEDIUM",
                        owasp_mapping=["MASVS-CODE-2"],
                        remediation=f"Update {lib} to a non-vulnerable release version."
                    )
                )
        return findings