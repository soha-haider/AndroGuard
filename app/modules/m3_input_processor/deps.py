import sys
import zipfile
import requests
from pathlib import Path
from typing import List
from app.schemas.finding import StandardFinding

# OSV's GHSA "database_specific.severity" -> our severity scale
SEVERITY_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def extract_dependencies(apk_path: Path) -> dict[str, str]:
    """Finds bundled Maven libraries and versions from APK metadata. Returns {"group:artifact": version}."""
    deps = {}
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if not name.startswith("META-INF/"):
                continue
            if name.endswith(".version"):
                # AndroidX/Google libs: META-INF/androidx.core_core.version -> androidx.core:core
                stem = name[len("META-INF/"):-len(".version")]
                if "_" in stem and "/" not in stem:
                    group, artifact = stem.split("_", 1)
                    deps[f"{group}:{artifact}"] = zf.read(name).decode(errors="ignore").strip()
            elif name.endswith("pom.properties"):
                props = dict(line.split("=", 1) for line in zf.read(name).decode(errors="ignore").splitlines()
                             if "=" in line and not line.startswith("#"))
                if {"groupId", "artifactId", "version"} <= props.keys():
                    deps[f"{props['groupId'].strip()}:{props['artifactId'].strip()}"] = props["version"].strip()
    # ponytail: metadata-only detection; libs shipped without META-INF (e.g. okhttp) need jadx/package fingerprinting later
    return {k: v for k, v in deps.items() if v}


class DependencyScanner:
    # OSV aggregates GitHub Advisory Database (GHSA) entries for Maven, so GHSA is covered here.
    OSV_URL = "https://api.osv.dev/v1/query"

    def scan_apk(self, apk_path: Path) -> List[StandardFinding]:
        findings = []
        for package_name, version in extract_dependencies(apk_path).items():
            findings.extend(self.query_osv(package_name, version))
        return findings

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
                    raw_sev = str(vuln.get("database_specific", {}).get("severity", "")).upper()
                    cves = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
                    findings.append(StandardFinding(
                        id=vuln.get("id", "UNKNOWN"),
                        title=vuln.get("summary", "Dependency Vulnerability"),
                        severity=SEVERITY_MAP.get(raw_sev, "UNKNOWN"),
                        description=vuln.get("details", "No description provided."),
                        category="Vulnerable Dependency",
                        affected_component=package_name,
                        evidence=[f"{package_name}:{version} matched {vuln.get('id')} in OSV"],
                        remediation="Upgrade to a version outside the affected range listed in the advisory.",
                        package_name=package_name,
                        version=version,
                        cve=cves[0] if cves else None,
                        references=[r["url"] for r in vuln.get("references", []) if "url" in r],
                        raw_data=vuln
                    ))
        except Exception as e:
            print(f"[!] OSV lookup error for {package_name}: {e}", file=sys.stderr)  # stdout carries the JSON report
        return findings
