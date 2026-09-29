from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class StandardFinding(BaseModel):
    id: str = Field(..., description="Unique vulnerability identifier (e.g. OSV-2023-XXXX or CVE-2023-XXXX)")
    title: str = Field(..., description="Short title describing the finding")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    description: str = Field(..., description="Detailed summary of the vulnerability")
    package_name: Optional[str] = Field(None, description="Affected library/component name")
    version: Optional[str] = Field(None, description="Affected version detected")
    cve: Optional[str] = Field(None, description="Associated CVE ID if available")
    references: list[str] = Field(default_factory=list, description="External reference URLs")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw response payload from scanner")