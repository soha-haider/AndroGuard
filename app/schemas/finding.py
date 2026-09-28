from typing import List, Optional
from pydantic import BaseModel, Field


class StandardFinding(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    category: str

    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    exploitability: Optional[str] = None

    description: str
    cause: Optional[str] = None
    remediation: Optional[str] = None

    supporting_evidence: List[str] = Field(default_factory=list)
    affected_file_or_component: Optional[str] = None

    owasp_mapping: List[str] = Field(default_factory=list)
