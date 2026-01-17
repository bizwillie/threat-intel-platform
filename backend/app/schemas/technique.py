"""
Technique-related Pydantic schemas
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from uuid import UUID


class TechniqueResponse(BaseModel):
    """Base technique response"""
    technique_id: str = Field(..., description="MITRE ATT&CK Technique ID (e.g., T1059.001)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0.0-1.0)")


class ExtractedTechniqueResponse(TechniqueResponse):
    """Extracted technique from threat intel"""
    id: int
    report_id: UUID
    evidence: Optional[str] = Field(None, description="Text snippet that triggered detection")
    extraction_method: str = Field(..., description="regex or llm")
    created_at: datetime

    class Config:
        from_attributes = True


class CVETechniqueResponse(TechniqueResponse):
    """CVE to technique mapping"""
    id: int
    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2024-1234)")
    source: str = Field(..., description="Mapping source: nvd, capec, or manual")

    class Config:
        from_attributes = True
