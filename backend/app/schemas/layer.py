"""
Layer-related Pydantic schemas
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Dict
from uuid import UUID


class LayerGenerateRequest(BaseModel):
    """Request to generate a new ATT&CK layer"""
    name: str = Field(..., description="Layer name")
    intel_reports: List[UUID] = Field(default=[], description="Threat report UUIDs to include")
    vuln_scans: List[UUID] = Field(default=[], description="Vulnerability scan UUIDs to include")


class LayerTechniqueResponse(BaseModel):
    """Technique within a layer"""
    technique_id: str
    color: str = Field(..., description="yellow, blue, or red")
    confidence: float = Field(..., ge=0.0, le=1.0)
    from_intel: bool
    from_vuln: bool

    class Config:
        from_attributes = True


class LayerResponse(BaseModel):
    """Layer response with metadata"""
    id: UUID
    name: str
    created_by: str
    created_at: datetime
    technique_count: int = Field(default=0, description="Total number of techniques")
    breakdown: Dict[str, int] = Field(
        default_factory=dict,
        description="Technique count by color: {red: 12, yellow: 45, blue: 30}"
    )

    class Config:
        from_attributes = True


class LayerDetailResponse(LayerResponse):
    """Detailed layer response with techniques"""
    techniques: List[LayerTechniqueResponse] = Field(default=[])
