"""
Phase 5: Layer schemas

Pydantic models for layer generation, retrieval, and export.
"""

from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field


class LayerGenerateRequest(BaseModel):
    """Request to generate a new correlation layer."""

    name: str = Field(..., min_length=1, max_length=255, description="Layer name")
    description: Optional[str] = Field(None, max_length=1000, description="Optional layer description")
    intel_report_ids: List[str] = Field(..., description="List of threat report UUIDs to include")
    vuln_scan_ids: List[str] = Field(..., description="List of vulnerability scan UUIDs to include")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Q4 2024 Threat Landscape",
                "description": "Correlation of Q4 threat intel and vulnerability scans",
                "intel_report_ids": ["uuid1", "uuid2"],
                "vuln_scan_ids": ["uuid3", "uuid4"]
            }
        }


class LayerBreakdown(BaseModel):
    """Technique count breakdown by color."""

    red: int = Field(..., description="Critical overlap techniques (intel + vuln)")
    yellow: int = Field(..., description="Intel-only techniques")
    blue: int = Field(..., description="Vulnerability-only techniques")
    total: int = Field(..., description="Total techniques in layer")


class LayerStatistics(BaseModel):
    """Layer generation statistics."""

    intel_reports_used: int = Field(..., description="Number of intel reports used")
    vuln_scans_used: int = Field(..., description="Number of vulnerability scans used")
    unique_intel_techniques: int = Field(..., description="Unique techniques from intel")
    unique_vuln_techniques: int = Field(..., description="Unique techniques from vulns")
    overlap_percentage: float = Field(..., description="Percentage of techniques in red (overlap)")


class LayerGenerateResponse(BaseModel):
    """Response from layer generation."""

    layer_id: str = Field(..., description="Generated layer UUID")
    name: str = Field(..., description="Layer name")
    breakdown: LayerBreakdown = Field(..., description="Technique breakdown by color")
    statistics: LayerStatistics = Field(..., description="Generation statistics")
    message: str = Field(default="Layer generated successfully")

    class Config:
        json_schema_extra = {
            "example": {
                "layer_id": "uuid",
                "name": "Q4 2024 Threat Landscape",
                "breakdown": {
                    "red": 12,
                    "yellow": 45,
                    "blue": 30,
                    "total": 87
                },
                "statistics": {
                    "intel_reports_used": 2,
                    "vuln_scans_used": 2,
                    "unique_intel_techniques": 57,
                    "unique_vuln_techniques": 42,
                    "overlap_percentage": 13.79
                },
                "message": "Layer generated successfully"
            }
        }


class Layer(BaseModel):
    """Layer metadata."""

    id: UUID = Field(..., description="Layer UUID")
    name: str = Field(..., description="Layer name")
    description: Optional[str] = Field(None, description="Layer description")
    created_by: UUID = Field(..., description="User who created the layer")
    created_at: datetime = Field(..., description="Creation timestamp")


class LayerListResponse(BaseModel):
    """Paginated list of layers."""

    layers: List[Layer]
    total: int
    page: int = 1
    size: int = 50


class LayerTechnique(BaseModel):
    """Technique in a layer."""

    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")
    color: str = Field(..., description="Color code (#EF4444, #F59E0B, #3B82F6)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0.0-1.0)")
    from_intel: bool = Field(..., description="Technique present in intel reports")
    from_vuln: bool = Field(..., description="Technique present in vulnerability scans")


class LayerDetail(Layer):
    """Layer with techniques."""

    techniques: List[LayerTechnique] = Field(default_factory=list, description="Techniques in layer")
    technique_count: int = Field(..., description="Total number of techniques")
    breakdown: Optional[Dict[str, int]] = Field(None, description="Technique breakdown by color")


class NavigatorLayer(BaseModel):
    """MITRE ATT&CK Navigator layer format (v4.5)."""

    # This model is just for documentation - actual export returns raw dict
    name: str
    versions: Dict[str, str]
    domain: str
    description: str
    techniques: List[Dict]

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Q4 2024 Threat Landscape",
                "versions": {
                    "attack": "14",
                    "navigator": "4.5",
                    "layer": "4.5"
                },
                "domain": "enterprise-attack",
                "description": "Correlation of Q4 threat intel and vulnerability scans",
                "techniques": [
                    {
                        "techniqueID": "T1059.001",
                        "color": "#EF4444",
                        "score": 95,
                        "enabled": True,
                        "metadata": [
                            {"name": "Source", "value": "Threat Intelligence"},
                            {"name": "Source", "value": "Vulnerability Scan"}
                        ]
                    }
                ]
            }
        }
