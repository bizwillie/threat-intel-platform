"""
Pydantic schemas for Intel API endpoints.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from uuid import UUID


class ThreatReportUploadResponse(BaseModel):
    """Response after uploading a threat intelligence document."""

    report_id: UUID = Field(description="Unique identifier for the threat report")
    filename: str = Field(description="Original filename")
    status: str = Field(description="Processing status (queued, processing, complete, failed)")
    message: str = Field(description="Human-readable status message")


class ExtractedTechnique(BaseModel):
    """Extracted ATT&CK technique from threat intel."""

    technique_id: str = Field(description="ATT&CK technique ID (e.g., T1059.001)")
    confidence: float = Field(description="Confidence score 0.0-1.0")
    evidence: str = Field(description="Text snippet that matched")
    extraction_method: str = Field(description="Method used (regex, llm, stix)")


class ThreatReport(BaseModel):
    """Threat intelligence report metadata."""

    id: UUID
    filename: str
    source_type: str = Field(description="Document type (pdf, stix, text)")
    status: str = Field(description="Processing status")
    uploaded_by: UUID
    created_at: datetime
    processed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class ThreatReportDetail(ThreatReport):
    """Detailed threat report with extracted techniques."""

    techniques: List[ExtractedTechnique] = Field(default_factory=list)


class ThreatReportStatusResponse(BaseModel):
    """Report processing status."""

    report_id: UUID
    filename: str
    status: str
    created_at: datetime
    processed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    techniques_count: int = Field(description="Number of techniques extracted")


class ProcessingStatistics(BaseModel):
    """Intel worker processing statistics."""

    status_breakdown: dict = Field(description="Count of reports by status")
    total_techniques_extracted: int
    average_techniques_per_report: float
    timestamp: str
