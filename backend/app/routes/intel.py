"""
Threat Intelligence routes (Phase 3)

Endpoints for uploading and managing threat intel documents.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from app.auth import get_current_user, require_hunter, User
from typing import List

router = APIRouter(prefix="/api/v1/intel", tags=["Intelligence"])


@router.post("/upload")
async def upload_threat_report(user: User = Depends(require_hunter)):
    """
    Upload a threat intelligence document (PDF, STIX, text).

    **Phase 3 Implementation Required**

    This endpoint will:
    1. Store file metadata in threat_reports table
    2. Queue Celery task for processing
    3. Return 202 Accepted with report_id

    Requires: hunter role
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Phase 3: Intel Worker not yet implemented"
    )


@router.get("/reports")
async def list_threat_reports(user: User = Depends(get_current_user)):
    """
    List all threat intelligence reports.

    **Phase 3 Implementation Required**

    Returns:
        List of threat reports with metadata and processing status
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Phase 3: Intel Worker not yet implemented"
    )


@router.get("/reports/{report_id}/status")
async def get_report_status(report_id: str, user: User = Depends(get_current_user)):
    """
    Get processing status of a threat report.

    **Phase 3 Implementation Required**

    Returns:
        Processing status: queued | processing | complete | failed
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Phase 3: Intel Worker not yet implemented"
    )


@router.get("/reports/{report_id}/techniques")
async def get_extracted_techniques(report_id: str, user: User = Depends(get_current_user)):
    """
    Get extracted MITRE ATT&CK techniques from a threat report.

    **Phase 3 Implementation Required**

    Returns:
        List of extracted techniques with confidence and evidence
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Phase 3: Intel Worker not yet implemented"
    )
