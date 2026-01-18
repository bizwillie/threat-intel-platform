"""
Threat Intelligence routes (Phase 3)

Endpoints for uploading and managing threat intel documents.
"""

import os
import uuid
import logging
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.responses import JSONResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, require_hunter, User
from app.models.database import get_db
from app.schemas.intel import (
    ThreatReportUploadResponse,
    ThreatReport,
    ThreatReportDetail,
    ThreatReportStatusResponse,
    ExtractedTechnique,
    ProcessingStatistics,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/intel", tags=["Intelligence"])

# Upload directory
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {".pdf", ".json", ".stix", ".stix2", ".txt"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


@router.post("/upload", response_model=ThreatReportUploadResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_threat_report(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_hunter)
):
    """
    Upload a threat intelligence document (PDF, STIX, text).

    This endpoint:
    1. Validates file type and size
    2. Stores file to disk
    3. Creates database record
    4. Queues Celery task for processing
    5. Returns 202 Accepted with report_id

    Requires: hunter role
    """
    # Validate file extension
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Generate unique report ID
    report_id = uuid.uuid4()

    # Save file to disk with unique name
    safe_filename = f"{report_id}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)

    try:
        # Read and validate file size
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size: {MAX_FILE_SIZE / (1024 * 1024)} MB"
            )

        # Write to disk
        with open(file_path, "wb") as f:
            f.write(content)

        logger.info(f"Saved file {file.filename} to {file_path}")

    except Exception as e:
        logger.error(f"Failed to save file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save file"
        )

    # Detect source type
    source_type = "unknown"
    if file_ext == ".pdf":
        source_type = "pdf"
    elif file_ext in [".json", ".stix", ".stix2"]:
        source_type = "stix"
    elif file_ext == ".txt":
        source_type = "text"

    # Create database record
    try:
        await db.execute(
            """
            INSERT INTO threat_reports (id, filename, source_type, status, uploaded_by, created_at)
            VALUES (:id, :filename, :source_type, 'queued', :uploaded_by, :created_at)
            """,
            {
                "id": str(report_id),
                "filename": file.filename,
                "source_type": source_type,
                "uploaded_by": str(user.id),
                "created_at": datetime.utcnow(),
            }
        )
        await db.commit()

        logger.info(f"Created threat_report record: {report_id}")

    except Exception as e:
        logger.error(f"Failed to create database record: {e}")
        # Clean up file
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create database record"
        )

    # Queue Celery task
    try:
        from celery import Celery
        celery_app = Celery(
            broker=os.getenv("REDIS_URL", "redis://redis:6379/0"),
            backend=os.getenv("REDIS_URL", "redis://redis:6379/0")
        )

        celery_app.send_task(
            "tasks.document_processing.process_threat_report",
            args=[str(report_id), file_path, file.filename]
        )

        logger.info(f"Queued Celery task for report {report_id}")

    except Exception as e:
        logger.error(f"Failed to queue Celery task: {e}")
        # Update status to failed
        await db.execute(
            "UPDATE threat_reports SET status = 'failed', error_message = :error WHERE id = :id",
            {"error": "Failed to queue processing task", "id": str(report_id)}
        )
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to queue processing task"
        )

    return ThreatReportUploadResponse(
        report_id=report_id,
        filename=file.filename,
        status="queued",
        message=f"Threat report uploaded and queued for processing"
    )


@router.get("/reports", response_model=List[ThreatReport])
async def list_threat_reports(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    List all threat intelligence reports.

    Returns:
        List of threat reports with metadata and processing status
    """
    result = await db.execute(
        """
        SELECT id, filename, source_type, status, uploaded_by, created_at, processed_at, error_message
        FROM threat_reports
        ORDER BY created_at DESC
        """
    )

    reports = []
    for row in result.fetchall():
        reports.append(ThreatReport(
            id=uuid.UUID(row[0]),
            filename=row[1],
            source_type=row[2],
            status=row[3],
            uploaded_by=uuid.UUID(row[4]),
            created_at=row[5],
            processed_at=row[6],
            error_message=row[7]
        ))

    return reports


@router.get("/reports/{report_id}", response_model=ThreatReportDetail)
async def get_report_detail(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Get detailed information about a threat report including extracted techniques.

    Returns:
        Threat report with extracted techniques
    """
    # Get report
    result = await db.execute(
        """
        SELECT id, filename, source_type, status, uploaded_by, created_at, processed_at, error_message
        FROM threat_reports
        WHERE id = :id
        """,
        {"id": report_id}
    )

    row = result.fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat report not found"
        )

    report = ThreatReportDetail(
        id=uuid.UUID(row[0]),
        filename=row[1],
        source_type=row[2],
        status=row[3],
        uploaded_by=uuid.UUID(row[4]),
        created_at=row[5],
        processed_at=row[6],
        error_message=row[7]
    )

    # Get extracted techniques
    techniques_result = await db.execute(
        """
        SELECT technique_id, confidence, evidence, extraction_method
        FROM extracted_techniques
        WHERE report_id = :report_id
        ORDER BY technique_id
        """,
        {"report_id": report_id}
    )

    for tech_row in techniques_result.fetchall():
        report.techniques.append(ExtractedTechnique(
            technique_id=tech_row[0],
            confidence=tech_row[1],
            evidence=tech_row[2],
            extraction_method=tech_row[3]
        ))

    return report


@router.get("/reports/{report_id}/status", response_model=ThreatReportStatusResponse)
async def get_report_status(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Get processing status of a threat report.

    Returns:
        Processing status: queued | processing | complete | failed
    """
    result = await db.execute(
        """
        SELECT filename, status, created_at, processed_at, error_message,
               (SELECT COUNT(*) FROM extracted_techniques WHERE report_id = :report_id) as tech_count
        FROM threat_reports
        WHERE id = :report_id
        """,
        {"report_id": report_id}
    )

    row = result.fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat report not found"
        )

    return ThreatReportStatusResponse(
        report_id=uuid.UUID(report_id),
        filename=row[0],
        status=row[1],
        created_at=row[2],
        processed_at=row[3],
        error_message=row[4],
        techniques_count=row[5]
    )


@router.get("/reports/{report_id}/techniques", response_model=List[ExtractedTechnique])
async def get_extracted_techniques(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Get extracted MITRE ATT&CK techniques from a threat report.

    Returns:
        List of extracted techniques with confidence and evidence
    """
    # Verify report exists
    report_result = await db.execute(
        "SELECT id FROM threat_reports WHERE id = :id",
        {"id": report_id}
    )

    if not report_result.fetchone():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat report not found"
        )

    # Get techniques
    result = await db.execute(
        """
        SELECT technique_id, confidence, evidence, extraction_method
        FROM extracted_techniques
        WHERE report_id = :report_id
        ORDER BY technique_id
        """,
        {"report_id": report_id}
    )

    techniques = []
    for row in result.fetchall():
        techniques.append(ExtractedTechnique(
            technique_id=row[0],
            confidence=row[1],
            evidence=row[2],
            extraction_method=row[3]
        ))

    return techniques


@router.get("/statistics", response_model=ProcessingStatistics, tags=["Phase 3"])
async def get_processing_statistics(
    db: AsyncSession = Depends(get_current_user)
):
    """
    Get statistics about threat report processing.

    Returns:
        Processing statistics including status breakdown and technique counts
    """
    # This could also call the Celery task, but we'll query directly for now
    status_result = await db.execute(
        """
        SELECT status, COUNT(*) as count
        FROM threat_reports
        GROUP BY status
        """
    )

    status_breakdown = {row[0]: row[1] for row in status_result.fetchall()}

    total_techniques_result = await db.execute(
        "SELECT COUNT(*) FROM extracted_techniques"
    )
    total_techniques = total_techniques_result.scalar()

    avg_techniques_result = await db.execute(
        """
        SELECT AVG(tech_count)
        FROM (
            SELECT COUNT(*) as tech_count
            FROM extracted_techniques
            GROUP BY report_id
        ) as subq
        """
    )
    avg_techniques = avg_techniques_result.scalar() or 0.0

    return ProcessingStatistics(
        status_breakdown=status_breakdown,
        total_techniques_extracted=total_techniques,
        average_techniques_per_report=float(avg_techniques),
        timestamp=datetime.utcnow().isoformat()
    )
