"""
Vulnerability management routes (Phase 2)

Endpoints for uploading and managing vulnerability scans.

SECURITY: Rate limiting applied to upload endpoints.
"""

import uuid
import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.auth import get_current_user, get_current_user_optional, require_hunter, User
from app.database import get_db
from app.shared.rate_limiter import limiter
from app.schemas.vulnerability import (
    VulnScanResponse,
    VulnScanListResponse,
    VulnScanDetailResponse,
    TechniqueListResponse,
)
from app.services.nessus_parser import NessusParser, NessusParseError
from app.services.cve_mapper import CVEMapper, CVEMapperError
from app.models.database import VulnerabilityScan, Vulnerability, CVETechnique
from app.models.database import ProcessingStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vuln", tags=["Vulnerabilities"])


@router.post("/upload", response_model=VulnScanResponse)
@limiter.limit("10/minute")
async def upload_vulnerability_scan(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_hunter),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload a Nessus vulnerability scan (.nessus XML file).

    **Phase 2 Implementation**

    This endpoint:
    1. Validates .nessus file format
    2. Parses XML to extract vulnerabilities
    3. Maps CVEs to MITRE ATT&CK techniques (CVE→CWE→CAPEC→Technique)
    4. Stores scan metadata, vulnerabilities, and technique mappings
    5. Returns scan_id

    Requires: hunter role
    """
    # Validate file extension
    if not file.filename.endswith('.nessus'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .nessus files are accepted"
        )

    # Read file content
    try:
        file_content = await file.read()
    except Exception as e:
        logger.error(f"Failed to read uploaded file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to read uploaded file"
        )

    # Validate it's a Nessus file
    if not NessusParser.validate_file(file_content):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File does not appear to be a valid Nessus .nessus file"
        )

    # Parse Nessus file
    try:
        parsed_data = NessusParser.parse(file_content, file.filename)
    except NessusParseError as e:
        logger.error(f"Nessus parse error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse Nessus file: {str(e)}"
        )

    scan_metadata = parsed_data["scan_metadata"]
    vulnerabilities = parsed_data["vulnerabilities"]

    # Create VulnerabilityScan record
    scan_id = uuid.uuid4()
    scan_date = scan_metadata.get("scan_date") or datetime.utcnow()

    vuln_scan = VulnerabilityScan(
        id=scan_id,
        filename=file.filename,
        scan_date=scan_date,
        uploaded_by=user.username,
        created_at=datetime.utcnow()
    )
    db.add(vuln_scan)

    # Store vulnerabilities
    vuln_count = 0
    unique_cves = set()

    for vuln_data in vulnerabilities:
        vuln = Vulnerability(
            scan_id=scan_id,
            cve_id=vuln_data["cve_id"],
            severity=vuln_data["severity"],
            cvss_score=vuln_data["cvss_score"],
            asset=vuln_data["asset"],
            port=vuln_data.get("port"),
            plugin_id=vuln_data.get("plugin_id"),
            plugin_name=vuln_data.get("plugin_name"),
            description=vuln_data.get("description"),
            solution=vuln_data.get("solution"),
        )
        db.add(vuln)
        vuln_count += 1
        unique_cves.add(vuln_data["cve_id"])

    await db.commit()

    logger.info(f"Stored {vuln_count} vulnerabilities with {len(unique_cves)} unique CVEs")

    # Map CVEs to techniques (Piranha crown jewel)
    try:
        cve_mappings = await CVEMapper.map_multiple_cves(list(unique_cves))
    except Exception as e:
        logger.error(f"CVE mapping error: {e}")
        # Don't fail the upload if mapping fails, just log it
        cve_mappings = {}

    # Store CVE→Technique mappings
    technique_count = 0
    for cve_id, techniques in cve_mappings.items():
        for tech in techniques:
            # Check if mapping already exists
            existing = await db.execute(
                select(CVETechnique).where(
                    CVETechnique.cve_id == cve_id,
                    CVETechnique.technique_id == tech["technique_id"]
                )
            )
            if existing.scalar_one_or_none():
                continue  # Skip duplicates

            cve_tech = CVETechnique(
                cve_id=cve_id,
                technique_id=tech["technique_id"],
                confidence=tech["confidence"],
                source=tech["source"]
            )
            db.add(cve_tech)
            technique_count += 1

    await db.commit()

    logger.info(f"Scan {scan_id} uploaded: {vuln_count} vulnerabilities, {technique_count} technique mappings")

    return VulnScanResponse(
        scan_id=str(scan_id),
        filename=file.filename,
        scan_date=scan_date,
        uploaded_by=user.username,
        vulnerability_count=vuln_count,
        unique_cve_count=len(unique_cves),
        technique_count=technique_count
    )


@router.get("/scans", response_model=VulnScanListResponse)
async def list_vulnerability_scans(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(50, ge=1, le=100, description="Items per page"),
    user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
):
    """
    List all vulnerability scans with summary statistics.

    **Pagination:** Use `page` and `size` query parameters.

    Returns:
        List of scans with metadata and vulnerability counts
    """
    # PERFORMANCE: Single aggregation query instead of N+1
    # This query gets scan metadata plus aggregated vulnerability stats in one trip
    offset = (page - 1) * size

    # Subquery for vulnerability counts per scan
    vuln_stats = (
        select(
            Vulnerability.scan_id,
            func.count(Vulnerability.id).label('vuln_count'),
            func.count(func.distinct(Vulnerability.cve_id)).label('unique_cve_count')
        )
        .group_by(Vulnerability.scan_id)
        .subquery()
    )

    # Main query with left join to get scans even if they have no vulnerabilities
    result = await db.execute(
        select(
            VulnerabilityScan,
            func.coalesce(vuln_stats.c.vuln_count, 0).label('vuln_count'),
            func.coalesce(vuln_stats.c.unique_cve_count, 0).label('unique_cve_count')
        )
        .outerjoin(vuln_stats, VulnerabilityScan.id == vuln_stats.c.scan_id)
        .order_by(VulnerabilityScan.created_at.desc())
        .offset(offset)
        .limit(size)
    )
    rows = result.all()

    # Get total count for pagination
    total_result = await db.execute(select(func.count(VulnerabilityScan.id)))
    total = total_result.scalar() or 0

    scan_list = []
    for row in rows:
        scan = row[0]  # VulnerabilityScan object
        vuln_count = row[1]
        unique_cve_count = row[2]

        scan_list.append({
            "scan_id": str(scan.id),
            "filename": scan.filename,
            "scan_date": scan.scan_date,
            "uploaded_by": scan.uploaded_by,
            "created_at": scan.created_at,
            "vulnerability_count": vuln_count,
            "unique_cve_count": unique_cve_count,
        })

    return VulnScanListResponse(scans=scan_list, total=total, page=page, size=size)


@router.get("/scans/{scan_id}", response_model=VulnScanDetailResponse)
async def get_vulnerability_scan(
    scan_id: str,
    user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed vulnerability scan with all vulnerabilities and mapped techniques.

    Returns:
        Scan metadata, vulnerabilities, CVE→TTP mappings, and technique breakdown
    """
    # Get scan
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan_id format"
        )

    result = await db.execute(
        select(VulnerabilityScan).where(VulnerabilityScan.id == scan_uuid)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Get vulnerabilities
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_uuid)
    )
    vulnerabilities = vuln_result.scalars().all()

    # Get unique CVEs from this scan
    unique_cves = set(v.cve_id for v in vulnerabilities)

    # Get technique mappings for these CVEs
    tech_result = await db.execute(
        select(CVETechnique).where(CVETechnique.cve_id.in_(unique_cves))
    )
    cve_techniques = tech_result.scalars().all()

    # Build technique breakdown
    technique_map = {}
    for ct in cve_techniques:
        if ct.technique_id not in technique_map:
            technique_map[ct.technique_id] = {
                "technique_id": ct.technique_id,
                "confidence": ct.confidence,
                "source_cves": []
            }
        technique_map[ct.technique_id]["source_cves"].append(ct.cve_id)

    return VulnScanDetailResponse(
        scan_id=str(scan.id),
        filename=scan.filename,
        scan_date=scan.scan_date,
        uploaded_by=scan.uploaded_by,
        created_at=scan.created_at,
        vulnerabilities=[{
            "cve_id": v.cve_id,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "asset": v.asset,
            "port": v.port,
            "plugin_id": v.plugin_id,
            "plugin_name": v.plugin_name,
        } for v in vulnerabilities],
        techniques=list(technique_map.values()),
        total_vulnerabilities=len(vulnerabilities),
        total_techniques=len(technique_map)
    )


@router.get("/scans/{scan_id}/techniques", response_model=TechniqueListResponse)
async def get_scan_techniques(
    scan_id: str,
    user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
):
    """
    Get only the MITRE ATT&CK technique mappings for a scan.

    This returns the "blue layer" data - techniques found in vulnerabilities.

    Returns:
        List of techniques with confidence scores and source CVEs
    """
    # Get scan
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan_id format"
        )

    result = await db.execute(
        select(VulnerabilityScan).where(VulnerabilityScan.id == scan_uuid)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    # Get vulnerabilities to find CVEs
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_uuid)
    )
    vulnerabilities = vuln_result.scalars().all()
    unique_cves = set(v.cve_id for v in vulnerabilities)

    # Get technique mappings
    tech_result = await db.execute(
        select(CVETechnique).where(CVETechnique.cve_id.in_(unique_cves))
    )
    cve_techniques = tech_result.scalars().all()

    # Build technique list
    technique_map = {}
    for ct in cve_techniques:
        if ct.technique_id not in technique_map:
            technique_map[ct.technique_id] = {
                "technique_id": ct.technique_id,
                "confidence": ct.confidence,
                "color": "blue",  # Blue = vulnerability only (Phase 5 will override to red if intel overlap)
                "source_cves": []
            }
        technique_map[ct.technique_id]["source_cves"].append(ct.cve_id)

    return TechniqueListResponse(
        scan_id=str(scan.id),
        techniques=list(technique_map.values()),
        total=len(technique_map)
    )


@router.get("/features", tags=["Phase 2.5"])
async def get_feature_statistics(user: Optional[User] = Depends(get_current_user_optional)):
    """
    Get Phase 2.5 feature flag statistics.

    Returns information about which optional enhancements are enabled and their status.
    Useful for troubleshooting and understanding the current configuration.

    **Phase 2.5 Features:**
    - NVD API integration (live CVE data)
    - CAPEC database (comprehensive CWE→Technique mappings)
    - ATT&CK STIX validation (technique validation)
    - Redis cache (persistent caching)
    - Extended CWE mappings (400+ CWEs vs. core 15)

    Returns:
        Feature statistics and enablement status
    """
    stats = await CVEMapper.get_feature_statistics()
    return stats
