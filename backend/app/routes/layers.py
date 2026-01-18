"""
Layer generation and correlation routes (Phase 5)

Endpoints for generating MITRE ATT&CK layers with correlation logic.
"""

import logging
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, User
from app.models.database import get_db
from app.schemas.layer import (
    LayerGenerateRequest,
    LayerGenerateResponse,
    LayerBreakdown,
    LayerStatistics,
    Layer,
    LayerDetail,
    LayerTechnique,
)
from app.services.correlation import CorrelationEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/layers", tags=["Layers"])


@router.post("/generate", response_model=LayerGenerateResponse, status_code=status.HTTP_201_CREATED)
async def generate_layer(
    request: LayerGenerateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Generate a MITRE ATT&CK layer by correlating intel and vulnerability data.

    Color Assignment Rules:
    - Yellow (#F59E0B): Intel only (from threat reports)
    - Blue (#3B82F6): Vulnerability only (from scans)
    - Red (#EF4444): CRITICAL OVERLAP (both intel and vulnerability)

    This is the core intellectual property of UTIP.

    Request:
    ```json
    {
        "name": "Q4 2024 Threat Landscape",
        "description": "Correlation of Q4 threat intel and vulnerability scans",
        "intel_report_ids": ["uuid1", "uuid2"],
        "vuln_scan_ids": ["uuid3"]
    }
    ```

    Response:
    ```json
    {
        "layer_id": "uuid",
        "name": "Q4 2024 Threat Landscape",
        "breakdown": {"red": 12, "yellow": 45, "blue": 30, "total": 87},
        "statistics": {
            "intel_reports_used": 2,
            "vuln_scans_used": 1,
            "unique_intel_techniques": 57,
            "unique_vuln_techniques": 42,
            "overlap_percentage": 13.79
        }
    }
    ```
    """
    logger.info(f"User {user.username} generating layer: {request.name}")

    # Validate that at least one source is provided
    if not request.intel_report_ids and not request.vuln_scan_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one intel report or vulnerability scan must be provided"
        )

    try:
        # Call correlation engine
        result = await CorrelationEngine.generate_layer(
            db=db,
            name=request.name,
            description=request.description,
            intel_report_ids=request.intel_report_ids,
            vuln_scan_ids=request.vuln_scan_ids,
            created_by=user.id
        )

        # Build response
        return LayerGenerateResponse(
            layer_id=result["layer_id"],
            name=result["name"],
            breakdown=LayerBreakdown(**result["breakdown"]),
            statistics=LayerStatistics(**result["statistics"]),
            message="Layer generated successfully"
        )

    except Exception as e:
        logger.error(f"Failed to generate layer: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate layer: {str(e)}"
        )


@router.get("/", response_model=List[Layer])
async def list_layers(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    List all generated layers.

    Returns:
        List of layers with metadata (no technique details)
    """
    result = await db.execute(
        text("""
            SELECT id, name, description, created_by, created_at
            FROM layers
            ORDER BY created_at DESC
        """)
    )

    layers = []
    for row in result.fetchall():
        layers.append(Layer(
            id=uuid.UUID(row[0]),
            name=row[1],
            description=row[2],
            created_by=uuid.UUID(row[3]),
            created_at=row[4]
        ))

    return layers


@router.get("/{layer_id}", response_model=LayerDetail)
async def get_layer(
    layer_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Get a generated layer with all techniques.

    Returns:
        Layer metadata and all techniques with colors and confidence
    """
    # Get layer metadata
    layer_result = await db.execute(
        text("""
            SELECT id, name, description, created_by, created_at
            FROM layers
            WHERE id = :id
        """),
        {"id": layer_id}
    )

    layer_row = layer_result.fetchone()
    if not layer_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Layer not found"
        )

    # Get techniques
    techniques = await CorrelationEngine.get_layer_techniques(db, layer_id)

    # Calculate breakdown
    breakdown = {"red": 0, "yellow": 0, "blue": 0}
    for tech in techniques:
        if tech["color"] == CorrelationEngine.COLOR_RED:
            breakdown["red"] += 1
        elif tech["color"] == CorrelationEngine.COLOR_YELLOW:
            breakdown["yellow"] += 1
        elif tech["color"] == CorrelationEngine.COLOR_BLUE:
            breakdown["blue"] += 1

    # Build response
    layer_detail = LayerDetail(
        id=uuid.UUID(layer_row[0]),
        name=layer_row[1],
        description=layer_row[2],
        created_by=uuid.UUID(layer_row[3]),
        created_at=layer_row[4],
        techniques=[LayerTechnique(**tech) for tech in techniques],
        technique_count=len(techniques),
        breakdown=breakdown
    )

    return layer_detail


@router.get("/{layer_id}/export", response_class=JSONResponse)
async def export_layer_navigator(
    layer_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Export layer to MITRE ATT&CK Navigator JSON format.

    Returns:
        Navigator-compatible JSON that can be imported into ATT&CK Navigator
    """
    try:
        navigator_json = await CorrelationEngine.export_to_navigator(db, layer_id)
        return JSONResponse(content=navigator_json)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to export layer: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export layer: {str(e)}"
        )


@router.delete("/{layer_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_layer(
    layer_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Delete a layer and all associated techniques.

    Note: Only the layer creator can delete it.
    """
    # Check if layer exists and user is creator
    layer_result = await db.execute(
        text("""
            SELECT created_by FROM layers WHERE id = :id
        """),
        {"id": layer_id}
    )

    layer_row = layer_result.fetchone()
    if not layer_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Layer not found"
        )

    # Verify ownership
    if str(layer_row[0]) != str(user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only delete layers you created"
        )

    # Delete layer techniques (cascades from foreign key)
    await db.execute(
        text("DELETE FROM layer_techniques WHERE layer_id = :id"),
        {"id": layer_id}
    )

    # Delete layer
    await db.execute(
        text("DELETE FROM layers WHERE id = :id"),
        {"id": layer_id}
    )

    await db.commit()

    logger.info(f"User {user.username} deleted layer {layer_id}")
    return None
