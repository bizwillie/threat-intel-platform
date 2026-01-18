"""
Threat actor attribution routes (Phase 6)

Endpoints for attributing layers to threat actors using deterministic scoring.
"""

import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, User
from app.database import get_db
from app.schemas.attribution import (
    AttributionRequest,
    AttributionResponse,
    ThreatActorAttribution,
    ThreatActor,
    ThreatActorDetail,
)
from app.services.attribution import AttributionService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/attribution", tags=["Attribution"])


@router.post("/", response_model=AttributionResponse)
async def attribute_layer(
    request: AttributionRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Attribute a layer to threat actors using deterministic scoring.

    Algorithm:
    1. Get all techniques from the specified layer
    2. For each threat actor in database:
       - Calculate overlap with layer techniques
       - Sum weights of matching techniques
       - Normalize by total actor weight for confidence score
    3. Return top N actors sorted by confidence

    Request:
    ```json
    {
        "layer_id": "550e8400-e29b-41d4-a716-446655440000",
        "top_n": 10,
        "min_confidence": 0.1
    }
    ```

    Response:
    ```json
    {
        "layer_id": "550e8400-e29b-41d4-a716-446655440000",
        "layer_name": "Q4 2024 Threat Landscape",
        "attributions": [
            {
                "actor_id": "APT29",
                "actor_name": "Cozy Bear",
                "confidence": 0.847,
                "matching_techniques": ["T1059.001", "T1566.001", ...],
                "match_count": 23,
                "total_actor_techniques": 45
            }
        ],
        "total_actors_evaluated": 45
    }
    ```
    """
    logger.info(f"User {user.username} attributing layer: {request.layer_id}")

    # Verify layer exists
    layer_result = await db.execute(
        text("""
            SELECT name FROM layers WHERE id = :id
        """),
        {"id": request.layer_id}
    )

    layer_row = layer_result.fetchone()
    if not layer_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Layer {request.layer_id} not found"
        )

    layer_name = layer_row[0]

    try:
        # Call attribution service
        attributions = await AttributionService.attribute_layer(
            db=db,
            layer_id=request.layer_id,
            top_n=request.top_n or 10,
            min_confidence=request.min_confidence or 0.0
        )

        # Get total actors count
        count_result = await db.execute(text("SELECT COUNT(*) FROM threat_actors"))
        total_actors = count_result.scalar()

        # Build response
        return AttributionResponse(
            layer_id=request.layer_id,
            layer_name=layer_name,
            attributions=[ThreatActorAttribution(**attr) for attr in attributions],
            total_actors_evaluated=total_actors,
            message="Attribution analysis complete"
        )

    except Exception as e:
        logger.error(f"Failed to attribute layer: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to attribute layer: {str(e)}"
        )


@router.get("/actors", response_model=List[ThreatActor])
async def list_threat_actors(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    List all threat actors in the database.

    Returns:
        List of threat actors with basic metadata (no techniques)
    """
    result = await db.execute(
        text("""
            SELECT id, name, description
            FROM threat_actors
            ORDER BY id
        """)
    )

    actors = []
    for row in result.fetchall():
        actors.append(ThreatActor(
            actor_id=row[0],
            actor_name=row[1],
            description=row[2]
        ))

    return actors


@router.get("/actors/{actor_id}", response_model=ThreatActorDetail)
async def get_threat_actor(
    actor_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Get detailed information about a specific threat actor.

    Returns:
        Threat actor metadata and all associated techniques with weights
    """
    actor_details = await AttributionService.get_actor_details(db, actor_id)

    if not actor_details:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat actor '{actor_id}' not found"
        )

    return ThreatActorDetail(**actor_details)
