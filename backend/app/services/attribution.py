"""
Attribution Engine (Phase 6)

Deterministic threat actor attribution based on technique overlap.

Uses weighted scoring - no probabilistic LLM inference.

Scoring Algorithm:
1. For each threat actor, calculate overlap between layer techniques and actor techniques
2. Sum the weights of matching techniques
3. Normalize by total possible weight to get confidence score (0.0-1.0)
4. Return actors sorted by confidence descending

This is fully deterministic and auditable - no black box LLM inference.
"""

import logging
from typing import List, Dict, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

logger = logging.getLogger(__name__)


class AttributionService:
    """
    Service for attributing layers to threat actors using deterministic scoring.

    The attribution algorithm is based on technique overlap with known actor TTPs.
    Each threat actor has a set of techniques with weights indicating how
    frequently/significantly they use each technique.

    Confidence calculation:
    - For each actor, sum the weights of techniques that match the layer
    - Divide by the total weight across all actor techniques
    - Result is a confidence score from 0.0 (no match) to 1.0 (perfect match)
    """

    @staticmethod
    async def attribute_layer(
        db: AsyncSession,
        layer_id: str,
        top_n: int = 10,
        min_confidence: float = 0.0
    ) -> List[Dict]:
        """
        Attribute a layer to threat actors using deterministic scoring.

        Algorithm:
        1. Get all techniques from the generated layer
        2. For each threat actor in database:
           a. Get actor's known techniques with weights
           b. Calculate overlap with layer techniques
           c. Sum weights of overlapping techniques
           d. Divide by total possible weight for confidence
        3. Sort actors by confidence descending
        4. Return top N with supporting evidence

        Args:
            db: Database session
            layer_id: UUID of the layer to attribute
            top_n: Number of top actors to return (default: 10)
            min_confidence: Minimum confidence threshold (default: 0.0)

        Returns:
            List of threat actors with confidence scores and matching techniques

        Example output:
        [
            {
                "actor_id": "APT29",
                "actor_name": "Cozy Bear",
                "description": "Russian cyber espionage group...",
                "confidence": 0.847,
                "matching_techniques": ["T1059.001", "T1566.001", ...],
                "match_count": 23,
                "total_actor_techniques": 45
            },
            ...
        ]
        """
        logger.info(f"Attributing layer {layer_id} to threat actors")

        # Step 1: Get all techniques from the layer
        layer_techniques = await AttributionService._get_layer_techniques(db, layer_id)

        if not layer_techniques:
            logger.warning(f"Layer {layer_id} has no techniques - cannot attribute")
            return []

        layer_technique_set = set(layer_techniques)
        logger.info(f"Layer has {len(layer_technique_set)} unique techniques")

        # Step 2: Get all threat actors
        actors = await AttributionService._get_all_actors(db)

        if not actors:
            logger.warning("No threat actors in database - cannot attribute")
            return []

        logger.info(f"Evaluating {len(actors)} threat actors")

        # Step 3: Calculate attribution score for each actor
        attributions = []

        for actor in actors:
            actor_id = actor["id"]
            actor_name = actor["name"]
            actor_description = actor["description"]

            # Get actor's techniques with weights
            actor_techniques = await AttributionService._get_actor_techniques(db, actor_id)

            if not actor_techniques:
                continue

            # Calculate overlap
            matching_techniques = []
            matched_weight = 0.0
            total_weight = 0.0

            for technique_id, weight in actor_techniques.items():
                total_weight += weight
                if technique_id in layer_technique_set:
                    matching_techniques.append(technique_id)
                    matched_weight += weight

            # Calculate confidence score
            if total_weight > 0:
                confidence = matched_weight / total_weight
            else:
                confidence = 0.0

            # Only include if meets minimum confidence threshold
            if confidence >= min_confidence and len(matching_techniques) > 0:
                attributions.append({
                    "actor_id": actor_id,
                    "actor_name": actor_name,
                    "description": actor_description,
                    "confidence": round(confidence, 4),
                    "matching_techniques": sorted(matching_techniques),
                    "match_count": len(matching_techniques),
                    "total_actor_techniques": len(actor_techniques)
                })

        # Step 4: Sort by confidence descending and return top N
        attributions.sort(key=lambda x: x["confidence"], reverse=True)
        top_attributions = attributions[:top_n]

        logger.info(f"Attribution complete: {len(top_attributions)} actors matched (from {len(attributions)} total matches)")

        return top_attributions

    @staticmethod
    async def _get_layer_techniques(db: AsyncSession, layer_id: str) -> List[str]:
        """
        Get all technique IDs from a layer.

        Args:
            db: Database session
            layer_id: UUID of the layer

        Returns:
            List of technique IDs
        """
        result = await db.execute(
            text("""
                SELECT technique_id
                FROM layer_techniques
                WHERE layer_id = :layer_id
            """),
            {"layer_id": layer_id}
        )

        techniques = [row[0] for row in result.fetchall()]
        return techniques

    @staticmethod
    async def _get_all_actors(db: AsyncSession) -> List[Dict]:
        """
        Get all threat actors from the database.

        Args:
            db: Database session

        Returns:
            List of dicts with actor id, name, description
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
            actors.append({
                "id": row[0],
                "name": row[1],
                "description": row[2]
            })

        return actors

    @staticmethod
    async def _get_actor_techniques(db: AsyncSession, actor_id: str) -> Dict[str, float]:
        """
        Get all techniques for a specific threat actor with weights.

        Args:
            db: Database session
            actor_id: Threat actor ID (e.g., "APT29")

        Returns:
            Dict mapping technique_id -> weight
        """
        result = await db.execute(
            text("""
                SELECT technique_id, weight
                FROM actor_techniques
                WHERE actor_id = :actor_id
            """),
            {"actor_id": actor_id}
        )

        techniques = {}
        for row in result.fetchall():
            techniques[row[0]] = row[1]

        return techniques

    @staticmethod
    async def get_actor_details(db: AsyncSession, actor_id: str) -> Optional[Dict]:
        """
        Get detailed information about a specific threat actor.

        Args:
            db: Database session
            actor_id: Threat actor ID (e.g., "APT29")

        Returns:
            Dict with actor details including all techniques, or None if not found
        """
        # Get actor metadata
        result = await db.execute(
            text("""
                SELECT id, name, description
                FROM threat_actors
                WHERE id = :actor_id
            """),
            {"actor_id": actor_id}
        )

        row = result.fetchone()
        if not row:
            return None

        # Get actor techniques
        techniques = await AttributionService._get_actor_techniques(db, actor_id)

        return {
            "actor_id": row[0],
            "actor_name": row[1],
            "description": row[2],
            "techniques": [
                {"technique_id": tid, "weight": weight}
                for tid, weight in techniques.items()
            ],
            "technique_count": len(techniques)
        }
