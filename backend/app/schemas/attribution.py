"""
Phase 6: Attribution schemas

Pydantic models for threat actor attribution requests and responses.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class AttributionRequest(BaseModel):
    """Request to attribute a layer to threat actors."""

    layer_id: str = Field(..., description="UUID of the layer to attribute")
    top_n: Optional[int] = Field(10, ge=1, le=50, description="Number of top actors to return (default: 10)")
    min_confidence: Optional[float] = Field(0.0, ge=0.0, le=1.0, description="Minimum confidence threshold (default: 0.0)")

    class Config:
        json_schema_extra = {
            "example": {
                "layer_id": "550e8400-e29b-41d4-a716-446655440000",
                "top_n": 10,
                "min_confidence": 0.1
            }
        }


class ActorTechniqueWeight(BaseModel):
    """Technique with weight for an actor."""

    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")
    weight: float = Field(..., description="Weight/importance for this actor")


class ThreatActorAttribution(BaseModel):
    """Attribution result for a single threat actor."""

    actor_id: str = Field(..., description="Threat actor ID (e.g., APT29)")
    actor_name: str = Field(..., description="Threat actor display name")
    description: Optional[str] = Field(None, description="Actor description")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Attribution confidence score (0.0-1.0)")
    matching_techniques: List[str] = Field(..., description="Techniques that match the layer")
    match_count: int = Field(..., description="Number of matching techniques")
    total_actor_techniques: int = Field(..., description="Total techniques known for this actor")

    class Config:
        json_schema_extra = {
            "example": {
                "actor_id": "APT29",
                "actor_name": "Cozy Bear",
                "description": "Russian cyber espionage group targeting governments and organizations",
                "confidence": 0.847,
                "matching_techniques": ["T1059.001", "T1566.001", "T1071.001"],
                "match_count": 23,
                "total_actor_techniques": 45
            }
        }


class AttributionResponse(BaseModel):
    """Response from attribution analysis."""

    layer_id: str = Field(..., description="Layer that was attributed")
    layer_name: str = Field(..., description="Layer name")
    attributions: List[ThreatActorAttribution] = Field(..., description="Threat actor matches sorted by confidence")
    total_actors_evaluated: int = Field(..., description="Total threat actors evaluated")
    message: str = Field(default="Attribution analysis complete")

    class Config:
        json_schema_extra = {
            "example": {
                "layer_id": "550e8400-e29b-41d4-a716-446655440000",
                "layer_name": "Q4 2024 Threat Landscape",
                "attributions": [
                    {
                        "actor_id": "APT29",
                        "actor_name": "Cozy Bear",
                        "description": "Russian cyber espionage group",
                        "confidence": 0.847,
                        "matching_techniques": ["T1059.001", "T1566.001"],
                        "match_count": 23,
                        "total_actor_techniques": 45
                    },
                    {
                        "actor_id": "APT28",
                        "actor_name": "Fancy Bear",
                        "description": "Russian military intelligence",
                        "confidence": 0.632,
                        "matching_techniques": ["T1566.001", "T1071.001"],
                        "match_count": 18,
                        "total_actor_techniques": 38
                    }
                ],
                "total_actors_evaluated": 45,
                "message": "Attribution analysis complete"
            }
        }


class ThreatActor(BaseModel):
    """Threat actor metadata."""

    actor_id: str = Field(..., description="Threat actor ID (e.g., APT29)")
    actor_name: str = Field(..., description="Threat actor display name")
    description: Optional[str] = Field(None, description="Actor description")


class ThreatActorDetail(ThreatActor):
    """Detailed threat actor information with techniques."""

    techniques: List[ActorTechniqueWeight] = Field(..., description="Techniques used by this actor")
    technique_count: int = Field(..., description="Total number of techniques")

    class Config:
        json_schema_extra = {
            "example": {
                "actor_id": "APT29",
                "actor_name": "Cozy Bear",
                "description": "Russian cyber espionage group targeting governments and organizations",
                "techniques": [
                    {"technique_id": "T1059.001", "weight": 0.95},
                    {"technique_id": "T1566.001", "weight": 0.87}
                ],
                "technique_count": 45
            }
        }
