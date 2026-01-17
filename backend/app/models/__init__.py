"""
UTIP Database Models

This module contains all SQLAlchemy ORM models for the UTIP platform.
The database is the single source of truth for the system.
"""

from .database import (
    Base,
    ThreatReport,
    ExtractedTechnique,
    VulnerabilityScan,
    Vulnerability,
    CVETechnique,
    Layer,
    LayerTechnique,
    ThreatActor,
    ActorTechnique,
)

__all__ = [
    "Base",
    "ThreatReport",
    "ExtractedTechnique",
    "VulnerabilityScan",
    "Vulnerability",
    "CVETechnique",
    "Layer",
    "LayerTechnique",
    "ThreatActor",
    "ActorTechnique",
]
