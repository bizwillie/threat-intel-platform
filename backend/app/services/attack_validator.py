"""
ATT&CK STIX Validation (Phase 2.5 - Optional Feature)

Validates technique IDs against the official MITRE ATT&CK STIX data.

This module is OPTIONAL and controlled by the ENABLE_ATTACK_STIX_VALIDATION feature flag.
If disabled, technique IDs are not validated (assumes they're correct).

Data Source: https://github.com/mitre-attack/attack-stix-data
Download: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
"""

import json
import logging
from typing import Dict, Optional, Set, List
from pathlib import Path
from app.config import settings

logger = logging.getLogger(__name__)


class ATTACKValidator:
    """
    Validates technique IDs against the official ATT&CK STIX data.

    Ensures that generated technique mappings reference valid ATT&CK techniques
    and provides metadata like technique names, tactics, and descriptions.
    """

    _stix_data: Optional[Dict] = None
    _valid_techniques: Optional[Set[str]] = None
    _technique_metadata: Optional[Dict[str, Dict]] = None

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if ATT&CK STIX validation is enabled."""
        return settings.enable_attack_stix_validation

    @classmethod
    def _load_stix_data(cls) -> None:
        """Load ATT&CK STIX bundle from JSON file."""
        if cls._stix_data is not None:
            return  # Already loaded

        if not cls.is_enabled():
            logger.info("ATT&CK STIX validation is disabled via feature flag")
            return

        stix_path = Path(settings.attack_stix_path)

        if not stix_path.exists():
            logger.warning(
                f"ATT&CK STIX data not found at {stix_path}. "
                f"Download from https://github.com/mitre-attack/attack-stix-data"
            )
            cls._stix_data = {}
            cls._valid_techniques = set()
            cls._technique_metadata = {}
            return

        try:
            with open(stix_path, 'r', encoding='utf-8') as f:
                cls._stix_data = json.load(f)

            logger.info(f"Loaded ATT&CK STIX data from {stix_path}")
            cls._build_technique_index()

        except Exception as e:
            logger.error(f"Failed to load ATT&CK STIX data: {e}")
            cls._stix_data = {}
            cls._valid_techniques = set()
            cls._technique_metadata = {}

    @classmethod
    def _build_technique_index(cls) -> None:
        """Build index of valid technique IDs and their metadata."""
        cls._valid_techniques = set()
        cls._technique_metadata = {}

        if not cls._stix_data:
            return

        # Parse STIX bundle
        # Format: { "type": "bundle", "objects": [ { "type": "attack-pattern", ... }, ... ] }
        objects = cls._stix_data.get("objects", [])

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue

            # Extract external references to get ATT&CK ID
            external_refs = obj.get("external_references", [])
            technique_id = None

            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            if not technique_id:
                continue

            cls._valid_techniques.add(technique_id)

            # Store metadata
            cls._technique_metadata[technique_id] = {
                "name": obj.get("name", "Unknown"),
                "description": obj.get("description", ""),
                "tactics": [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])],
                "platforms": obj.get("x_mitre_platforms", []),
                "deprecated": obj.get("x_mitre_deprecated", False),
                "subtechnique_of": cls._extract_parent_technique(technique_id),
            }

        logger.info(f"Indexed {len(cls._valid_techniques)} ATT&CK techniques")

    @classmethod
    def _extract_parent_technique(cls, technique_id: str) -> Optional[str]:
        """Extract parent technique ID for sub-techniques."""
        # Sub-techniques have format T1234.001
        if "." in technique_id:
            return technique_id.split(".")[0]
        return None

    @classmethod
    def is_valid_technique(cls, technique_id: str) -> bool:
        """
        Check if a technique ID is valid according to ATT&CK STIX data.

        Args:
            technique_id: Technique ID (e.g., "T1059" or "T1059.001")

        Returns:
            True if valid, False otherwise (or if validation is disabled)
        """
        if not cls.is_enabled():
            # If validation is disabled, assume all techniques are valid
            return True

        if cls._valid_techniques is None:
            cls._load_stix_data()

        if not cls._valid_techniques:
            # If we couldn't load STIX data, be permissive
            logger.warning("ATT&CK STIX data not loaded - cannot validate technique ID")
            return True

        return technique_id in cls._valid_techniques

    @classmethod
    def get_technique_metadata(cls, technique_id: str) -> Optional[Dict]:
        """
        Get metadata for a technique from STIX data.

        Args:
            technique_id: Technique ID (e.g., "T1059")

        Returns:
            Dictionary with technique metadata or None if not found
        """
        if not cls.is_enabled():
            return None

        if cls._technique_metadata is None:
            cls._load_stix_data()

        return cls._technique_metadata.get(technique_id)

    @classmethod
    def validate_techniques(cls, technique_ids: List[str]) -> Dict[str, bool]:
        """
        Validate multiple technique IDs at once.

        Args:
            technique_ids: List of technique IDs to validate

        Returns:
            Dictionary mapping technique_id → is_valid
        """
        return {tech_id: cls.is_valid_technique(tech_id) for tech_id in technique_ids}

    @classmethod
    def get_deprecated_techniques(cls, technique_ids: List[str]) -> List[str]:
        """
        Get list of deprecated techniques from a set of technique IDs.

        Args:
            technique_ids: List of technique IDs to check

        Returns:
            List of technique IDs that are deprecated
        """
        if not cls.is_enabled():
            return []

        if cls._technique_metadata is None:
            cls._load_stix_data()

        deprecated = []
        for tech_id in technique_ids:
            metadata = cls._technique_metadata.get(tech_id)
            if metadata and metadata.get("deprecated", False):
                deprecated.append(tech_id)

        return deprecated

    @classmethod
    def get_statistics(cls) -> Dict:
        """Get statistics about the loaded ATT&CK STIX data."""
        if not cls.is_enabled():
            return {
                "enabled": False,
                "message": "ATT&CK STIX validation is disabled"
            }

        if cls._stix_data is None:
            cls._load_stix_data()

        technique_count = len(cls._valid_techniques) if cls._valid_techniques else 0
        parent_count = len([t for t in (cls._valid_techniques or []) if "." not in t])
        sub_count = len([t for t in (cls._valid_techniques or []) if "." in t])

        return {
            "enabled": True,
            "data_loaded": cls._stix_data is not None and len(cls._stix_data) > 0,
            "total_techniques": technique_count,
            "parent_techniques": parent_count,
            "sub_techniques": sub_count,
        }


# Preload STIX data on module import if enabled
if settings.enable_attack_stix_validation:
    logger.info("ATT&CK STIX validation enabled - preloading STIX data")
    ATTACKValidator._load_stix_data()
else:
    logger.info("ATT&CK STIX validation disabled - techniques will not be validated")
