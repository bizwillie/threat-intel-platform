"""
CAPEC Database Integration (Phase 2.5 - Optional Feature)

Provides enhanced CWE→CAPEC→ATT&CK Technique mapping using the full CAPEC database.

This module is OPTIONAL and controlled by the ENABLE_CAPEC_DATABASE feature flag.
If disabled, the system falls back to the simpler CWE→Technique mappings in cve_mapper.py.

Data Source: https://capec.mitre.org/data/index.html
Download: https://capec.mitre.org/data/xml/capec_latest.xml
"""

import json
import logging
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from app.config import settings

logger = logging.getLogger(__name__)


class CAPECMapper:
    """
    Maps CWEs to ATT&CK techniques via CAPEC attack patterns.

    This provides more comprehensive coverage than the hardcoded CWE mappings,
    but requires downloading and maintaining the CAPEC database.
    """

    _capec_data: Optional[Dict] = None
    _cwe_to_capec: Optional[Dict[str, List[str]]] = None
    _capec_to_technique: Optional[Dict[str, List[Tuple[str, float]]]] = None

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if CAPEC database integration is enabled."""
        return settings.enable_capec_database

    @classmethod
    def _load_capec_database(cls) -> None:
        """Load CAPEC database from JSON file."""
        if cls._capec_data is not None:
            return  # Already loaded

        if not cls.is_enabled():
            logger.info("CAPEC database integration is disabled via feature flag")
            return

        capec_path = Path(settings.capec_data_path)

        if not capec_path.exists():
            logger.warning(
                f"CAPEC database not found at {capec_path}. "
                f"Download from https://capec.mitre.org/data/index.html"
            )
            cls._capec_data = {}
            cls._cwe_to_capec = {}
            cls._capec_to_technique = {}
            return

        try:
            with open(capec_path, 'r', encoding='utf-8') as f:
                cls._capec_data = json.load(f)

            logger.info(f"Loaded CAPEC database from {capec_path}")
            cls._build_mapping_indexes()

        except Exception as e:
            logger.error(f"Failed to load CAPEC database: {e}")
            cls._capec_data = {}
            cls._cwe_to_capec = {}
            cls._capec_to_technique = {}

    @classmethod
    def _build_mapping_indexes(cls) -> None:
        """Build CWE→CAPEC and CAPEC→Technique indexes from CAPEC data."""
        cls._cwe_to_capec = {}
        cls._capec_to_technique = {}

        if not cls._capec_data:
            return

        # Parse CAPEC database structure and build indexes
        # This is a placeholder - actual implementation depends on CAPEC JSON format
        # Format: { "attack_patterns": [ { "id": "CAPEC-1", "related_weaknesses": ["CWE-78"], ... } ] }

        attack_patterns = cls._capec_data.get("attack_patterns", [])

        for pattern in attack_patterns:
            capec_id = pattern.get("id", "")

            # Build CWE→CAPEC mapping
            for cwe in pattern.get("related_weaknesses", []):
                if cwe not in cls._cwe_to_capec:
                    cls._cwe_to_capec[cwe] = []
                cls._cwe_to_capec[cwe].append(capec_id)

            # Build CAPEC→Technique mapping
            # This requires ATT&CK mappings in CAPEC data or a separate mapping file
            techniques = pattern.get("attack_techniques", [])
            if techniques:
                cls._capec_to_technique[capec_id] = [
                    (tech["id"], tech.get("confidence", 0.75))
                    for tech in techniques
                ]

        logger.info(
            f"Built CAPEC indexes: {len(cls._cwe_to_capec)} CWEs, "
            f"{len(cls._capec_to_technique)} CAPEC patterns"
        )

    @classmethod
    def map_cwe_to_techniques(cls, cwe_id: str) -> List[Tuple[str, float, str]]:
        """
        Map a CWE to ATT&CK techniques via CAPEC.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-78")

        Returns:
            List of (technique_id, confidence, source) tuples
        """
        if not cls.is_enabled():
            return []

        # Ensure database is loaded
        if cls._capec_data is None:
            cls._load_capec_database()

        if not cls._cwe_to_capec:
            return []

        # Get CAPEC patterns for this CWE
        capec_ids = cls._cwe_to_capec.get(cwe_id, [])

        if not capec_ids:
            return []

        # Get techniques for each CAPEC pattern
        techniques = []
        seen = set()

        for capec_id in capec_ids:
            capec_techniques = cls._capec_to_technique.get(capec_id, [])

            for tech_id, confidence in capec_techniques:
                if tech_id not in seen:
                    techniques.append((tech_id, confidence, f"capec-{capec_id}"))
                    seen.add(tech_id)

        return techniques

    @classmethod
    def get_capec_details(cls, capec_id: str) -> Optional[Dict]:
        """
        Get detailed information about a CAPEC attack pattern.

        Args:
            capec_id: CAPEC identifier (e.g., "CAPEC-1")

        Returns:
            Dictionary with CAPEC details or None if not found
        """
        if not cls.is_enabled():
            return None

        if cls._capec_data is None:
            cls._load_capec_database()

        if not cls._capec_data:
            return None

        for pattern in cls._capec_data.get("attack_patterns", []):
            if pattern.get("id") == capec_id:
                return pattern

        return None

    @classmethod
    def get_statistics(cls) -> Dict:
        """Get statistics about the loaded CAPEC database."""
        if not cls.is_enabled():
            return {
                "enabled": False,
                "message": "CAPEC database integration is disabled"
            }

        if cls._capec_data is None:
            cls._load_capec_database()

        return {
            "enabled": True,
            "database_loaded": cls._capec_data is not None and len(cls._capec_data) > 0,
            "total_attack_patterns": len(cls._capec_data.get("attack_patterns", [])) if cls._capec_data else 0,
            "cwe_mappings": len(cls._cwe_to_capec) if cls._cwe_to_capec else 0,
            "technique_mappings": len(cls._capec_to_technique) if cls._capec_to_technique else 0,
        }


# Preload database on module import if enabled
if settings.enable_capec_database:
    logger.info("CAPEC database feature enabled - preloading database")
    CAPECMapper._load_capec_database()
else:
    logger.info("CAPEC database feature disabled - using core CWE mappings only")
