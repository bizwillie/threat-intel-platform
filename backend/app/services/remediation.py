"""
Remediation Engine (Phase 7)

Maps MITRE ATT&CK techniques to actionable remediation guidance:
- MITRE Mitigations (M-series IDs)
- CIS Controls (v8)
- Detection Rules (Sigma/YARA patterns)
- Hardening guidance

This is the "so what now?" layer - turning threat intelligence into action.

Data is loaded from external JSON files for maintainability:
- data/remediation/mitigations.json
- data/remediation/cis_controls.json
- data/remediation/detection_rules.json
- data/remediation/hardening_guidance.json
"""

import json
import logging
import os
from typing import Dict, List, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

# Path to data directory (relative to backend root)
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "remediation")


@lru_cache(maxsize=1)
def _load_mitigations() -> Dict[str, List[Dict[str, str]]]:
    """Load mitigations from JSON file with caching."""
    path = os.path.join(DATA_DIR, "mitigations.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Mitigations file not found: {path}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in mitigations file: {e}")
        return {}


@lru_cache(maxsize=1)
def _load_cis_controls() -> Dict[str, List[Dict[str, str]]]:
    """Load CIS controls from JSON file with caching."""
    path = os.path.join(DATA_DIR, "cis_controls.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"CIS controls file not found: {path}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in CIS controls file: {e}")
        return {}


@lru_cache(maxsize=1)
def _load_detection_rules() -> Dict[str, List[Dict[str, str]]]:
    """Load detection rules from JSON file with caching."""
    path = os.path.join(DATA_DIR, "detection_rules.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Detection rules file not found: {path}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in detection rules file: {e}")
        return {}


@lru_cache(maxsize=1)
def _load_hardening_guidance() -> Dict[str, str]:
    """Load hardening guidance from JSON file with caching."""
    path = os.path.join(DATA_DIR, "hardening_guidance.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Hardening guidance file not found: {path}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in hardening guidance file: {e}")
        return {}


class RemediationService:
    """
    Service for mapping techniques to remediation guidance.

    Provides actionable mitigations, security controls, and detection rules
    for MITRE ATT&CK techniques identified in correlation layers.

    Data is loaded from external JSON files and cached in memory for performance.
    """

    @staticmethod
    async def get_technique_remediation(technique_id: str) -> Optional[Dict]:
        """
        Get remediation guidance for a specific technique.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1059.001")

        Returns:
            Dict containing mitigations, CIS controls, detection rules, and hardening guidance
            Returns None if technique not found in remediation database
        """
        logger.info(f"Retrieving remediation guidance for technique: {technique_id}")

        # Load data from JSON files (cached)
        mitigations = _load_mitigations()
        cis_controls = _load_cis_controls()
        detection_rules = _load_detection_rules()

        # Check if we have remediation data for this technique
        has_mitigations = technique_id in mitigations
        has_cis_controls = technique_id in cis_controls
        has_detection_rules = technique_id in detection_rules

        if not (has_mitigations or has_cis_controls or has_detection_rules):
            logger.warning(f"No remediation data found for technique: {technique_id}")
            return None

        # Build response
        response = {
            "technique_id": technique_id,
            "mitigations": mitigations.get(technique_id, []),
            "cis_controls": cis_controls.get(technique_id, []),
            "detection_rules": detection_rules.get(technique_id, []),
            "hardening_guidance": RemediationService._get_hardening_guidance(technique_id)
        }

        logger.info(f"Retrieved {len(response['mitigations'])} mitigations, "
                   f"{len(response['cis_controls'])} CIS controls, "
                   f"{len(response['detection_rules'])} detection rules for {technique_id}")

        return response

    @staticmethod
    def _get_hardening_guidance(technique_id: str) -> str:
        """
        Get hardening guidance for a technique from external JSON.

        This summarizes the key actions to take based on mitigations and controls.
        """
        guidance = _load_hardening_guidance()
        return guidance.get(technique_id, guidance.get("_default",
            "**General Hardening Guidance:**\n"
            "1. Apply security patches and updates promptly\n"
            "2. Implement defense-in-depth security controls\n"
            "3. Enable comprehensive logging and monitoring\n"
            "4. Conduct regular security assessments\n"
            "5. Follow vendor security best practices"))

    @staticmethod
    async def get_layer_remediation(layer_id: str, db) -> Dict:
        """
        Get comprehensive remediation guidance for all techniques in a layer.

        Args:
            layer_id: UUID of the layer
            db: Database session

        Returns:
            Dict containing remediation for all techniques, prioritized by color
        """
        from sqlalchemy import text

        logger.info(f"Retrieving layer remediation for layer: {layer_id}")

        # Get all techniques from layer
        result = await db.execute(
            text("""
                SELECT technique_id, color, confidence, from_intel, from_vuln
                FROM layer_techniques
                WHERE layer_id = :layer_id
                ORDER BY
                    CASE color
                        WHEN '#EF4444' THEN 1  -- Red (critical) first
                        WHEN '#F59E0B' THEN 2  -- Yellow second
                        WHEN '#3B82F6' THEN 3  -- Blue last
                    END,
                    confidence DESC
            """),
            {"layer_id": layer_id}
        )

        techniques = []
        for row in result.fetchall():
            technique_id = row[0]
            remediation = await RemediationService.get_technique_remediation(technique_id)

            techniques.append({
                "technique_id": technique_id,
                "color": row[1],
                "confidence": row[2],
                "from_intel": row[3],
                "from_vuln": row[4],
                "remediation": remediation
            })

        # Calculate statistics
        total_techniques = len(techniques)
        red_count = sum(1 for t in techniques if t["color"] == "#EF4444")
        yellow_count = sum(1 for t in techniques if t["color"] == "#F59E0B")
        blue_count = sum(1 for t in techniques if t["color"] == "#3B82F6")

        has_remediation = sum(1 for t in techniques if t["remediation"] is not None)
        coverage = (has_remediation / total_techniques * 100) if total_techniques > 0 else 0

        return {
            "layer_id": layer_id,
            "techniques": techniques,
            "statistics": {
                "total_techniques": total_techniques,
                "red_techniques": red_count,
                "yellow_techniques": yellow_count,
                "blue_techniques": blue_count,
                "remediation_coverage": round(coverage, 2)
            }
        }
