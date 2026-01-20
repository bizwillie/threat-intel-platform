"""
Correlation Engine (Phase 5)

Core intellectual property: Layer generation with color-coded correlation logic.

Color Assignment Rules:
- Intel only → Yellow (#F59E0B) - Observed in threat intel
- Vulnerability only → Blue (#3B82F6) - Present in your vulns
- Intel + Vulnerability → Red (#EF4444) - CRITICAL OVERLAP

The correlation logic must be deterministic for auditability.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Layer generation and correlation logic.

    This class is the heart of UTIP - it performs the fusion of:
    1. Threat intelligence (yellow layer)
    2. Vulnerability data (blue layer)
    3. Produces actionable red layer showing critical overlaps
    """

    # Color codes for MITRE Navigator layers
    COLOR_RED = "#EF4444"      # Critical overlap (intel + vuln)
    COLOR_YELLOW = "#F59E0B"   # Intel only
    COLOR_BLUE = "#3B82F6"     # Vulnerability only

    @staticmethod
    async def generate_layer(
        db: AsyncSession,
        name: str,
        description: Optional[str],
        intel_report_ids: List[str],
        vuln_scan_ids: List[str],
        created_by: UUID
    ) -> Dict:
        """
        Generate a correlation layer from intel reports and vulnerability scans.

        Algorithm:
        1. Create layer record in database
        2. Query extracted_techniques for selected intel reports
        3. Query cve_techniques via vulnerabilities for selected scans
        4. Build technique sets: intel_set, vuln_set
        5. Compute union of all techniques
        6. For each technique, apply color rules
        7. Store layer_techniques with from_intel, from_vuln flags
        8. Return layer_id with breakdown statistics

        Args:
            db: Database session
            name: Layer name
            description: Optional description
            intel_report_ids: List of threat report UUIDs
            vuln_scan_ids: List of vulnerability scan UUIDs
            created_by: User UUID who created the layer

        Returns:
            Dict with layer_id, breakdown (red/yellow/blue counts), and statistics
        """
        logger.info(f"Generating layer '{name}' with {len(intel_report_ids)} intel reports and {len(vuln_scan_ids)} vuln scans")

        # Step 1: Create layer record
        layer_id = uuid4()
        await db.execute(
            text("""
                INSERT INTO layers (id, name, description, created_by, created_at)
                VALUES (:id, :name, :description, :created_by, :created_at)
            """),
            {
                "id": str(layer_id),
                "name": name,
                "description": description,
                "created_by": str(created_by),
                "created_at": datetime.utcnow()
            }
        )

        # Step 2: Get intel techniques (yellow layer)
        intel_techniques = await CorrelationEngine._get_intel_techniques(db, intel_report_ids)
        logger.info(f"Found {len(intel_techniques)} unique techniques from intel reports")

        # Step 3: Get vulnerability techniques (blue layer)
        vuln_techniques = await CorrelationEngine._get_vuln_techniques(db, vuln_scan_ids)
        logger.info(f"Found {len(vuln_techniques)} unique techniques from vulnerability scans")

        # Step 4: Build sets for color assignment
        intel_set = set(intel_techniques.keys())
        vuln_set = set(vuln_techniques.keys())

        # Step 5: Compute technique categorization
        red_techniques = intel_set & vuln_set  # Intersection (critical overlap)
        yellow_techniques = intel_set - vuln_set  # Intel only
        blue_techniques = vuln_set - intel_set  # Vulnerability only

        logger.info(f"Layer breakdown: {len(red_techniques)} red, {len(yellow_techniques)} yellow, {len(blue_techniques)} blue")

        # Step 6 & 7: Store layer techniques with color assignments
        technique_count = 0

        # Red techniques (critical overlap)
        for technique_id in red_techniques:
            intel_conf = intel_techniques[technique_id]["confidence"]
            vuln_conf = vuln_techniques[technique_id]["confidence"]
            confidence = max(intel_conf, vuln_conf)  # Take highest confidence

            await db.execute(
                text("""
                    INSERT INTO layer_techniques
                    (layer_id, technique_id, color, confidence, from_intel, from_vuln)
                    VALUES (:layer_id, :technique_id, :color, :confidence, true, true)
                """),
                {
                    "layer_id": str(layer_id),
                    "technique_id": technique_id,
                    "color": CorrelationEngine.COLOR_RED,
                    "confidence": confidence
                }
            )
            technique_count += 1

        # Yellow techniques (intel only)
        for technique_id in yellow_techniques:
            confidence = intel_techniques[technique_id]["confidence"]

            await db.execute(
                text("""
                    INSERT INTO layer_techniques
                    (layer_id, technique_id, color, confidence, from_intel, from_vuln)
                    VALUES (:layer_id, :technique_id, :color, :confidence, true, false)
                """),
                {
                    "layer_id": str(layer_id),
                    "technique_id": technique_id,
                    "color": CorrelationEngine.COLOR_YELLOW,
                    "confidence": confidence
                }
            )
            technique_count += 1

        # Blue techniques (vulnerability only)
        for technique_id in blue_techniques:
            confidence = vuln_techniques[technique_id]["confidence"]

            await db.execute(
                text("""
                    INSERT INTO layer_techniques
                    (layer_id, technique_id, color, confidence, from_intel, from_vuln)
                    VALUES (:layer_id, :technique_id, :color, :confidence, false, true)
                """),
                {
                    "layer_id": str(layer_id),
                    "technique_id": technique_id,
                    "color": CorrelationEngine.COLOR_BLUE,
                    "confidence": confidence
                }
            )
            technique_count += 1

        await db.commit()

        logger.info(f"Layer {layer_id} generated successfully with {technique_count} total techniques")

        # Step 8: Return breakdown statistics
        return {
            "layer_id": str(layer_id),
            "name": name,
            "breakdown": {
                "red": len(red_techniques),
                "yellow": len(yellow_techniques),
                "blue": len(blue_techniques),
                "total": technique_count
            },
            "statistics": {
                "intel_reports_used": len(intel_report_ids),
                "vuln_scans_used": len(vuln_scan_ids),
                "unique_intel_techniques": len(intel_set),
                "unique_vuln_techniques": len(vuln_set),
                "overlap_percentage": round((len(red_techniques) / technique_count * 100) if technique_count > 0 else 0, 2)
            }
        }

    @staticmethod
    async def _get_intel_techniques(db: AsyncSession, report_ids: List[str]) -> Dict[str, Dict]:
        """
        Get all techniques from selected intel reports.

        Returns:
            Dict keyed by technique_id with confidence and metadata
        """
        if not report_ids:
            return {}

        # Use parameterized query to prevent SQL injection
        # PostgreSQL ANY() accepts array parameters safely
        result = await db.execute(
            text("""
                SELECT technique_id, MAX(confidence) as max_confidence
                FROM extracted_techniques
                WHERE report_id = ANY(:report_ids)
                GROUP BY technique_id
            """),
            {"report_ids": [str(rid) for rid in report_ids]}
        )

        techniques = {}
        for row in result.fetchall():
            techniques[row[0]] = {
                "confidence": row[1],
                "source": "intel"
            }

        return techniques

    @staticmethod
    async def _get_vuln_techniques(db: AsyncSession, scan_ids: List[str]) -> Dict[str, Dict]:
        """
        Get all techniques from selected vulnerability scans via CVE mappings.

        Returns:
            Dict keyed by technique_id with confidence and metadata
        """
        if not scan_ids:
            return {}

        # Use parameterized query to prevent SQL injection
        # PostgreSQL ANY() accepts array parameters safely
        result = await db.execute(
            text("""
                SELECT DISTINCT ct.technique_id, MAX(ct.confidence) as max_confidence
                FROM cve_techniques ct
                JOIN vulnerabilities v ON ct.cve_id = v.cve_id
                WHERE v.scan_id = ANY(:scan_ids)
                GROUP BY ct.technique_id
            """),
            {"scan_ids": [str(sid) for sid in scan_ids]}
        )

        techniques = {}
        for row in result.fetchall():
            techniques[row[0]] = {
                "confidence": row[1],
                "source": "vulnerability"
            }

        return techniques

    @staticmethod
    async def get_layer_techniques(db: AsyncSession, layer_id: str) -> List[Dict]:
        """
        Get all techniques in a layer with their colors and metadata.

        Args:
            db: Database session
            layer_id: UUID of the layer

        Returns:
            List of techniques with technique_id, color, confidence, flags
        """
        result = await db.execute(
            text("""
                SELECT technique_id, color, confidence, from_intel, from_vuln
                FROM layer_techniques
                WHERE layer_id = :layer_id
                ORDER BY technique_id
            """),
            {"layer_id": layer_id}
        )

        techniques = []
        for row in result.fetchall():
            techniques.append({
                "technique_id": row[0],
                "color": row[1],
                "confidence": row[2],
                "from_intel": row[3],
                "from_vuln": row[4]
            })

        return techniques

    @staticmethod
    async def export_to_navigator(db: AsyncSession, layer_id: str) -> Dict:
        """
        Export layer to MITRE ATT&CK Navigator JSON format.

        Returns Navigator-compatible JSON structure.

        Args:
            db: Database session
            layer_id: UUID of the layer

        Returns:
            Dict in Navigator layer format (v4.5)
        """
        # Get layer metadata
        layer_result = await db.execute(
            text("""
                SELECT name, description, created_at
                FROM layers
                WHERE id = :id
            """),
            {"id": layer_id}
        )

        layer_row = layer_result.fetchone()
        if not layer_row:
            raise ValueError(f"Layer {layer_id} not found")

        layer_name = layer_row[0]
        layer_description = layer_row[1] or ""
        created_at = layer_row[2]

        # Get techniques
        techniques = await CorrelationEngine.get_layer_techniques(db, layer_id)

        # Build Navigator JSON structure
        navigator_layer = {
            "name": layer_name,
            "versions": {
                "attack": "14",  # ATT&CK version
                "navigator": "4.5",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": layer_description,
            "filters": {
                "platforms": ["windows", "linux", "macos"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False
            },
            "hideDisabled": False,
            "techniques": [],
            "gradient": {
                "colors": [
                    "#ffffff",
                    "#ff0000"
                ],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [
                {
                    "label": "Critical Overlap (Intel + Vuln)",
                    "color": CorrelationEngine.COLOR_RED
                },
                {
                    "label": "Threat Intel Only",
                    "color": CorrelationEngine.COLOR_YELLOW
                },
                {
                    "label": "Vulnerability Only",
                    "color": CorrelationEngine.COLOR_BLUE
                }
            ],
            "metadata": [
                {
                    "name": "UTIP Layer",
                    "value": layer_name
                },
                {
                    "name": "Generated",
                    "value": created_at.isoformat()
                },
                {
                    "name": "Total Techniques",
                    "value": str(len(techniques))
                }
            ],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False
        }

        # Add techniques to Navigator format
        for tech in techniques:
            technique_entry = {
                "techniqueID": tech["technique_id"],
                "color": tech["color"],
                "score": int(tech["confidence"] * 100),  # Convert 0.0-1.0 to 0-100
                "enabled": True,
                "metadata": []
            }

            # Add metadata tags
            if tech["from_intel"]:
                technique_entry["metadata"].append({
                    "name": "Source",
                    "value": "Threat Intelligence"
                })
            if tech["from_vuln"]:
                technique_entry["metadata"].append({
                    "name": "Source",
                    "value": "Vulnerability Scan"
                })

            navigator_layer["techniques"].append(technique_entry)

        logger.info(f"Exported layer {layer_id} to Navigator format with {len(techniques)} techniques")

        return navigator_layer
