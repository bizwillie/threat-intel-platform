"""
Remediation routes (Phase 7)

Endpoints for retrieving technique remediation guidance.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, User
from app.models.database import get_db
from app.schemas.remediation import (
    TechniqueRemediation,
    Mitigation,
    CISControl,
    DetectionRule,
    LayerRemediationResponse,
    LayerTechniqueRemediation,
    LayerRemediationStatistics,
)
from app.services.remediation import RemediationService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/remediation", tags=["Remediation"])


@router.get("/techniques/{technique_id}", response_model=TechniqueRemediation)
async def get_technique_remediation(
    technique_id: str,
    user: User = Depends(get_current_user)
):
    """
    Get remediation guidance for a specific MITRE ATT&CK technique.

    Returns:
    - MITRE Mitigations (M-series IDs)
    - CIS Controls v8 safeguards
    - Detection rules (Sigma-style)
    - Hardening guidance

    Example request:
    ```
    GET /api/v1/remediation/techniques/T1059.001
    ```

    Example response:
    ```json
    {
        "technique_id": "T1059.001",
        "mitigations": [
            {
                "mitigation_id": "M1042",
                "name": "Disable or Remove Feature or Program",
                "description": "Consider disabling PowerShell where not required..."
            }
        ],
        "cis_controls": [
            {
                "control_id": "2.3",
                "control": "Address Unauthorized Software",
                "safeguard": "Use application allowlisting to control PowerShell"
            }
        ],
        "detection_rules": [
            {
                "rule_name": "PowerShell Execution Policy Bypass",
                "description": "Detects PowerShell with -ExecutionPolicy Bypass",
                "log_source": "Windows Security Event Log (4688)",
                "detection": "CommandLine contains '-ExecutionPolicy Bypass'"
            }
        ],
        "hardening_guidance": "1. Enable Constrained Language Mode\\n2. Set execution policy..."
    }
    ```
    """
    logger.info(f"User {user.username} requesting remediation for technique: {technique_id}")

    # Get remediation from service
    remediation = await RemediationService.get_technique_remediation(technique_id)

    if not remediation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No remediation guidance available for technique {technique_id}"
        )

    # Convert to Pydantic models
    return TechniqueRemediation(
        technique_id=remediation["technique_id"],
        mitigations=[Mitigation(**m) for m in remediation["mitigations"]],
        cis_controls=[CISControl(**c) for c in remediation["cis_controls"]],
        detection_rules=[DetectionRule(**r) for r in remediation["detection_rules"]],
        hardening_guidance=remediation["hardening_guidance"]
    )


@router.get("/layers/{layer_id}", response_model=LayerRemediationResponse)
async def get_layer_remediation(
    layer_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """
    Get comprehensive remediation guidance for all techniques in a layer.

    Techniques are returned prioritized by color:
    1. Red (critical overlap) - highest priority
    2. Yellow (intel only) - medium priority
    3. Blue (vulnerability only) - lower priority

    Within each color, techniques are sorted by confidence descending.

    Example request:
    ```
    GET /api/v1/remediation/layers/550e8400-e29b-41d4-a716-446655440000
    ```

    Example response:
    ```json
    {
        "layer_id": "550e8400-e29b-41d4-a716-446655440000",
        "techniques": [
            {
                "technique_id": "T1059.001",
                "color": "#EF4444",
                "confidence": 0.95,
                "from_intel": true,
                "from_vuln": true,
                "remediation": { ... }
            }
        ],
        "statistics": {
            "total_techniques": 87,
            "red_techniques": 12,
            "yellow_techniques": 45,
            "blue_techniques": 30,
            "remediation_coverage": 85.5
        }
    }
    ```
    """
    logger.info(f"User {user.username} requesting remediation for layer: {layer_id}")

    # Verify layer exists
    layer_result = await db.execute(
        text("SELECT id FROM layers WHERE id = :id"),
        {"id": layer_id}
    )

    if not layer_result.fetchone():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Layer {layer_id} not found"
        )

    try:
        # Get layer remediation from service
        result = await RemediationService.get_layer_remediation(layer_id, db)

        # Convert to Pydantic models
        techniques = []
        for tech in result["techniques"]:
            remediation = None
            if tech["remediation"]:
                remediation = TechniqueRemediation(
                    technique_id=tech["remediation"]["technique_id"],
                    mitigations=[Mitigation(**m) for m in tech["remediation"]["mitigations"]],
                    cis_controls=[CISControl(**c) for c in tech["remediation"]["cis_controls"]],
                    detection_rules=[DetectionRule(**r) for r in tech["remediation"]["detection_rules"]],
                    hardening_guidance=tech["remediation"]["hardening_guidance"]
                )

            techniques.append(LayerTechniqueRemediation(
                technique_id=tech["technique_id"],
                color=tech["color"],
                confidence=tech["confidence"],
                from_intel=tech["from_intel"],
                from_vuln=tech["from_vuln"],
                remediation=remediation
            ))

        return LayerRemediationResponse(
            layer_id=layer_id,
            techniques=techniques,
            statistics=LayerRemediationStatistics(**result["statistics"])
        )

    except Exception as e:
        logger.error(f"Failed to get layer remediation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve remediation: {str(e)}"
        )


@router.get("/coverage", response_model=dict)
async def get_remediation_coverage(
    user: User = Depends(get_current_user)
):
    """
    Get statistics on remediation database coverage.

    Returns:
    - Total techniques with remediation data
    - Breakdown by remediation type (mitigations, CIS controls, detection rules)

    Example response:
    ```json
    {
        "total_techniques": 15,
        "techniques_with_mitigations": 15,
        "techniques_with_cis_controls": 12,
        "techniques_with_detection_rules": 10,
        "coverage_techniques": [
            "T1059.001",
            "T1059.003",
            ...
        ]
    }
    ```
    """
    logger.info(f"User {user.username} requesting remediation coverage statistics")

    # Get all technique IDs from remediation service
    all_mitigations = set(RemediationService.TECHNIQUE_MITIGATIONS.keys())
    all_cis = set(RemediationService.TECHNIQUE_CIS_CONTROLS.keys())
    all_detection = set(RemediationService.TECHNIQUE_DETECTION_RULES.keys())

    # Union of all techniques with any remediation data
    all_techniques = all_mitigations | all_cis | all_detection

    return {
        "total_techniques": len(all_techniques),
        "techniques_with_mitigations": len(all_mitigations),
        "techniques_with_cis_controls": len(all_cis),
        "techniques_with_detection_rules": len(all_detection),
        "coverage_techniques": sorted(list(all_techniques))
    }
