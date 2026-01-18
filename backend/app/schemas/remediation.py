"""
Phase 7: Remediation schemas

Pydantic models for technique remediation guidance.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class Mitigation(BaseModel):
    """MITRE ATT&CK mitigation."""

    mitigation_id: str = Field(..., description="MITRE mitigation ID (M-series)")
    name: str = Field(..., description="Mitigation name")
    description: str = Field(..., description="Detailed mitigation guidance")


class CISControl(BaseModel):
    """CIS Control v8 safeguard."""

    control_id: str = Field(..., description="CIS Control ID (e.g., '5.3')")
    control: str = Field(..., description="CIS Control name")
    safeguard: str = Field(..., description="Specific safeguard to implement")


class DetectionRule(BaseModel):
    """Detection rule for technique."""

    rule_name: str = Field(..., description="Name of the detection rule")
    description: str = Field(..., description="What the rule detects")
    log_source: str = Field(..., description="Required log source (e.g., Sysmon, EDR)")
    detection: str = Field(..., description="Detection logic or pattern")


class TechniqueRemediation(BaseModel):
    """Complete remediation guidance for a technique."""

    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")
    mitigations: List[Mitigation] = Field(default_factory=list, description="MITRE mitigations")
    cis_controls: List[CISControl] = Field(default_factory=list, description="CIS Controls v8")
    detection_rules: List[DetectionRule] = Field(default_factory=list, description="Detection rules")
    hardening_guidance: str = Field(..., description="Consolidated hardening steps")

    class Config:
        json_schema_extra = {
            "example": {
                "technique_id": "T1059.001",
                "mitigations": [
                    {
                        "mitigation_id": "M1042",
                        "name": "Disable or Remove Feature or Program",
                        "description": "Consider disabling or restricting PowerShell where not required."
                    }
                ],
                "cis_controls": [
                    {
                        "control_id": "2.3",
                        "control": "Address Unauthorized Software",
                        "safeguard": "Use application allowlisting to control PowerShell execution"
                    }
                ],
                "detection_rules": [
                    {
                        "rule_name": "PowerShell Execution Policy Bypass",
                        "description": "Detects PowerShell executed with -ExecutionPolicy Bypass",
                        "log_source": "Windows Security Event Log (4688)",
                        "detection": "CommandLine contains '-ExecutionPolicy Bypass'"
                    }
                ],
                "hardening_guidance": "1. Enable Constrained Language Mode\n2. Set execution policy to AllSigned..."
            }
        }


class LayerTechniqueRemediation(BaseModel):
    """Technique with its remediation in a layer context."""

    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")
    color: str = Field(..., description="Layer color (#EF4444, #F59E0B, #3B82F6)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    from_intel: bool = Field(..., description="Present in threat intel")
    from_vuln: bool = Field(..., description="Present in vulnerabilities")
    remediation: Optional[TechniqueRemediation] = Field(None, description="Remediation guidance if available")


class LayerRemediationStatistics(BaseModel):
    """Statistics for layer remediation coverage."""

    total_techniques: int = Field(..., description="Total techniques in layer")
    red_techniques: int = Field(..., description="Critical overlap techniques")
    yellow_techniques: int = Field(..., description="Intel-only techniques")
    blue_techniques: int = Field(..., description="Vulnerability-only techniques")
    remediation_coverage: float = Field(..., description="Percentage of techniques with remediation data")


class LayerRemediationResponse(BaseModel):
    """Complete remediation guidance for a layer."""

    layer_id: str = Field(..., description="Layer UUID")
    techniques: List[LayerTechniqueRemediation] = Field(..., description="Techniques with remediation")
    statistics: LayerRemediationStatistics = Field(..., description="Remediation statistics")

    class Config:
        json_schema_extra = {
            "example": {
                "layer_id": "550e8400-e29b-41d4-a716-446655440000",
                "techniques": [
                    {
                        "technique_id": "T1059.001",
                        "color": "#EF4444",
                        "confidence": 0.95,
                        "from_intel": True,
                        "from_vuln": True,
                        "remediation": {
                            "technique_id": "T1059.001",
                            "mitigations": [],
                            "cis_controls": [],
                            "detection_rules": [],
                            "hardening_guidance": "..."
                        }
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
        }
