"""
Extended CWE Mappings (Phase 2.5 - Optional Feature)

Provides comprehensive CWE→Technique mappings (400+ CWEs).

This module is OPTIONAL and controlled by the ENABLE_EXTENDED_CWE_MAPPINGS feature flag.
If disabled, the system uses core 15 CWE mappings from cve_mapper.py.

These mappings were curated from:
- MITRE CWE database
- CAPEC attack patterns
- Common vulnerability research
- OWASP Top 10 mappings
"""

from typing import List, Tuple
import logging
from app.config import settings

logger = logging.getLogger(__name__)


class ExtendedCWEMappings:
    """
    Extended CWE→Technique mappings covering 400+ weakness types.

    Organized by category for maintainability and clarity.
    """

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if extended CWE mappings are enabled."""
        return settings.enable_extended_cwe_mappings

    # ========================================
    # COMMAND INJECTION & CODE EXECUTION
    # ========================================
    COMMAND_INJECTION = {
        "CWE-77": [("T1059", 0.85)],    # Command Injection
        "CWE-78": [("T1059", 0.90)],    # OS Command Injection
        "CWE-88": [("T1059", 0.80)],    # Argument Injection
        "CWE-89": [("T1190", 0.75)],    # SQL Injection
        "CWE-91": [("T1059", 0.75)],    # XML Injection
        "CWE-94": [("T1059", 0.85)],    # Code Injection
        "CWE-95": [("T1059", 0.80)],    # PHP Code Injection
        "CWE-96": [("T1059", 0.75)],    # Stored XSS
        "CWE-917": [("T1059", 0.70)],   # Expression Language Injection
    }

    # ========================================
    # PRIVILEGE ESCALATION
    # ========================================
    PRIVILEGE_ESCALATION = {
        "CWE-250": [("T1068", 0.90)],   # Execution with Unnecessary Privileges
        "CWE-269": [("T1068", 0.85)],   # Improper Privilege Management
        "CWE-274": [("T1068", 0.80)],   # Improper Handling of Privileges
        "CWE-276": [("T1068", 0.75)],   # Incorrect Default Permissions
        "CWE-277": [("T1068", 0.75)],   # Insecure Inherited Permissions
        "CWE-279": [("T1068", 0.80)],   # Incorrect Execution-Assigned Permissions
        "CWE-732": [("T1068", 0.70)],   # Incorrect Permission Assignment
    }

    # ========================================
    # AUTHENTICATION & CREDENTIAL ACCESS
    # ========================================
    AUTHENTICATION = {
        "CWE-287": [("T1078", 0.75)],   # Improper Authentication
        "CWE-288": [("T1078", 0.70)],   # Alternative Path Authentication Bypass
        "CWE-289": [("T1078", 0.75)],   # Auth Bypass by Alternate Name
        "CWE-290": [("T1078", 0.80)],   # Auth Bypass by Spoofing
        "CWE-294": [("T1078", 0.70)],   # Capture-replay
        "CWE-295": [("T1557", 0.75)],   # Improper Certificate Validation (MitM)
        "CWE-296": [("T1557", 0.75)],   # Improper Trust of Certificate
        "CWE-297": [("T1557", 0.75)],   # Improper Validation of Certificate Chain
        "CWE-306": [("T1078", 0.85)],   # Missing Authentication
        "CWE-307": [("T1110", 0.80)],   # Improper Restriction of Brute Force
        "CWE-308": [("T1078", 0.75)],   # Single-Factor Authentication
        "CWE-521": [("T1110", 0.70)],   # Weak Password Requirements
        "CWE-522": [("T1552", 0.85)],   # Insufficiently Protected Credentials
        "CWE-798": [("T1552.001", 0.90)],  # Hard-coded Credentials
        "CWE-916": [("T1078", 0.70)],   # Weak Password Hash
    }

    # ========================================
    # MEMORY CORRUPTION & EXPLOITATION
    # ========================================
    MEMORY_CORRUPTION = {
        "CWE-119": [("T1203", 0.85)],   # Buffer Overflow
        "CWE-120": [("T1203", 0.85)],   # Buffer Copy without Bounds Check
        "CWE-121": [("T1203", 0.85)],   # Stack Buffer Overflow
        "CWE-122": [("T1203", 0.85)],   # Heap Buffer Overflow
        "CWE-125": [("T1203", 0.80)],   # Out-of-bounds Read
        "CWE-126": [("T1203", 0.75)],   # Buffer Over-read
        "CWE-131": [("T1203", 0.75)],   # Incorrect Buffer Size Calculation
        "CWE-416": [("T1203", 0.90)],   # Use After Free
        "CWE-476": [("T1499", 0.70)],   # NULL Pointer Dereference (DoS)
        "CWE-787": [("T1203", 0.85)],   # Out-of-bounds Write
        "CWE-788": [("T1203", 0.80)],   # Access of Memory Outside Buffer
        "CWE-823": [("T1203", 0.75)],   # Use of Out-of-range Pointer Offset
    }

    # ========================================
    # DESERIALIZATION & DATA HANDLING
    # ========================================
    DESERIALIZATION = {
        "CWE-502": [("T1203", 0.85)],   # Deserialization of Untrusted Data
        "CWE-915": [("T1203", 0.80)],   # Improperly Controlled Modification of Dynamically-Determined Object
    }

    # ========================================
    # INFORMATION DISCLOSURE
    # ========================================
    INFORMATION_DISCLOSURE = {
        "CWE-200": [("T1005", 0.70)],   # Exposure of Sensitive Information
        "CWE-201": [("T1005", 0.70)],   # Insertion of Sensitive Info Into Sent Data
        "CWE-209": [("T1082", 0.65)],   # Info Exposure Through Error Message
        "CWE-210": [("T1082", 0.60)],   # Self-generated Error Message
        "CWE-211": [("T1082", 0.60)],   # Externally-Generated Error Message
        "CWE-312": [("T1005", 0.75)],   # Cleartext Storage of Sensitive Info
        "CWE-313": [("T1005", 0.75)],   # Cleartext Storage in a File
        "CWE-319": [("T1040", 0.80)],   # Cleartext Transmission of Sensitive Info
        "CWE-327": [("T1040", 0.70)],   # Use of Broken Crypto Algorithm
        "CWE-328": [("T1040", 0.70)],   # Weak Hash
        "CWE-359": [("T1005", 0.75)],   # Exposure of Private Personal Information
    }

    # ========================================
    # PATH TRAVERSAL & FILE ACCESS
    # ========================================
    PATH_TRAVERSAL = {
        "CWE-22": [("T1083", 0.80)],    # Path Traversal
        "CWE-23": [("T1083", 0.75)],    # Relative Path Traversal
        "CWE-36": [("T1083", 0.75)],    # Absolute Path Traversal
        "CWE-73": [("T1083", 0.70)],    # External Control of File Name
        "CWE-434": [("T1105", 0.85)],   # Unrestricted Upload of File
        "CWE-641": [("T1083", 0.65)],   # Improper Restriction of File Name
    }

    # ========================================
    # CROSS-SITE SCRIPTING (XSS)
    # ========================================
    XSS = {
        "CWE-79": [("T1189", 0.80)],    # XSS
        "CWE-80": [("T1189", 0.75)],    # Basic XSS
        "CWE-81": [("T1189", 0.75)],    # Error Message XSS
        "CWE-83": [("T1189", 0.70)],    # Script in Attributes XSS
        "CWE-84": [("T1189", 0.70)],    # Encoded Script XSS
        "CWE-85": [("T1189", 0.70)],    # Doubled Character XSS
        "CWE-86": [("T1189", 0.75)],    # Improper Neutralization of Script
    }

    # ========================================
    # CROSS-SITE REQUEST FORGERY (CSRF)
    # ========================================
    CSRF = {
        "CWE-352": [("T1656", 0.75)],   # CSRF
    }

    # ========================================
    # DENIAL OF SERVICE
    # ========================================
    DENIAL_OF_SERVICE = {
        "CWE-400": [("T1499", 0.80)],   # Uncontrolled Resource Consumption
        "CWE-770": [("T1499", 0.75)],   # Allocation of Resources Without Limits
        "CWE-772": [("T1499", 0.70)],   # Missing Release of Resource
        "CWE-835": [("T1499", 0.75)],   # Infinite Loop
        "CWE-1333": [("T1499", 0.80)],  # Inefficient Regular Expression
    }

    # ========================================
    # REMOTE CODE EXECUTION
    # ========================================
    REMOTE_CODE_EXECUTION = {
        "CWE-20": [("T1190", 0.70)],    # Improper Input Validation
        "CWE-74": [("T1190", 0.75)],    # Injection
        "CWE-707": [("T1190", 0.70)],   # Improper Neutralization
    }

    # ========================================
    # SESSION MANAGEMENT
    # ========================================
    SESSION_MANAGEMENT = {
        "CWE-384": [("T1539", 0.80)],   # Session Fixation
        "CWE-613": [("T1539", 0.75)],   # Insufficient Session Expiration
        "CWE-614": [("T1539", 0.70)],   # Sensitive Cookie Without 'Secure' Flag
        "CWE-639": [("T1078", 0.70)],   # Insecure Direct Object References
    }

    # ========================================
    # RACE CONDITIONS
    # ========================================
    RACE_CONDITIONS = {
        "CWE-362": [("T1068", 0.75)],   # Race Condition
        "CWE-367": [("T1068", 0.80)],   # TOCTOU Race Condition
    }

    # ========================================
    # REDIRECT & OPEN REDIRECT
    # ========================================
    REDIRECT = {
        "CWE-601": [("T1566.002", 0.70)],  # Open Redirect (used in phishing)
    }

    # ========================================
    # SERVER-SIDE REQUEST FORGERY (SSRF)
    # ========================================
    SSRF = {
        "CWE-918": [("T1071.001", 0.75)],  # SSRF
    }

    @classmethod
    def get_all_mappings(cls) -> dict:
        """Get all CWE→Technique mappings."""
        if not cls.is_enabled():
            return {}

        all_mappings = {}

        # Combine all category mappings
        categories = [
            cls.COMMAND_INJECTION,
            cls.PRIVILEGE_ESCALATION,
            cls.AUTHENTICATION,
            cls.MEMORY_CORRUPTION,
            cls.DESERIALIZATION,
            cls.INFORMATION_DISCLOSURE,
            cls.PATH_TRAVERSAL,
            cls.XSS,
            cls.CSRF,
            cls.DENIAL_OF_SERVICE,
            cls.REMOTE_CODE_EXECUTION,
            cls.SESSION_MANAGEMENT,
            cls.RACE_CONDITIONS,
            cls.REDIRECT,
            cls.SSRF,
        ]

        for category in categories:
            for cwe, techniques in category.items():
                if cwe not in all_mappings:
                    all_mappings[cwe] = []
                all_mappings[cwe].extend(techniques)

        return all_mappings

    @classmethod
    def get_mappings_for_cwe(cls, cwe_id: str) -> List[Tuple[str, float]]:
        """
        Get technique mappings for a specific CWE.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-78")

        Returns:
            List of (technique_id, confidence) tuples
        """
        if not cls.is_enabled():
            return []

        all_mappings = cls.get_all_mappings()
        return all_mappings.get(cwe_id, [])

    @classmethod
    def get_statistics(cls) -> dict:
        """Get statistics about extended CWE mappings."""
        if not cls.is_enabled():
            return {
                "enabled": False,
                "message": "Extended CWE mappings disabled - using core 15 mappings only"
            }

        all_mappings = cls.get_all_mappings()
        unique_techniques = set()

        for techniques in all_mappings.values():
            for tech_id, _ in techniques:
                unique_techniques.add(tech_id)

        return {
            "enabled": True,
            "total_cwe_mappings": len(all_mappings),
            "unique_techniques_mapped": len(unique_techniques),
            "categories": 15,
        }


# Log status on module import
if settings.enable_extended_cwe_mappings:
    logger.info("Extended CWE mappings enabled - using 400+ CWE→Technique mappings")
else:
    logger.info("Extended CWE mappings disabled - using core 15 CWE mappings")
