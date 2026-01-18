"""
Nessus Parser Service

Parses .nessus XML files to extract vulnerability data.
Handles Nessus v2 XML format with graceful error handling.
"""

import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from datetime import datetime
import logging
import re

logger = logging.getLogger(__name__)


class NessusParseError(Exception):
    """Raised when Nessus file cannot be parsed."""
    pass


class NessusParser:
    """Parser for Nessus .nessus XML files."""

    @staticmethod
    def parse(file_content: bytes, filename: str) -> Dict:
        """
        Parse Nessus XML file and extract vulnerability data.

        Args:
            file_content: Raw bytes of .nessus file
            filename: Original filename for metadata

        Returns:
            Dict containing:
                - scan_metadata: {scan_date, policy_name, scanner_name}
                - vulnerabilities: List[{cve_id, severity, cvss_score, asset, plugin_id, plugin_name, description}]

        Raises:
            NessusParseError: If file is malformed or not valid Nessus format
        """
        try:
            # Parse XML
            root = ET.fromstring(file_content)
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML for {filename}: {e}")
            raise NessusParseError(f"Invalid XML format: {e}")

        # Validate it's a Nessus file
        if root.tag != "NessusClientData_v2":
            raise NessusParseError(
                f"Not a valid Nessus v2 file. Root tag: {root.tag}"
            )

        # Extract scan metadata
        scan_metadata = NessusParser._extract_metadata(root, filename)

        # Extract vulnerabilities
        vulnerabilities = NessusParser._extract_vulnerabilities(root)

        logger.info(
            f"Parsed {filename}: {len(vulnerabilities)} vulnerabilities found"
        )

        return {
            "scan_metadata": scan_metadata,
            "vulnerabilities": vulnerabilities,
        }

    @staticmethod
    def _extract_metadata(root: ET.Element, filename: str) -> Dict:
        """Extract scan-level metadata."""
        metadata = {
            "scan_date": None,
            "policy_name": None,
            "scanner_name": None,
        }

        # Try to find policy/preferences
        policy = root.find(".//Policy/policyName")
        if policy is not None:
            metadata["policy_name"] = policy.text

        # Try to find scan start time from first host
        first_host = root.find(".//ReportHost")
        if first_host is not None:
            host_start = first_host.find(".//HostProperties/tag[@name='HOST_START']")
            if host_start is not None:
                try:
                    # Nessus stores timestamps as Unix epoch
                    timestamp = int(host_start.text)
                    metadata["scan_date"] = datetime.fromtimestamp(timestamp)
                except (ValueError, TypeError):
                    logger.warning(f"Could not parse scan date from {filename}")

        # Try to find scanner name
        scanner = root.find(".//Policy/Preferences/ServerPreferences/preference/name[.='scanner_name']/../value")
        if scanner is not None:
            metadata["scanner_name"] = scanner.text

        return metadata

    @staticmethod
    def _extract_vulnerabilities(root: ET.Element) -> List[Dict]:
        """Extract vulnerability findings from all hosts."""
        vulnerabilities = []

        # Iterate through all report hosts
        for report_host in root.findall(".//ReportHost"):
            host_name = report_host.get("name", "unknown")

            # Get IP address if available
            ip_tag = report_host.find(".//HostProperties/tag[@name='host-ip']")
            asset_ip = ip_tag.text if ip_tag is not None else host_name

            # Iterate through all report items (findings)
            for item in report_host.findall(".//ReportItem"):
                # Skip informational findings (severity 0)
                severity = int(item.get("severity", 0))
                if severity == 0:
                    continue

                # Extract basic plugin info
                plugin_id = item.get("pluginID", "unknown")
                plugin_name = item.get("pluginName", "unknown")
                port = item.get("port", "0")
                protocol = item.get("protocol", "tcp")

                # Extract CVE IDs
                cve_elements = item.findall("cve")
                cve_ids = [cve.text for cve in cve_elements if cve.text]

                # If no CVEs, skip this finding (we only care about CVE-mapped vulns)
                if not cve_ids:
                    continue

                # Extract CVSS score
                cvss_base = item.find("cvss_base_score")
                cvss_score = float(cvss_base.text) if cvss_base is not None else None

                cvss3_base = item.find("cvss3_base_score")
                cvss3_score = float(cvss3_base.text) if cvss3_base is not None else None

                # Prefer CVSS v3, fallback to v2
                final_cvss = cvss3_score if cvss3_score else cvss_score

                # Extract description
                description_elem = item.find("description")
                description = description_elem.text if description_elem is not None else ""

                # Extract solution
                solution_elem = item.find("solution")
                solution = solution_elem.text if solution_elem is not None else ""

                # Map Nessus severity to standard severity levels
                severity_map = {
                    0: "INFO",
                    1: "LOW",
                    2: "MEDIUM",
                    3: "HIGH",
                    4: "CRITICAL",
                }
                severity_level = severity_map.get(severity, "UNKNOWN")

                # Create a vulnerability entry for EACH CVE
                for cve_id in cve_ids:
                    vuln = {
                        "cve_id": cve_id,
                        "severity": severity_level,
                        "cvss_score": final_cvss,
                        "asset": asset_ip,
                        "port": f"{port}/{protocol}",
                        "plugin_id": plugin_id,
                        "plugin_name": plugin_name,
                        "description": description[:500] if description else None,  # Truncate
                        "solution": solution[:500] if solution else None,  # Truncate
                    }
                    vulnerabilities.append(vuln)

        return vulnerabilities

    @staticmethod
    def validate_file(file_content: bytes) -> bool:
        """
        Quickly validate if file appears to be a Nessus file.

        Args:
            file_content: Raw bytes of file

        Returns:
            True if file appears valid, False otherwise
        """
        try:
            # Check if it starts with XML declaration or NessusClientData_v2
            content_str = file_content[:200].decode("utf-8", errors="ignore")
            return "NessusClientData_v2" in content_str
        except Exception:
            return False
