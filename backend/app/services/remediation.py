"""
Remediation Engine (Phase 7)

Maps MITRE ATT&CK techniques to actionable remediation guidance:
- MITRE Mitigations (M-series IDs)
- CIS Controls (v8)
- Detection Rules (Sigma/YARA patterns)
- Hardening guidance

This is the "so what now?" layer - turning threat intelligence into action.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class RemediationService:
    """
    Service for mapping techniques to remediation guidance.

    Provides actionable mitigations, security controls, and detection rules
    for MITRE ATT&CK techniques identified in correlation layers.
    """

    # MITRE Mitigation mappings (curated from official ATT&CK data)
    # Format: technique_id -> list of (mitigation_id, mitigation_name, description)
    TECHNIQUE_MITIGATIONS: Dict[str, List[Dict[str, str]]] = {
        "T1059.001": [  # PowerShell
            {
                "mitigation_id": "M1042",
                "name": "Disable or Remove Feature or Program",
                "description": "Consider disabling or restricting PowerShell where not required. Use PowerShell Constrained Language Mode to restrict capabilities."
            },
            {
                "mitigation_id": "M1049",
                "name": "Antivirus/Antimalware",
                "description": "Anti-virus can be used to automatically quarantine suspicious files with PowerShell scripts."
            },
            {
                "mitigation_id": "M1045",
                "name": "Code Signing",
                "description": "Set PowerShell execution policy to require signed scripts. Use AppLocker or Software Restriction Policies."
            },
            {
                "mitigation_id": "M1026",
                "name": "Privileged Account Management",
                "description": "Remove PowerShell from systems where not required. Restrict PowerShell execution to privileged accounts only."
            }
        ],
        "T1059.003": [  # Windows Command Shell
            {
                "mitigation_id": "M1038",
                "name": "Execution Prevention",
                "description": "Use application control to prevent execution of cmd.exe if not required. Block command-line interpreters through AppLocker."
            },
            {
                "mitigation_id": "M1026",
                "name": "Privileged Account Management",
                "description": "Restrict cmd.exe execution to privileged accounts. Remove unnecessary access for standard users."
            }
        ],
        "T1566.001": [  # Spearphishing Attachment
            {
                "mitigation_id": "M1049",
                "name": "Antivirus/Antimalware",
                "description": "Anti-virus can automatically quarantine malicious email attachments before delivery to users."
            },
            {
                "mitigation_id": "M1031",
                "name": "Network Intrusion Prevention",
                "description": "Network intrusion prevention systems and email gateways can be used to detect and block malicious attachments."
            },
            {
                "mitigation_id": "M1021",
                "name": "Restrict Web-Based Content",
                "description": "Block email attachments that can execute macros (e.g., .doc, .xls, .xlsm). Only allow safe file types."
            },
            {
                "mitigation_id": "M1017",
                "name": "User Training",
                "description": "Train users to identify phishing emails and avoid opening suspicious attachments. Conduct regular phishing simulations."
            }
        ],
        "T1566.002": [  # Spearphishing Link
            {
                "mitigation_id": "M1031",
                "name": "Network Intrusion Prevention",
                "description": "Network intrusion prevention systems can be used to block URLs associated with known malicious domains."
            },
            {
                "mitigation_id": "M1021",
                "name": "Restrict Web-Based Content",
                "description": "Block access to known malicious web domains through DNS filtering and web proxies."
            },
            {
                "mitigation_id": "M1017",
                "name": "User Training",
                "description": "Train users to identify phishing links. Teach verification techniques (hover before clicking, check sender)."
            }
        ],
        "T1071.001": [  # Web Protocols for C2
            {
                "mitigation_id": "M1031",
                "name": "Network Intrusion Prevention",
                "description": "Network intrusion detection and prevention systems can identify C2 traffic patterns. Use SSL/TLS inspection."
            },
            {
                "mitigation_id": "M1037",
                "name": "Filter Network Traffic",
                "description": "Filter outbound web traffic through web proxies. Block access to known malicious domains and IP addresses."
            }
        ],
        "T1486": [  # Data Encrypted for Impact (Ransomware)
            {
                "mitigation_id": "M1053",
                "name": "Data Backup",
                "description": "Maintain offline, encrypted backups of critical data. Test backup restoration regularly."
            },
            {
                "mitigation_id": "M1040",
                "name": "Behavior Prevention on Endpoint",
                "description": "Use endpoint protection that can detect and block ransomware behavior (rapid file encryption)."
            },
            {
                "mitigation_id": "M1022",
                "name": "Restrict File and Directory Permissions",
                "description": "Restrict write access to critical directories. Use least privilege principles for file access."
            }
        ],
        "T1055": [  # Process Injection
            {
                "mitigation_id": "M1040",
                "name": "Behavior Prevention on Endpoint",
                "description": "Use endpoint protection that can detect process injection techniques (memory writes, thread manipulation)."
            },
            {
                "mitigation_id": "M1026",
                "name": "Privileged Account Management",
                "description": "Restrict debug privileges to administrators only. Minimize accounts with SeDebugPrivilege."
            }
        ],
        "T1027": [  # Obfuscated Files or Information
            {
                "mitigation_id": "M1049",
                "name": "Antivirus/Antimalware",
                "description": "Anti-malware can detect obfuscated code patterns and malicious packers."
            },
            {
                "mitigation_id": "M1040",
                "name": "Behavior Prevention on Endpoint",
                "description": "Use endpoint protection that analyzes behavior rather than just signatures to detect obfuscated malware."
            }
        ],
        "T1082": [  # System Information Discovery
            {
                "mitigation_id": "M1028",
                "name": "Operating System Configuration",
                "description": "Restrict access to system information commands through application control policies."
            }
        ],
        "T1083": [  # File and Directory Discovery
            {
                "mitigation_id": "M1022",
                "name": "Restrict File and Directory Permissions",
                "description": "Use file system permissions to restrict access to sensitive directories."
            }
        ],
        "T1087": [  # Account Discovery
            {
                "mitigation_id": "M1028",
                "name": "Operating System Configuration",
                "description": "Restrict access to account enumeration utilities through application control."
            }
        ],
        "T1005": [  # Data from Local System
            {
                "mitigation_id": "M1022",
                "name": "Restrict File and Directory Permissions",
                "description": "Use file permissions to restrict access to sensitive data files."
            },
            {
                "mitigation_id": "M1057",
                "name": "Data Loss Prevention",
                "description": "Implement DLP solutions to detect and block unauthorized data collection."
            }
        ],
        "T1041": [  # Exfiltration Over C2 Channel
            {
                "mitigation_id": "M1031",
                "name": "Network Intrusion Prevention",
                "description": "Network monitoring can detect abnormal data flows and large outbound transfers."
            },
            {
                "mitigation_id": "M1057",
                "name": "Data Loss Prevention",
                "description": "DLP solutions can detect and block data exfiltration attempts."
            }
        ],
        "T1190": [  # Exploit Public-Facing Application
            {
                "mitigation_id": "M1050",
                "name": "Exploit Protection",
                "description": "Use exploit protection features like DEP, ASLR, and CFG. Deploy WAF for web applications."
            },
            {
                "mitigation_id": "M1016",
                "name": "Vulnerability Scanning",
                "description": "Regularly scan public-facing applications for vulnerabilities and misconfigurations."
            },
            {
                "mitigation_id": "M1026",
                "name": "Privileged Account Management",
                "description": "Run public-facing applications with minimal privileges. Use separate service accounts."
            }
        ],
        "T1078": [  # Valid Accounts
            {
                "mitigation_id": "M1027",
                "name": "Password Policies",
                "description": "Enforce strong password policies and multi-factor authentication for all accounts."
            },
            {
                "mitigation_id": "M1026",
                "name": "Privileged Account Management",
                "description": "Implement privileged access management (PAM). Use just-in-time access provisioning."
            },
            {
                "mitigation_id": "M1018",
                "name": "User Account Management",
                "description": "Regularly audit accounts and remove unused or dormant accounts."
            }
        ]
    }

    # CIS Controls v8 mappings
    # Format: technique_id -> list of (control_id, control_name, safeguard)
    TECHNIQUE_CIS_CONTROLS: Dict[str, List[Dict[str, str]]] = {
        "T1059.001": [  # PowerShell
            {"control_id": "2.3", "control": "Address Unauthorized Software", "safeguard": "Use application allowlisting to control PowerShell execution"},
            {"control_id": "2.7", "control": "Allowlist Authorized Scripts", "safeguard": "Maintain allowlist of authorized PowerShell scripts"},
            {"control_id": "8.2", "control": "Collect Audit Logs", "safeguard": "Enable PowerShell script block logging and transcription"},
        ],
        "T1059.003": [  # Windows Command Shell
            {"control_id": "2.3", "control": "Address Unauthorized Software", "safeguard": "Restrict cmd.exe execution through application control"},
            {"control_id": "8.2", "control": "Collect Audit Logs", "safeguard": "Enable command-line process auditing"},
        ],
        "T1566.001": [  # Spearphishing Attachment
            {"control_id": "7.1", "control": "Establish Secure Configurations", "safeguard": "Configure email gateway to block dangerous attachment types"},
            {"control_id": "9.2", "control": "Use DNS Filtering Services", "safeguard": "Block connections to known malicious domains"},
            {"control_id": "10.1", "control": "Deploy Anti-Malware Software", "safeguard": "Scan all email attachments for malware"},
            {"control_id": "14.2", "control": "Train Workforce Members", "safeguard": "Conduct phishing awareness training"},
        ],
        "T1566.002": [  # Spearphishing Link
            {"control_id": "9.2", "control": "Use DNS Filtering Services", "safeguard": "Block DNS queries to malicious domains"},
            {"control_id": "9.3", "control": "Deploy URL Filtering", "safeguard": "Block access to known phishing URLs"},
            {"control_id": "14.2", "control": "Train Workforce Members", "safeguard": "Train users to identify and report phishing"},
        ],
        "T1071.001": [  # Web Protocols for C2
            {"control_id": "13.3", "control": "Deploy Network-Based IDS", "safeguard": "Monitor network traffic for C2 communication patterns"},
            {"control_id": "13.10", "control": "Perform Application Layer Filtering", "safeguard": "Inspect HTTPS traffic through SSL/TLS decryption"},
        ],
        "T1486": [  # Ransomware
            {"control_id": "11.1", "control": "Establish Data Recovery Practices", "safeguard": "Maintain offline, encrypted backups"},
            {"control_id": "11.2", "control": "Perform Automated Backups", "safeguard": "Automate regular backups of critical systems"},
            {"control_id": "10.5", "control": "Malware Detection", "safeguard": "Deploy anti-ransomware endpoint protection"},
        ],
        "T1055": [  # Process Injection
            {"control_id": "10.5", "control": "Malware Detection", "safeguard": "Deploy EDR that detects process injection techniques"},
            {"control_id": "8.5", "control": "Collect Detailed Audit Logs", "safeguard": "Log process creation and memory manipulation events"},
        ],
        "T1027": [  # Obfuscated Files
            {"control_id": "10.1", "control": "Deploy Anti-Malware Software", "safeguard": "Use anti-malware with heuristic analysis"},
            {"control_id": "8.2", "control": "Collect Audit Logs", "safeguard": "Log file creation and modification events"},
        ],
        "T1190": [  # Exploit Public-Facing Application
            {"control_id": "7.1", "control": "Establish Secure Configurations", "safeguard": "Harden public-facing applications per CIS Benchmarks"},
            {"control_id": "7.2", "control": "Maintain Secure Images", "safeguard": "Use hardened container images for applications"},
            {"control_id": "7.3", "control": "Securely Configure Network Infrastructure", "safeguard": "Deploy WAF in front of web applications"},
        ],
        "T1078": [  # Valid Accounts
            {"control_id": "5.2", "control": "Use Unique Passwords", "safeguard": "Enforce unique passwords across all accounts"},
            {"control_id": "5.3", "control": "Disable Dormant Accounts", "safeguard": "Automatically disable inactive accounts after 45 days"},
            {"control_id": "6.3", "control": "Require MFA", "safeguard": "Enforce multi-factor authentication for all accounts"},
        ]
    }

    # Detection rules (Sigma-style patterns)
    # Format: technique_id -> list of detection rules with description
    TECHNIQUE_DETECTION_RULES: Dict[str, List[Dict[str, str]]] = {
        "T1059.001": [  # PowerShell
            {
                "rule_name": "PowerShell Execution Policy Bypass",
                "description": "Detects PowerShell executed with -ExecutionPolicy Bypass flag",
                "log_source": "Windows Security Event Log (4688)",
                "detection": "CommandLine contains '-ExecutionPolicy Bypass' OR '-exec bypass' OR '-ep bypass'"
            },
            {
                "rule_name": "PowerShell Download Cradle",
                "description": "Detects PowerShell downloading files from web",
                "log_source": "PowerShell Script Block Logging (4104)",
                "detection": "ScriptBlockText contains 'Invoke-WebRequest' OR 'IWR' OR 'wget' OR 'curl' OR 'DownloadString'"
            },
            {
                "rule_name": "Encoded PowerShell Command",
                "description": "Detects Base64-encoded PowerShell commands",
                "log_source": "Windows Security Event Log (4688)",
                "detection": "CommandLine contains '-EncodedCommand' OR '-enc' OR '-e'"
            }
        ],
        "T1059.003": [  # Windows Command Shell
            {
                "rule_name": "CMD.exe Suspicious Execution",
                "description": "Detects cmd.exe executed with suspicious flags",
                "log_source": "Windows Security Event Log (4688)",
                "detection": "Image ends with 'cmd.exe' AND (CommandLine contains '/c' OR '/k' OR '/r')"
            }
        ],
        "T1566.001": [  # Spearphishing Attachment
            {
                "rule_name": "Office Macro Execution",
                "description": "Detects Office documents executing macros",
                "log_source": "Windows Security Event Log (4688)",
                "detection": "ParentImage contains 'WINWORD.EXE' OR 'EXCEL.EXE' AND Image contains 'cmd.exe' OR 'powershell.exe'"
            },
            {
                "rule_name": "Suspicious Email Attachment Opened",
                "description": "Detects execution of files from temporary email locations",
                "log_source": "Windows Security Event Log (4688)",
                "detection": "CommandLine contains '\\AppData\\Local\\Microsoft\\Windows\\INetCache\\'"
            }
        ],
        "T1071.001": [  # Web Protocols for C2
            {
                "rule_name": "Suspicious Outbound HTTPS Connection",
                "description": "Detects uncommon processes making HTTPS connections",
                "log_source": "Network Connection Logs / EDR",
                "detection": "Process NOT IN (browser list) AND DestinationPort = 443 AND ConnectionDuration > 300s"
            },
            {
                "rule_name": "Beaconing Activity Detected",
                "description": "Detects regular periodic outbound connections (C2 beaconing)",
                "log_source": "Network Flow Logs",
                "detection": "Regular connection intervals (e.g., every 60s ±5s) to same destination"
            }
        ],
        "T1486": [  # Ransomware
            {
                "rule_name": "Rapid File Encryption Activity",
                "description": "Detects mass file modifications (ransomware behavior)",
                "log_source": "File System Auditing / EDR",
                "detection": "File modifications > 100 files in < 60 seconds with file renames"
            },
            {
                "rule_name": "Ransomware Note Creation",
                "description": "Detects creation of ransom notes",
                "log_source": "File System Auditing",
                "detection": "File created with name containing 'DECRYPT' OR 'README' OR 'RANSOM' with .txt extension"
            }
        ],
        "T1055": [  # Process Injection
            {
                "rule_name": "Process Injection via CreateRemoteThread",
                "description": "Detects process injection using CreateRemoteThread API",
                "log_source": "EDR / Sysmon Event 8",
                "detection": "CreateRemoteThread detected with target process different from source"
            }
        ],
        "T1190": [  # Exploit Public-Facing Application
            {
                "rule_name": "Web Application Exploit Attempt",
                "description": "Detects common web exploit patterns in HTTP requests",
                "log_source": "WAF / Web Server Logs",
                "detection": "HTTP request contains SQL injection patterns OR command injection OR path traversal"
            }
        ],
        "T1078": [  # Valid Accounts
            {
                "rule_name": "Impossible Travel Login",
                "description": "Detects logins from geographically impossible locations",
                "log_source": "Authentication Logs",
                "detection": "User login from IP1 (Location A) and IP2 (Location B) within impossible timeframe"
            },
            {
                "rule_name": "After-Hours Login from Privileged Account",
                "description": "Detects privileged account logins outside business hours",
                "log_source": "Windows Security Event Log (4624)",
                "detection": "Logon Type = 3 OR 10 AND Account in privileged group AND Time outside 08:00-18:00"
            }
        ]
    }

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

        # Check if we have remediation data for this technique
        has_mitigations = technique_id in RemediationService.TECHNIQUE_MITIGATIONS
        has_cis_controls = technique_id in RemediationService.TECHNIQUE_CIS_CONTROLS
        has_detection_rules = technique_id in RemediationService.TECHNIQUE_DETECTION_RULES

        if not (has_mitigations or has_cis_controls or has_detection_rules):
            logger.warning(f"No remediation data found for technique: {technique_id}")
            return None

        # Build response
        response = {
            "technique_id": technique_id,
            "mitigations": RemediationService.TECHNIQUE_MITIGATIONS.get(technique_id, []),
            "cis_controls": RemediationService.TECHNIQUE_CIS_CONTROLS.get(technique_id, []),
            "detection_rules": RemediationService.TECHNIQUE_DETECTION_RULES.get(technique_id, []),
            "hardening_guidance": RemediationService._generate_hardening_guidance(technique_id)
        }

        logger.info(f"Retrieved {len(response['mitigations'])} mitigations, "
                   f"{len(response['cis_controls'])} CIS controls, "
                   f"{len(response['detection_rules'])} detection rules for {technique_id}")

        return response

    @staticmethod
    def _generate_hardening_guidance(technique_id: str) -> str:
        """
        Generate consolidated hardening guidance for a technique.

        This summarizes the key actions to take based on mitigations and controls.
        """
        # Hardening guidance by technique category
        guidance_map = {
            "T1059.001": "**PowerShell Hardening:**\n"
                        "1. Enable PowerShell Constrained Language Mode\n"
                        "2. Set execution policy to AllSigned or RemoteSigned\n"
                        "3. Enable PowerShell Script Block Logging (Event ID 4104)\n"
                        "4. Enable PowerShell Transcription logging\n"
                        "5. Use AppLocker to restrict PowerShell execution to authorized scripts\n"
                        "6. Disable PowerShell v2 (legacy version bypass)\n"
                        "7. Monitor for suspicious PowerShell commands (encodedCommand, downloadString, etc.)",

            "T1059.003": "**Command Shell Hardening:**\n"
                        "1. Enable command-line process auditing (Event ID 4688)\n"
                        "2. Use AppLocker to restrict cmd.exe execution\n"
                        "3. Monitor for suspicious command-line patterns\n"
                        "4. Restrict cmd.exe access to privileged users only",

            "T1566.001": "**Email Security Hardening:**\n"
                        "1. Block dangerous attachment types (.exe, .scr, .bat, .js, .vbs, macro-enabled Office docs)\n"
                        "2. Enable Office macro execution warnings\n"
                        "3. Disable macros in Office documents from internet sources\n"
                        "4. Implement DMARC, SPF, and DKIM for email authentication\n"
                        "5. Deploy email gateway with attachment sandboxing\n"
                        "6. Conduct regular phishing simulation exercises",

            "T1566.002": "**Phishing Link Protection:**\n"
                        "1. Deploy DNS filtering to block malicious domains\n"
                        "2. Implement web proxy with URL filtering\n"
                        "3. Enable browser security features (SmartScreen, Safe Browsing)\n"
                        "4. Use email security gateway with URL rewriting/sandboxing\n"
                        "5. Train users on link verification techniques",

            "T1071.001": "**C2 Communication Prevention:**\n"
                        "1. Deploy network IDS/IPS to detect C2 patterns\n"
                        "2. Implement SSL/TLS inspection for HTTPS traffic\n"
                        "3. Block access to known malicious domains/IPs\n"
                        "4. Monitor for beaconing behavior (regular periodic connections)\n"
                        "5. Restrict outbound connections to only necessary destinations",

            "T1486": "**Ransomware Protection:**\n"
                        "1. Implement 3-2-1 backup strategy (3 copies, 2 different media, 1 offsite)\n"
                        "2. Keep offline, encrypted backups that are air-gapped\n"
                        "3. Test backup restoration procedures quarterly\n"
                        "4. Enable Controlled Folder Access (Windows Defender)\n"
                        "5. Deploy anti-ransomware endpoint protection\n"
                        "6. Use file integrity monitoring to detect rapid encryption\n"
                        "7. Restrict file system permissions (principle of least privilege)",

            "T1055": "**Process Injection Prevention:**\n"
                        "1. Deploy EDR solution that detects injection techniques\n"
                        "2. Restrict SeDebugPrivilege to administrators only\n"
                        "3. Enable Microsoft Defender Attack Surface Reduction rules\n"
                        "4. Monitor for CreateRemoteThread, WriteProcessMemory APIs\n"
                        "5. Use exploit protection features (CFG, DEP, ASLR)",

            "T1027": "**Obfuscation Detection:**\n"
                        "1. Deploy anti-malware with heuristic and behavior-based detection\n"
                        "2. Monitor for file modifications and suspicious encodings\n"
                        "3. Analyze scripts before execution (detonation chambers)\n"
                        "4. Use YARA rules to detect obfuscation patterns",

            "T1190": "**Application Security Hardening:**\n"
                        "1. Keep all public-facing applications patched and updated\n"
                        "2. Deploy Web Application Firewall (WAF) with OWASP rulesets\n"
                        "3. Conduct regular vulnerability scans and penetration tests\n"
                        "4. Implement input validation and output encoding\n"
                        "5. Use secure coding practices (OWASP Top 10)\n"
                        "6. Run applications with least privilege\n"
                        "7. Enable exploit protection (DEP, ASLR, CFG)",

            "T1078": "**Account Security Hardening:**\n"
                        "1. Enforce multi-factor authentication (MFA) for all accounts\n"
                        "2. Implement strong password policy (16+ characters, complexity)\n"
                        "3. Use Privileged Access Management (PAM) for admin accounts\n"
                        "4. Enable account lockout after failed login attempts\n"
                        "5. Monitor for impossible travel and after-hours access\n"
                        "6. Disable inactive accounts after 45 days\n"
                        "7. Audit privileged account usage regularly"
        }

        return guidance_map.get(technique_id,
                               "**General Hardening Guidance:**\n"
                               "1. Apply security patches and updates promptly\n"
                               "2. Implement defense-in-depth security controls\n"
                               "3. Enable comprehensive logging and monitoring\n"
                               "4. Conduct regular security assessments\n"
                               "5. Follow vendor security best practices")

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
