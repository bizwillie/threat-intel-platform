"""
Regex-Based TTP Extraction Engine

Deterministic, high-confidence TTP detection using regex patterns.
No LLM required - perfect for air-gapped environments.

Phase 3: Regex-only extraction
Phase 4 (deferred): Hybrid regex + LLM approach
"""

import re
import logging
from typing import List, Dict, Set, Tuple

logger = logging.getLogger(__name__)


class RegexExtractor:
    """
    Regex-based ATT&CK technique extraction.

    Provides high-confidence, deterministic TTP detection from threat intelligence text.
    """

    # Technique patterns organized by ATT&CK tactic
    # Format: technique_id -> (confidence, [regex_patterns])

    PATTERNS = {
        # === INITIAL ACCESS ===
        "T1566": (0.85, [
            r"\b(?:spear[- ]?phish(?:ing)?|phishing|malicious attachment|weaponized document|malicious email)\b",
            r"\b(?:phishing campaign|email-based attack|targeted email)\b",
        ]),
        "T1566.001": (0.90, [
            r"\b(?:spear[- ]?phishing attachment|malicious (?:PDF|DOC|DOCX|XLS|XLSX|RTF))\b",
            r"\b(?:weaponized (?:PDF|Office document|macro))\b",
        ]),
        "T1566.002": (0.90, [
            r"\b(?:spear[- ]?phishing link|malicious link|malicious URL)\b",
        ]),
        "T1190": (0.85, [
            r"\b(?:exploit(?:ed)? public[- ]facing application|web application exploit)\b",
            r"\b(?:CVE-\d{4}-\d{4,})\b.*\b(?:exploit|vulnerability|RCE)\b",
        ]),
        "T1133": (0.85, [
            r"\b(?:external remote services|VPN compromise|RDP compromise)\b",
        ]),

        # === EXECUTION ===
        "T1059": (0.80, [
            r"\b(?:command[- ]line|command[- ]and[- ]control|scripting)\b",
        ]),
        "T1059.001": (0.90, [
            r"\b(?:PowerShell|powershell\.exe|PS1|Invoke-|IEX)\b",
            r"\b(?:encoded PowerShell|obfuscated PowerShell)\b",
        ]),
        "T1059.003": (0.90, [
            r"\b(?:cmd\.exe|command prompt|batch file|\.bat|\.cmd)\b",
        ]),
        "T1059.004": (0.90, [
            r"\b(?:bash|sh|/bin/(?:bash|sh)|shell script)\b",
        ]),
        "T1059.005": (0.85, [
            r"\b(?:Visual Basic|VBScript|\.vbs|WScript)\b",
        ]),
        "T1059.006": (0.85, [
            r"\b(?:Python|python\.exe|\.py)\b.*\b(?:malicious|backdoor|payload)\b",
        ]),
        "T1203": (0.85, [
            r"\b(?:exploitation for client execution|exploit kit|browser exploit)\b",
        ]),
        "T1204": (0.80, [
            r"\b(?:user execution|victim opened|user clicked|user ran)\b",
        ]),
        "T1204.002": (0.85, [
            r"\b(?:user executed|victim executed|double-clicked malicious)\b",
        ]),

        # === PERSISTENCE ===
        "T1053": (0.85, [
            r"\b(?:scheduled task|cron job|at command|schtasks)\b",
        ]),
        "T1053.005": (0.90, [
            r"\b(?:scheduled task|schtasks\.exe|Task Scheduler)\b",
        ]),
        "T1543": (0.85, [
            r"\b(?:create(?:d)? service|Windows service|sc\.exe create)\b",
        ]),
        "T1547": (0.85, [
            r"\b(?:boot(?:ed)?|startup|auto[- ]?start|run key|registry persistence)\b",
        ]),
        "T1547.001": (0.90, [
            r"\b(?:registry run key|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)\b",
        ]),
        "T1078": (0.80, [
            r"\b(?:valid account|compromised credential|stolen credential)\b",
        ]),
        "T1136": (0.85, [
            r"\b(?:create(?:d)? account|new user account|add(?:ed)? user)\b",
        ]),

        # === PRIVILEGE ESCALATION ===
        "T1068": (0.90, [
            r"\b(?:exploit(?:ed)? (?:for )?privilege escalation|elevation of privilege|EoP|local privilege)\b",
            r"\b(?:CVE-\d{4}-\d{4,})\b.*\b(?:privilege|escalation|LPE)\b",
        ]),
        "T1134": (0.85, [
            r"\b(?:access token manipulation|token impersonation|stolen token)\b",
        ]),
        "T1548": (0.80, [
            r"\b(?:abuse elevation control|UAC bypass|sudo)\b",
        ]),

        # === DEFENSE EVASION ===
        "T1027": (0.85, [
            r"\b(?:obfuscat(?:ed|ion)|encoded payload|XOR encoded|base64 encoded)\b",
        ]),
        "T1070": (0.85, [
            r"\b(?:indicator removal|clear(?:ed)? logs|deleted logs|event log cleared)\b",
        ]),
        "T1070.004": (0.90, [
            r"\b(?:file deletion|deleted files|removed artifacts)\b",
        ]),
        "T1140": (0.85, [
            r"\b(?:deobfuscat(?:ed|ion)|decode(?:d)?|decrypt(?:ed)?)\b",
        ]),
        "T1562": (0.85, [
            r"\b(?:impair(?:ed)? defenses|disable(?:d)? (?:antivirus|AV|security software|firewall))\b",
        ]),
        "T1562.001": (0.90, [
            r"\b(?:disable(?:d)? (?:antivirus|anti-virus|AV|Windows Defender|security tools))\b",
        ]),
        "T1055": (0.85, [
            r"\b(?:process injection|injected into|DLL injection|code injection)\b",
        ]),
        "T1036": (0.85, [
            r"\b(?:masquerad(?:e|ing)|disguised as|renamed to|spoofed)\b",
        ]),

        # === CREDENTIAL ACCESS ===
        "T1003": (0.85, [
            r"\b(?:credential dump(?:ing)?|LSASS|SAM database|mimikatz)\b",
        ]),
        "T1003.001": (0.90, [
            r"\b(?:LSASS|lsass\.exe|dump(?:ed)? LSASS memory)\b",
        ]),
        "T1003.002": (0.90, [
            r"\b(?:SAM database|Security Account Manager)\b",
        ]),
        "T1003.003": (0.90, [
            r"\b(?:NTDS\.dit|Active Directory database)\b",
        ]),
        "T1110": (0.85, [
            r"\b(?:brute[- ]?force|password spray(?:ing)?|credential stuffing)\b",
        ]),
        "T1555": (0.85, [
            r"\b(?:credential(?:s)? from password store|browser credential|saved password)\b",
        ]),
        "T1056": (0.85, [
            r"\b(?:input capture|keylogg(?:er|ing)|keystroke)\b",
        ]),
        "T1056.001": (0.90, [
            r"\b(?:keylogg(?:er|ing)|keystroke logging)\b",
        ]),

        # === DISCOVERY ===
        "T1082": (0.90, [
            r"\b(?:system information discovery|systeminfo|hostname|whoami|uname)\b",
        ]),
        "T1083": (0.85, [
            r"\b(?:file and directory discovery|dir|ls|find)\b",
        ]),
        "T1087": (0.85, [
            r"\b(?:account discovery|net user|net group|enumerate(?:d)? users)\b",
        ]),
        "T1069": (0.85, [
            r"\b(?:permission group discovery|net localgroup|group membership)\b",
        ]),
        "T1018": (0.85, [
            r"\b(?:remote system discovery|network scan|ping sweep)\b",
        ]),
        "T1046": (0.90, [
            r"\b(?:network service scan(?:ning)?|port scan|nmap|masscan)\b",
        ]),
        "T1057": (0.85, [
            r"\b(?:process discovery|tasklist|ps|get-process)\b",
        ]),
        "T1049": (0.85, [
            r"\b(?:system network connections|netstat|network connection)\b",
        ]),

        # === LATERAL MOVEMENT ===
        "T1021": (0.80, [
            r"\b(?:remote services|lateral movement)\b",
        ]),
        "T1021.001": (0.90, [
            r"\b(?:RDP|Remote Desktop|mstsc|terminal services)\b",
        ]),
        "T1021.002": (0.90, [
            r"\b(?:SMB|Windows Admin Shares|PsExec|ADMIN\$|C\$)\b",
        ]),
        "T1021.006": (0.90, [
            r"\b(?:Windows Remote Management|WinRM|PowerShell Remoting)\b",
        ]),
        "T1047": (0.85, [
            r"\b(?:WMI|Windows Management Instrumentation|wmic)\b",
        ]),
        "T1550": (0.85, [
            r"\b(?:use alternate authentication|pass[- ]the[- ]hash|PtH|pass[- ]the[- ]ticket|PtT)\b",
        ]),

        # === COLLECTION ===
        "T1005": (0.85, [
            r"\b(?:data from local system|collect(?:ed)? files|exfiltrat(?:ed)? files)\b",
        ]),
        "T1039": (0.85, [
            r"\b(?:data from network shared drive|network share|file share)\b",
        ]),
        "T1074": (0.85, [
            r"\b(?:data staged|staging directory|collected data)\b",
        ]),
        "T1119": (0.80, [
            r"\b(?:automated collection|scripted collection)\b",
        ]),
        "T1113": (0.90, [
            r"\b(?:screen capture|screenshot|screen recording)\b",
        ]),

        # === COMMAND AND CONTROL ===
        "T1071": (0.85, [
            r"\b(?:application layer protocol|C2|command[- ]and[- ]control|C&C|beacon(?:ing)?)\b",
        ]),
        "T1071.001": (0.90, [
            r"\b(?:web protocol|HTTP(?:S)?|web[- ]based C2)\b",
        ]),
        "T1071.004": (0.90, [
            r"\b(?:DNS tunnel(?:ing)?|DNS-based C2)\b",
        ]),
        "T1573": (0.85, [
            r"\b(?:encrypted channel|TLS|SSL|encrypted C2)\b",
        ]),
        "T1090": (0.85, [
            r"\b(?:proxy|SOCKS|proxy server|Tor)\b",
        ]),
        "T1095": (0.85, [
            r"\b(?:non[- ]application layer protocol|raw socket|custom protocol)\b",
        ]),
        "T1219": (0.85, [
            r"\b(?:remote access software|RAT|TeamViewer|AnyDesk|remote access tool)\b",
        ]),

        # === EXFILTRATION ===
        "T1041": (0.85, [
            r"\b(?:exfiltration over C2|exfiltrat(?:ed|ion) via C2)\b",
        ]),
        "T1048": (0.85, [
            r"\b(?:exfiltration over alternative protocol|data exfiltration|exfiltrat(?:ed|ion))\b",
        ]),
        "T1567": (0.85, [
            r"\b(?:exfiltration over web service|upload(?:ed)? to cloud|cloud storage)\b",
        ]),

        # === IMPACT ===
        "T1486": (0.95, [
            r"\b(?:data encrypted for impact|ransomware|encrypt(?:ed)? files?|\.locked|\.encrypted)\b",
        ]),
        "T1490": (0.90, [
            r"\b(?:inhibit system recovery|deleted (?:shadow copies|backups)|vssadmin delete)\b",
        ]),
        "T1489": (0.85, [
            r"\b(?:service stop|stopped service|disabled service)\b",
        ]),
        "T1485": (0.85, [
            r"\b(?:data destruction|wiped|deleted data|destroyed files)\b",
        ]),
        "T1491": (0.85, [
            r"\b(?:defacement|defaced|vandalism|ransom note)\b",
        ]),
        "T1498": (0.85, [
            r"\b(?:network denial of service|DDoS|DoS attack)\b",
        ]),
    }

    @classmethod
    def extract_techniques(cls, text: str) -> List[Dict]:
        """
        Extract ATT&CK techniques from text using regex patterns.

        Args:
            text: Input text to analyze

        Returns:
            List of technique dictionaries with:
            - technique_id: ATT&CK ID (e.g., T1059.001)
            - confidence: 0.0-1.0 confidence score
            - evidence: Text snippet that matched
        """
        if not text or len(text.strip()) == 0:
            logger.warning("Empty text provided to regex extractor")
            return []

        logger.info(f"Extracting techniques from {len(text)} characters of text")

        # Normalize text for better matching
        normalized_text = text.lower()

        # Track found techniques (deduplicate by technique_id)
        found_techniques: Dict[str, Dict] = {}

        # Apply each pattern
        for technique_id, (base_confidence, patterns) in cls.PATTERNS.items():
            for pattern in patterns:
                try:
                    matches = re.finditer(pattern, normalized_text, re.IGNORECASE)

                    for match in matches:
                        matched_text = match.group(0)

                        # Get context around match (50 chars before/after)
                        start = max(0, match.start() - 50)
                        end = min(len(text), match.end() + 50)
                        evidence = text[start:end].strip()

                        # If we already found this technique, keep the higher confidence
                        if technique_id in found_techniques:
                            if base_confidence > found_techniques[technique_id]["confidence"]:
                                found_techniques[technique_id]["confidence"] = base_confidence
                                found_techniques[technique_id]["evidence"] = evidence
                        else:
                            found_techniques[technique_id] = {
                                "technique_id": technique_id,
                                "confidence": base_confidence,
                                "evidence": evidence,
                            }

                        logger.debug(f"Matched {technique_id} with pattern '{pattern}': {matched_text}")

                except re.error as e:
                    logger.error(f"Regex error for pattern '{pattern}': {e}")
                    continue

        # Convert to list and sort by technique ID
        results = sorted(found_techniques.values(), key=lambda x: x["technique_id"])

        logger.info(f"Extracted {len(results)} unique techniques")

        return results

    @classmethod
    def get_statistics(cls) -> Dict:
        """
        Get statistics about the regex extractor.

        Returns:
            Dictionary with pattern statistics
        """
        total_patterns = sum(len(patterns) for _, patterns in cls.PATTERNS.values())

        # Count techniques by tactic (approximation based on ID range)
        tactic_counts = {
            "Initial Access": 0,
            "Execution": 0,
            "Persistence": 0,
            "Privilege Escalation": 0,
            "Defense Evasion": 0,
            "Credential Access": 0,
            "Discovery": 0,
            "Lateral Movement": 0,
            "Collection": 0,
            "Command and Control": 0,
            "Exfiltration": 0,
            "Impact": 0,
        }

        for tech_id in cls.PATTERNS.keys():
            # Approximation - actual tactics would require ATT&CK database
            if tech_id.startswith("T1566") or tech_id.startswith("T1190") or tech_id.startswith("T1133"):
                tactic_counts["Initial Access"] += 1
            elif tech_id.startswith("T1059") or tech_id.startswith("T1203") or tech_id.startswith("T1204"):
                tactic_counts["Execution"] += 1
            elif tech_id.startswith("T1053") or tech_id.startswith("T1543") or tech_id.startswith("T1547"):
                tactic_counts["Persistence"] += 1
            # ... and so on

        return {
            "total_techniques": len(cls.PATTERNS),
            "total_patterns": total_patterns,
            "average_patterns_per_technique": round(total_patterns / len(cls.PATTERNS), 2),
            "extraction_method": "regex",
            "llm_enabled": False,
        }
