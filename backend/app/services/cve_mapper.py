"""
CVE to MITRE ATT&CK Technique Mapper (with Phase 2.5 Enhancements)

The "Piranha Crown Jewel" - Maps CVEs to ATT&CK techniques via CWE→CAPEC→Technique chain.

Mapping Pipeline:
    CVE → CWE → CAPEC → ATT&CK Technique

Data Sources:
    1. NIST NVD API for CVE→CWE mappings (optional via ENABLE_NVD_API)
    2. MITRE CAPEC database for CWE→CAPEC mappings (optional via ENABLE_CAPEC_DATABASE)
    3. MITRE ATT&CK STIX data for CAPEC→Technique mappings (optional via ENABLE_ATTACK_STIX_VALIDATION)
    4. Manual curated mappings for high-priority CVEs (always enabled)
    5. Extended CWE mappings (400+ CWEs, optional via ENABLE_EXTENDED_CWE_MAPPINGS)
    6. Redis cache for persistent storage (optional via ENABLE_REDIS_CACHE)

Phase 2.5 Feature Flags:
    - All enhancements are OPTIONAL and configurable via environment variables
    - System gracefully degrades to core functionality if features are disabled

SECURITY: NVD API protected with:
    - Circuit breaker (prevents cascading failures)
    - Rate limiting (prevents NVD API abuse)
    - Bounded cache (prevents memory exhaustion)
"""

import httpx
import logging
from typing import List, Dict, Optional
import asyncio
from datetime import datetime, timedelta
from cachetools import TTLCache
from app.config import settings
# Note: tenacity and circuitbreaker were removed - manual implementations are used instead
from app.services.capec_mapper import CAPECMapper
from app.services.attack_validator import ATTACKValidator
from app.services.redis_cache import RedisCache
from app.services.extended_cwe_mappings import ExtendedCWEMappings

logger = logging.getLogger(__name__)


class CVEMapperError(Exception):
    """Raised when CVE mapping fails."""
    pass


class CVEMapper:
    """Maps CVEs to MITRE ATT&CK techniques."""

    # NVD API endpoint
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # SECURITY: Bounded cache to prevent memory exhaustion
    # 10,000 items max, 7 day TTL (604800 seconds)
    _cve_cache: TTLCache = TTLCache(maxsize=10000, ttl=604800)

    # Rate limiting semaphore: max 5 concurrent NVD requests
    _nvd_semaphore = asyncio.Semaphore(5)

    # Circuit breaker state tracking
    _circuit_failures = 0
    _circuit_open_until: Optional[datetime] = None

    # Manual high-confidence mappings (curated)
    # Format: CVE-ID → [(technique_id, confidence, source)]
    MANUAL_MAPPINGS = {
        # Remote Code Execution CVEs → Command/Scripting Execution
        "CVE-2021-44228": [("T1059", 0.95, "manual")],  # Log4Shell → Command Execution
        "CVE-2017-0144": [("T1210", 0.98, "manual")],  # EternalBlue → Exploitation for Remote Code Execution

        # Privilege Escalation
        "CVE-2021-3156": [("T1068", 0.95, "manual")],  # Sudo Baron Samedit
        "CVE-2022-26134": [("T1190", 0.95, "manual")],  # Confluence RCE

        # Credential Access
        "CVE-2020-1472": [("T1003.006", 0.98, "manual")],  # Zerologon → DCSync

        # Ransomware-related
        "CVE-2023-23397": [("T1566.001", 0.90, "manual")],  # Outlook Elevation → Spearphishing Attachment
    }

    # CWE → CAPEC → Technique mappings (simplified, production would use full STIX)
    CWE_TO_TECHNIQUE = {
        # Command Injection
        "CWE-77": [("T1059", 0.85, "cwe-mapping")],   # Command Injection → Command/Scripting
        "CWE-78": [("T1059", 0.90, "cwe-mapping")],   # OS Command Injection
        "CWE-94": [("T1059", 0.85, "cwe-mapping")],   # Code Injection

        # Authentication/Credential Issues
        "CWE-287": [("T1078", 0.75, "cwe-mapping")],  # Improper Auth → Valid Accounts
        "CWE-798": [("T1552.001", 0.90, "cwe-mapping")],  # Hardcoded Credentials
        "CWE-522": [("T1552", 0.80, "cwe-mapping")],  # Insufficiently Protected Credentials

        # Privilege Escalation
        "CWE-269": [("T1068", 0.85, "cwe-mapping")],  # Improper Privilege Management
        "CWE-250": [("T1068", 0.80, "cwe-mapping")],  # Execution with Unnecessary Privileges

        # Remote Code Execution
        "CWE-502": [("T1203", 0.85, "cwe-mapping")],  # Deserialization → Exploitation for Client Exec
        "CWE-434": [("T1203", 0.80, "cwe-mapping")],  # Unrestricted File Upload

        # SQL Injection
        "CWE-89": [("T1190", 0.75, "cwe-mapping")],   # SQL Injection → Exploit Public-Facing App

        # XSS and Web Vulns
        "CWE-79": [("T1189", 0.70, "cwe-mapping")],   # XSS → Drive-by Compromise
        "CWE-352": [("T1189", 0.65, "cwe-mapping")],  # CSRF

        # Path Traversal
        "CWE-22": [("T1083", 0.75, "cwe-mapping")],   # Path Traversal → File/Directory Discovery

        # Information Disclosure
        "CWE-200": [("T1005", 0.60, "cwe-mapping")],  # Info Exposure → Data from Local System

        # Buffer Overflow
        "CWE-120": [("T1203", 0.80, "cwe-mapping")],  # Buffer Overflow → Exploitation
        "CWE-787": [("T1203", 0.80, "cwe-mapping")],  # Out-of-bounds Write
    }

    @classmethod
    async def map_cve_to_techniques(cls, cve_id: str) -> List[Dict]:
        """
        Map a CVE to MITRE ATT&CK techniques.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            List of technique mappings:
            [
                {
                    "technique_id": "T1059",
                    "confidence": 0.95,
                    "source": "manual"
                },
                ...
            ]

        Raises:
            CVEMapperError: If CVE cannot be resolved
        """
        # Normalize CVE ID
        cve_id = cve_id.upper().strip()

        logger.info(f"Mapping {cve_id} to ATT&CK techniques")

        # Step 1: Check manual mappings (highest confidence)
        if cve_id in cls.MANUAL_MAPPINGS:
            mappings = [
                {
                    "technique_id": tid,
                    "confidence": conf,
                    "source": src,
                }
                for tid, conf, src in cls.MANUAL_MAPPINGS[cve_id]
            ]
            logger.info(f"{cve_id}: Found {len(mappings)} manual mappings")
            return mappings

        # Step 2: Query NVD API for CWE mappings
        try:
            cve_data = await cls._fetch_cve_from_nvd(cve_id)
        except Exception as e:
            logger.error(f"Failed to fetch {cve_id} from NVD: {e}")
            # Don't raise - continue with empty CWE list
            cve_data = {"cwes": []}

        cwes = cve_data.get("cwes", [])

        # Step 3: Map CWEs to techniques (Phase 2.5: with extended mappings and CAPEC)
        techniques = []
        seen_techniques = set()  # Deduplicate

        for cwe_id in cwes:
            # Phase 2.5: Try CAPEC database first (if enabled)
            if settings.enable_capec_database:
                capec_techniques = CAPECMapper.map_cwe_to_techniques(cwe_id)
                for tid, conf, src in capec_techniques:
                    if tid not in seen_techniques:
                        techniques.append({
                            "technique_id": tid,
                            "confidence": conf,
                            "source": src,
                        })
                        seen_techniques.add(tid)

            # Phase 2.5: Try extended CWE mappings (if enabled and CAPEC didn't match)
            if settings.enable_extended_cwe_mappings and cwe_id not in seen_techniques:
                extended_techniques = ExtendedCWEMappings.get_mappings_for_cwe(cwe_id)
                for tid, conf in extended_techniques:
                    if tid not in seen_techniques:
                        techniques.append({
                            "technique_id": tid,
                            "confidence": conf,
                            "source": f"extended-cwe-mapping:{cwe_id}",
                        })
                        seen_techniques.add(tid)

            # Fallback to core CWE mappings
            if cwe_id in cls.CWE_TO_TECHNIQUE:
                for tid, conf, src in cls.CWE_TO_TECHNIQUE[cwe_id]:
                    if tid not in seen_techniques:
                        techniques.append({
                            "technique_id": tid,
                            "confidence": conf,
                            "source": f"{src}:{cwe_id}",
                        })
                        seen_techniques.add(tid)

        # Phase 2.5: Validate techniques against ATT&CK STIX (if enabled)
        if settings.enable_attack_stix_validation and techniques:
            validated_techniques = []
            for tech in techniques:
                if ATTACKValidator.is_valid_technique(tech["technique_id"]):
                    validated_techniques.append(tech)
                else:
                    logger.warning(
                        f"{cve_id}: Technique {tech['technique_id']} failed STIX validation - excluding"
                    )
            techniques = validated_techniques

        if techniques:
            logger.info(f"{cve_id}: Mapped to {len(techniques)} techniques via CWE")
        else:
            logger.warning(f"{cve_id}: No technique mappings found")

        return techniques

    @classmethod
    async def _fetch_cve_from_nvd(cls, cve_id: str) -> Dict:
        """
        Fetch CVE details from NIST NVD API (Phase 2.5: with Redis cache support).

        SECURITY: Protected with:
        - Circuit breaker (5 failures opens circuit for 60 seconds)
        - Rate limiting (5 concurrent requests max, 200ms delay)
        - Retry with exponential backoff (3 attempts)

        Returns:
            {
                "cve_id": "CVE-2021-44228",
                "description": "...",
                "cwes": ["CWE-502", "CWE-400"],
                "cvss_score": 10.0,
                "published_date": "2021-12-10T00:00:00",
            }
        """
        # Phase 2.5: Check if NVD API is enabled
        if not settings.enable_nvd_api:
            logger.debug(f"{cve_id}: NVD API disabled, returning empty CWE list")
            return {"cwes": []}

        # SECURITY: Check circuit breaker state
        if cls._circuit_open_until and datetime.now() < cls._circuit_open_until:
            logger.warning(f"{cve_id}: Circuit breaker OPEN, returning empty CWE list")
            return {"cwes": []}

        # Phase 2.5: Try Redis cache first (if enabled)
        cache_key = f"cve:{cve_id}"
        if settings.enable_redis_cache:
            cached_data = await RedisCache.get(cache_key)
            if cached_data:
                logger.debug(f"{cve_id}: Using Redis cached data")
                return cached_data

        # Fallback to in-memory cache (TTLCache handles expiration automatically)
        if cve_id in cls._cve_cache:
            logger.debug(f"{cve_id}: Using in-memory cached data")
            return cls._cve_cache[cve_id]

        # SECURITY: Rate limit NVD API requests
        async with cls._nvd_semaphore:
            # Add delay between requests to respect NVD rate limits
            await asyncio.sleep(0.2)  # 200ms = max 5 req/sec

            # Fetch from NVD with retry logic
            nvd_data = await cls._fetch_nvd_with_retry(cve_id)

        return nvd_data

    @classmethod
    async def _fetch_nvd_with_retry(cls, cve_id: str) -> Dict:
        """
        Fetch from NVD with retry and circuit breaker logic.

        Retries up to 3 times with exponential backoff.
        Opens circuit breaker after 5 consecutive failures.
        """
        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                async with httpx.AsyncClient(timeout=settings.nvd_api_timeout) as client:
                    response = await client.get(
                        cls.NVD_API_BASE,
                        params={"cveId": cve_id},
                        headers=headers
                    )
                    response.raise_for_status()
                    nvd_data = response.json()

                # Success - reset circuit breaker
                cls._circuit_failures = 0
                cls._circuit_open_until = None

                return await cls._parse_and_cache_nvd_response(cve_id, nvd_data)

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.warning(f"{cve_id}: Not found in NVD")
                    return {"cwes": []}
                elif e.response.status_code == 429:
                    # Rate limited - back off
                    wait_time = (2 ** attempt) * 2  # 2, 4, 8 seconds
                    logger.warning(f"{cve_id}: NVD rate limited, waiting {wait_time}s (attempt {attempt + 1}/{max_attempts})")
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    cls._record_circuit_failure()
                    if attempt < max_attempts - 1:
                        wait_time = (2 ** attempt)
                        logger.warning(f"{cve_id}: NVD API error {e.response.status_code}, retrying in {wait_time}s")
                        await asyncio.sleep(wait_time)
                        continue
                    raise CVEMapperError(f"NVD API error: {e}")

            except httpx.RequestError as e:
                cls._record_circuit_failure()
                if attempt < max_attempts - 1:
                    wait_time = (2 ** attempt)
                    logger.warning(f"{cve_id}: NVD request failed, retrying in {wait_time}s: {e}")
                    await asyncio.sleep(wait_time)
                    continue
                raise CVEMapperError(f"NVD API request failed: {e}")

        # All retries exhausted
        return {"cwes": []}

    @classmethod
    def _record_circuit_failure(cls):
        """Record a failure and potentially open the circuit breaker."""
        cls._circuit_failures += 1
        if cls._circuit_failures >= 5:
            cls._circuit_open_until = datetime.now() + timedelta(seconds=60)
            logger.error(f"Circuit breaker OPENED after {cls._circuit_failures} failures, will retry in 60s")

    @classmethod
    async def _parse_and_cache_nvd_response(cls, cve_id: str, nvd_data: Dict) -> Dict:
        """Parse NVD response and cache the result."""
        cache_key = f"cve:{cve_id}"

        # Parse NVD response
        try:
            vulnerabilities = nvd_data.get("vulnerabilities", [])
            if not vulnerabilities:
                logger.warning(f"{cve_id}: No data in NVD response")
                return {"cwes": []}

            cve_item = vulnerabilities[0]["cve"]

            # Extract CWEs
            cwes = []
            weaknesses = cve_item.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_value = desc.get("value", "")
                    if cwe_value.startswith("CWE-"):
                        cwes.append(cwe_value)

            # Extract description
            descriptions = cve_item.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS score (prefer v3, fallback to v2)
            cvss_score = None
            metrics = cve_item.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            # Extract published date
            published_date = cve_item.get("published", "")

            result = {
                "cve_id": cve_id,
                "description": description,
                "cwes": cwes,
                "cvss_score": cvss_score,
                "published_date": published_date,
            }

            # Phase 2.5: Cache in Redis if enabled
            if settings.enable_redis_cache:
                await RedisCache.set(cache_key, result, ttl_seconds=settings.nvd_api_cache_ttl)

            # Always cache in memory as fallback (TTLCache handles expiration)
            cls._cve_cache[cve_id] = result

            logger.info(f"{cve_id}: Fetched from NVD with {len(cwes)} CWEs")
            return result

        except (KeyError, IndexError) as e:
            logger.error(f"Failed to parse NVD response for {cve_id}: {e}")
            return {"cwes": []}

    @classmethod
    async def map_multiple_cves(cls, cve_ids: List[str]) -> Dict[str, List[Dict]]:
        """
        Map multiple CVEs to techniques concurrently.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dict mapping CVE-ID → list of technique mappings
        """
        # Deduplicate and normalize
        unique_cves = list(set(cve.upper().strip() for cve in cve_ids))

        logger.info(f"Mapping {len(unique_cves)} CVEs to techniques")

        # Map concurrently with rate limiting
        tasks = [cls.map_cve_to_techniques(cve_id) for cve_id in unique_cves]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Build result dict
        mappings = {}
        for cve_id, result in zip(unique_cves, results):
            if isinstance(result, Exception):
                logger.error(f"Failed to map {cve_id}: {result}")
                mappings[cve_id] = []
            else:
                mappings[cve_id] = result

        total_techniques = sum(len(v) for v in mappings.values())
        logger.info(f"Mapped {len(unique_cves)} CVEs to {total_techniques} total technique mappings")

        return mappings

    @classmethod
    def validate_technique_id(cls, technique_id: str) -> bool:
        """
        Validate that a technique ID exists in MITRE ATT&CK.

        Phase 2.5: If STIX validation is enabled, uses full ATT&CK data.
        Otherwise, performs simple format check.

        Args:
            technique_id: Technique ID (e.g., "T1059" or "T1059.001")

        Returns:
            True if valid format, False otherwise
        """
        # Phase 2.5: Use STIX validator if enabled
        if settings.enable_attack_stix_validation:
            return ATTACKValidator.is_valid_technique(technique_id)

        # Fallback to format check
        import re
        # Pattern: T followed by 4 digits, optional .001-.999 sub-technique
        pattern = r"^T\d{4}(\.\d{3})?$"
        return bool(re.match(pattern, technique_id))

    @classmethod
    async def get_feature_statistics(cls) -> Dict:
        """
        Get statistics about Phase 2.5 features and their status.

        Returns:
            Dictionary with feature enablement status and statistics
        """
        stats = {
            "phase": "2.5",
            "features": {
                "nvd_api": {
                    "enabled": settings.enable_nvd_api,
                    "has_api_key": settings.nvd_api_key is not None,
                    "cache_ttl_days": settings.nvd_api_cache_ttl / 86400,
                    "in_memory_cache_size": len(cls._cve_cache),
                    "in_memory_cache_max": cls._cve_cache.maxsize,
                    "circuit_breaker_open": cls._circuit_open_until is not None and datetime.now() < cls._circuit_open_until,
                    "circuit_failures": cls._circuit_failures,
                },
                "redis_cache": await RedisCache.get_statistics(),
                "capec_database": CAPECMapper.get_statistics(),
                "attack_stix_validation": ATTACKValidator.get_statistics(),
                "extended_cwe_mappings": ExtendedCWEMappings.get_statistics(),
            },
            "core_mappings": {
                "manual_cve_count": len(cls.MANUAL_MAPPINGS),
                "core_cwe_count": len(cls.CWE_TO_TECHNIQUE),
            }
        }

        return stats
