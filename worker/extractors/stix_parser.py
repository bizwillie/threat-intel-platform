"""
STIX Parser using stix2 library

Extracts threat intelligence from STIX 2.x bundles.
Focuses on indicators, attack patterns, and course-of-action objects.
"""

import json
import logging
from typing import List, Dict, Optional
import stix2

logger = logging.getLogger(__name__)


class STIXParser:
    """STIX 2.x bundle parser for threat intelligence extraction."""

    @staticmethod
    def extract_text(file_path: str) -> str:
        """
        Extract threat intelligence from STIX bundle.

        Converts STIX objects into text format suitable for TTP extraction.
        Focuses on descriptive fields that may contain technique references.

        Args:
            file_path: Absolute path to STIX JSON file

        Returns:
            Extracted text content from STIX objects

        Raises:
            ValueError: If file is not valid STIX or is empty
        """
        logger.info(f"Parsing STIX bundle: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                stix_data = json.load(f)

            # Verify it's a STIX bundle
            if not isinstance(stix_data, dict) or stix_data.get("type") != "bundle":
                raise ValueError("File is not a valid STIX 2.x bundle")

            objects = stix_data.get("objects", [])
            if not objects:
                raise ValueError("STIX bundle contains no objects")

            logger.info(f"STIX bundle contains {len(objects)} objects")

            extracted_parts = []

            # Process each STIX object
            for obj in objects:
                obj_type = obj.get("type", "unknown")
                obj_text = STIXParser._extract_from_object(obj, obj_type)

                if obj_text:
                    extracted_parts.append(f"--- {obj_type.upper()} ---\n{obj_text}")

            if not extracted_parts:
                raise ValueError("No text could be extracted from STIX objects")

            full_text = "\n\n".join(extracted_parts)

            logger.info(f"Successfully extracted {len(full_text)} characters from {len(extracted_parts)} STIX objects")

            return full_text

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in STIX file: {e}")
            raise ValueError(f"File is not valid JSON: {str(e)}")

        except FileNotFoundError:
            logger.error(f"STIX file not found: {file_path}")
            raise

        except Exception as e:
            logger.error(f"STIX parsing failed: {e}", exc_info=True)
            raise ValueError(f"Failed to parse STIX bundle: {str(e)}")

    @staticmethod
    def _extract_from_object(obj: dict, obj_type: str) -> str:
        """
        Extract relevant text from a STIX object.

        Args:
            obj: STIX object dictionary
            obj_type: Type of STIX object

        Returns:
            Extracted text content
        """
        parts = []

        # Common fields across all objects
        if "name" in obj:
            parts.append(f"Name: {obj['name']}")

        if "description" in obj:
            parts.append(f"Description: {obj['description']}")

        # Type-specific extraction
        if obj_type == "attack-pattern":
            # ATT&CK techniques are often in attack-pattern objects
            if "external_references" in obj:
                for ref in obj["external_references"]:
                    if ref.get("source_name") == "mitre-attack":
                        parts.append(f"ATT&CK Technique: {ref.get('external_id', '')}")
                        if "url" in ref:
                            parts.append(f"URL: {ref['url']}")

            if "kill_chain_phases" in obj:
                phases = [phase.get("phase_name", "") for phase in obj["kill_chain_phases"]]
                parts.append(f"Kill Chain Phases: {', '.join(phases)}")

        elif obj_type == "indicator":
            if "pattern" in obj:
                parts.append(f"Pattern: {obj['pattern']}")

            if "indicator_types" in obj:
                parts.append(f"Types: {', '.join(obj['indicator_types'])}")

        elif obj_type == "malware":
            if "malware_types" in obj:
                parts.append(f"Malware Types: {', '.join(obj['malware_types'])}")

            if "is_family" in obj:
                parts.append(f"Is Family: {obj['is_family']}")

        elif obj_type == "threat-actor":
            if "threat_actor_types" in obj:
                parts.append(f"Actor Types: {', '.join(obj['threat_actor_types'])}")

            if "aliases" in obj:
                parts.append(f"Aliases: {', '.join(obj['aliases'])}")

            if "goals" in obj:
                parts.append(f"Goals: {', '.join(obj['goals'])}")

        elif obj_type == "course-of-action":
            # Mitigations and defensive measures
            if "labels" in obj:
                parts.append(f"Labels: {', '.join(obj['labels'])}")

        elif obj_type == "intrusion-set":
            if "aliases" in obj:
                parts.append(f"Aliases: {', '.join(obj['aliases'])}")

            if "goals" in obj:
                parts.append(f"Goals: {', '.join(obj['goals'])}")

        elif obj_type == "tool":
            if "tool_types" in obj:
                parts.append(f"Tool Types: {', '.join(obj['tool_types'])}")

        elif obj_type == "vulnerability":
            if "external_references" in obj:
                for ref in obj["external_references"]:
                    if "external_id" in ref:
                        parts.append(f"CVE: {ref['external_id']}")

        # Extract any labels
        if "labels" in obj and obj_type not in ["course-of-action"]:
            parts.append(f"Labels: {', '.join(obj['labels'])}")

        return "\n".join(parts)

    @staticmethod
    def extract_techniques_direct(file_path: str) -> List[str]:
        """
        Directly extract ATT&CK technique IDs from STIX bundle.

        This bypasses regex extraction for STIX files that explicitly
        reference ATT&CK techniques in attack-pattern objects.

        Args:
            file_path: Absolute path to STIX JSON file

        Returns:
            List of technique IDs found in STIX bundle
        """
        logger.info(f"Extracting techniques directly from STIX: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                stix_data = json.load(f)

            objects = stix_data.get("objects", [])
            techniques = []

            for obj in objects:
                if obj.get("type") == "attack-pattern":
                    # Look for ATT&CK external references
                    refs = obj.get("external_references", [])
                    for ref in refs:
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id", "")
                            if tech_id and tech_id.startswith("T"):
                                techniques.append(tech_id)
                                logger.debug(f"Found technique in STIX: {tech_id}")

            logger.info(f"Extracted {len(techniques)} techniques directly from STIX")

            return techniques

        except Exception as e:
            logger.error(f"Failed to extract techniques from STIX: {e}")
            return []
