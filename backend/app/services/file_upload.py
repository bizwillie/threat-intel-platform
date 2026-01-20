"""
File Upload Service

Centralized file upload validation and processing.

SECURITY: Provides hardened file upload handling with:
- Magic byte validation (prevents file type spoofing)
- Filename sanitization (prevents path traversal attacks)
- Path validation (defense in depth)
- Size limits (prevents resource exhaustion)

This service is used by both intel and vulnerability upload endpoints.
"""

import os
import re
import logging
from typing import Dict, Set, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FileValidationResult:
    """Result of file validation."""
    is_valid: bool
    error_message: Optional[str] = None
    sanitized_filename: Optional[str] = None
    detected_type: Optional[str] = None


class FileUploadService:
    """
    Service for secure file upload validation.

    Provides centralized security controls for all file uploads.
    """

    # Default upload directory
    DEFAULT_UPLOAD_DIR = "/app/uploads"

    # Magic bytes for file type validation
    # Format: extension -> magic bytes (None if no reliable magic bytes)
    MAGIC_BYTES: Dict[str, Optional[bytes]] = {
        # Threat Intel formats
        ".pdf": b"%PDF",
        ".json": None,  # JSON files don't have reliable magic bytes
        ".stix": None,  # JSON-based
        ".stix2": None,  # JSON-based
        ".txt": None,  # Text files don't have magic bytes
        # Vulnerability scan formats
        ".nessus": b"<?xml",  # XML-based
        ".xml": b"<?xml",
    }

    # Default size limits
    DEFAULT_MAX_SIZE = 50 * 1024 * 1024  # 50 MB

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename to prevent path traversal attacks.

        SECURITY: Only allows alphanumeric characters, underscores, hyphens, and dots.
        Removes any path components that could be used for directory traversal.

        Args:
            filename: Original filename from upload

        Returns:
            Sanitized filename safe for filesystem use
        """
        # Extract just the filename (remove any path)
        filename = os.path.basename(filename)
        # Replace any potentially dangerous characters
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
        # Remove any leading dots (hidden files)
        safe_name = safe_name.lstrip('.')
        # Ensure filename is not empty
        if not safe_name:
            safe_name = "unnamed_file"
        return safe_name

    @staticmethod
    def validate_magic_bytes(content: bytes, extension: str) -> bool:
        """
        Validate file content matches expected type using magic bytes.

        SECURITY: Prevents file type spoofing by verifying actual content
        matches the declared file extension.

        Args:
            content: File content bytes
            extension: File extension (e.g., ".pdf")

        Returns:
            True if validation passes, False otherwise
        """
        expected_magic = FileUploadService.MAGIC_BYTES.get(extension.lower())
        if expected_magic is None:
            # No magic bytes to validate for this type
            return True
        return content.startswith(expected_magic)

    @staticmethod
    def validate_path_safety(file_path: str, upload_dir: str) -> bool:
        """
        Validate that the final file path is within the upload directory.

        SECURITY: Defense in depth - verifies the resolved path is within
        the intended upload directory, even after filename sanitization.

        Args:
            file_path: Proposed file path
            upload_dir: Allowed upload directory

        Returns:
            True if path is safe, False if path traversal detected
        """
        real_upload_dir = os.path.realpath(upload_dir)
        real_file_path = os.path.realpath(file_path)
        return real_file_path.startswith(real_upload_dir)

    @classmethod
    def validate_upload(
        cls,
        filename: str,
        content: bytes,
        allowed_extensions: Set[str],
        max_size: int = DEFAULT_MAX_SIZE,
        upload_dir: Optional[str] = None
    ) -> FileValidationResult:
        """
        Perform comprehensive validation of an uploaded file.

        Args:
            filename: Original filename
            content: File content bytes
            allowed_extensions: Set of allowed file extensions (e.g., {".pdf", ".txt"})
            max_size: Maximum allowed file size in bytes
            upload_dir: Upload directory for path validation

        Returns:
            FileValidationResult with validation status and details
        """
        upload_dir = upload_dir or os.getenv("UPLOAD_DIR", cls.DEFAULT_UPLOAD_DIR)

        # 1. Check file extension
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext not in allowed_extensions:
            return FileValidationResult(
                is_valid=False,
                error_message=f"File type not allowed. Allowed: {', '.join(allowed_extensions)}"
            )

        # 2. Check file size
        if len(content) > max_size:
            max_mb = max_size / (1024 * 1024)
            return FileValidationResult(
                is_valid=False,
                error_message=f"File too large. Maximum size: {max_mb} MB"
            )

        # 3. Sanitize filename
        sanitized = cls.sanitize_filename(filename)

        # 4. Validate magic bytes
        if not cls.validate_magic_bytes(content, file_ext):
            logger.warning(f"Magic byte mismatch for file: {filename}")
            return FileValidationResult(
                is_valid=False,
                error_message="File content does not match file extension"
            )

        # 5. Validate path safety (if upload_dir provided)
        if upload_dir:
            test_path = os.path.join(upload_dir, sanitized)
            if not cls.validate_path_safety(test_path, upload_dir):
                logger.error(f"Path traversal attempt detected: {filename}")
                return FileValidationResult(
                    is_valid=False,
                    error_message="Invalid filename"
                )

        # Detect file type
        detected_type = cls._detect_file_type(file_ext)

        return FileValidationResult(
            is_valid=True,
            sanitized_filename=sanitized,
            detected_type=detected_type
        )

    @staticmethod
    def _detect_file_type(extension: str) -> str:
        """
        Detect the logical file type from extension.

        Args:
            extension: File extension (e.g., ".pdf")

        Returns:
            Logical file type (e.g., "pdf", "stix", "nessus")
        """
        ext = extension.lower()
        if ext == ".pdf":
            return "pdf"
        elif ext in [".json", ".stix", ".stix2"]:
            return "stix"
        elif ext == ".txt":
            return "text"
        elif ext in [".nessus", ".xml"]:
            return "nessus"
        return "unknown"

    @classmethod
    async def save_file(
        cls,
        content: bytes,
        filename: str,
        upload_dir: Optional[str] = None
    ) -> str:
        """
        Save file content to disk.

        Args:
            content: File content bytes
            filename: Sanitized filename (should already be validated)
            upload_dir: Upload directory

        Returns:
            Full path to saved file

        Raises:
            IOError: If file cannot be written
        """
        upload_dir = upload_dir or os.getenv("UPLOAD_DIR", cls.DEFAULT_UPLOAD_DIR)

        # Ensure upload directory exists
        os.makedirs(upload_dir, exist_ok=True)

        file_path = os.path.join(upload_dir, filename)

        with open(file_path, "wb") as f:
            f.write(content)

        logger.info(f"Saved file to {file_path}")
        return file_path
