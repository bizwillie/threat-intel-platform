"""
UTIP Structured Logging Configuration

Provides JSON-formatted logs with:
- Request correlation IDs
- Structured fields for log aggregation
- Security event tracking
- Performance metrics

Usage:
    from app.shared.logging_config import get_logger
    logger = get_logger(__name__)
    logger.info("User action", extra={"user_id": "123", "action": "login"})
"""

import json
import logging
import os
import sys
from datetime import datetime
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """
    JSON log formatter for structured logging.

    Outputs logs in a format suitable for log aggregation systems
    like ELK Stack, Splunk, or CloudWatch.
    """

    def __init__(self, service_name: str = "utip-api"):
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
        }

        # Add source location
        log_data["source"] = {
            "file": record.filename,
            "line": record.lineno,
            "function": record.funcName
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info)
            }

        # Add extra fields from the record
        # These can be passed via logger.info("msg", extra={...})
        extra_keys = [
            "request_id", "user_id", "username", "action",
            "duration_ms", "status_code", "method", "path",
            "ip_address", "user_agent", "layer_id", "technique_id"
        ]

        for key in extra_keys:
            if hasattr(record, key):
                log_data[key] = getattr(record, key)

        # Also capture any other extra fields
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord.__dict__ and key not in log_data and not key.startswith("_"):
                try:
                    # Ensure the value is JSON serializable
                    json.dumps(value)
                    log_data[key] = value
                except (TypeError, ValueError):
                    log_data[key] = str(value)

        return json.dumps(log_data, default=str)


class SecurityEventLogger:
    """
    Specialized logger for security-relevant events.

    Logs authentication, authorization, and security policy violations.
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def auth_success(self, username: str, user_id: str, ip_address: str):
        """Log successful authentication."""
        self.logger.info(
            "Authentication successful",
            extra={
                "event_type": "auth.success",
                "username": username,
                "user_id": user_id,
                "ip_address": ip_address
            }
        )

    def auth_failure(self, username: str, ip_address: str, reason: str):
        """Log failed authentication attempt."""
        self.logger.warning(
            "Authentication failed",
            extra={
                "event_type": "auth.failure",
                "username": username,
                "ip_address": ip_address,
                "reason": reason
            }
        )

    def authorization_denied(self, user_id: str, resource: str, action: str):
        """Log authorization denial."""
        self.logger.warning(
            "Authorization denied",
            extra={
                "event_type": "authz.denied",
                "user_id": user_id,
                "resource": resource,
                "action": action
            }
        )

    def rate_limit_exceeded(self, ip_address: str, endpoint: str):
        """Log rate limit violation."""
        self.logger.warning(
            "Rate limit exceeded",
            extra={
                "event_type": "security.rate_limit",
                "ip_address": ip_address,
                "endpoint": endpoint
            }
        )

    def suspicious_activity(self, description: str, details: Dict[str, Any]):
        """Log suspicious activity detection."""
        self.logger.warning(
            f"Suspicious activity: {description}",
            extra={
                "event_type": "security.suspicious",
                **details
            }
        )


class AuditLogger:
    """
    Logger for audit trail events.

    Tracks data modifications, uploads, and deletions for compliance.
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def data_created(self, user_id: str, resource_type: str, resource_id: str, details: Optional[Dict] = None):
        """Log resource creation."""
        self.logger.info(
            f"Created {resource_type}",
            extra={
                "event_type": "audit.create",
                "user_id": user_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                **(details or {})
            }
        )

    def data_modified(self, user_id: str, resource_type: str, resource_id: str, changes: Optional[Dict] = None):
        """Log resource modification."""
        self.logger.info(
            f"Modified {resource_type}",
            extra={
                "event_type": "audit.modify",
                "user_id": user_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "changes": changes
            }
        )

    def data_deleted(self, user_id: str, resource_type: str, resource_id: str):
        """Log resource deletion."""
        self.logger.info(
            f"Deleted {resource_type}",
            extra={
                "event_type": "audit.delete",
                "user_id": user_id,
                "resource_type": resource_type,
                "resource_id": resource_id
            }
        )

    def file_uploaded(self, user_id: str, filename: str, file_type: str, file_size: int):
        """Log file upload."""
        self.logger.info(
            f"File uploaded: {filename}",
            extra={
                "event_type": "audit.upload",
                "user_id": user_id,
                "filename": filename,
                "file_type": file_type,
                "file_size": file_size
            }
        )


def configure_logging(
    level: str = "INFO",
    json_format: bool = True,
    service_name: str = "utip-api"
) -> None:
    """
    Configure application-wide logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Use JSON formatting (True for production)
        service_name: Service identifier for log aggregation
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, level.upper()))

    if json_format:
        handler.setFormatter(JSONFormatter(service_name))
    else:
        # Human-readable format for development
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        ))

    root_logger.addHandler(handler)

    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name."""
    return logging.getLogger(name)


def get_security_logger() -> SecurityEventLogger:
    """Get the security event logger."""
    return SecurityEventLogger(logging.getLogger("security"))


def get_audit_logger() -> AuditLogger:
    """Get the audit trail logger."""
    return AuditLogger(logging.getLogger("audit"))


# Auto-configure on import based on environment
_environment = os.environ.get("ENVIRONMENT", "development")
_log_level = os.environ.get("LOG_LEVEL", "INFO")
_json_logs = _environment in ("production", "staging", "test")

configure_logging(level=_log_level, json_format=_json_logs)
