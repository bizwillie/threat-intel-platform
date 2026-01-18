"""
UTIP API Routes
"""

from .health import router as health_router
from .intel import router as intel_router
from .vulnerabilities import router as vuln_router
from .layers import router as layer_router
from .attribution import router as attribution_router
from .remediation import router as remediation_router

__all__ = [
    "health_router",
    "intel_router",
    "vuln_router",
    "layer_router",
    "attribution_router",
    "remediation_router",
]
