"""
UTIP Database Schema

All 9 core tables as specified in the Engineering Implementation Guide.
This schema is the foundation - everything depends on it.

Critical Tables:
1. threat_reports - Raw intel metadata
2. extracted_techniques - Barracuda core value
3. vulnerability_scans - Scan metadata
4. vulnerabilities - Individual vulns
5. cve_techniques - Piranha crown jewel
6. layers - Generated layers
7. layer_techniques - Layer content
8. threat_actors - APT definitions
9. actor_techniques - Actor TTPs
"""

from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text, Enum as SQLEnum, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

Base = declarative_base()


class SourceType(enum.Enum):
    """Threat report source types"""
    PDF = "pdf"
    STIX = "stix"
    TEXT = "text"


class ProcessingStatus(enum.Enum):
    """Processing status for async tasks"""
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETE = "complete"
    FAILED = "failed"


class ExtractionMethod(enum.Enum):
    """Technique extraction method"""
    REGEX = "regex"
    LLM = "llm"


class TechniqueColor(enum.Enum):
    """MITRE ATT&CK layer colors"""
    YELLOW = "yellow"  # Intel only
    BLUE = "blue"      # Vulnerability only
    RED = "red"        # Critical overlap (Intel + Vuln)


# Table 1: threat_reports
class ThreatReport(Base):
    """
    Stores raw intel metadata.

    This preserves Barracuda's core value - tracking threat intelligence
    documents through the processing pipeline.
    """
    __tablename__ = "threat_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename = Column(String(255), nullable=False)
    source_type = Column(SQLEnum(SourceType), nullable=False)
    status = Column(SQLEnum(ProcessingStatus), nullable=False, default=ProcessingStatus.QUEUED)
    uploaded_by = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship to extracted techniques
    extracted_techniques = relationship("ExtractedTechnique", back_populates="report", cascade="all, delete-orphan")


# Table 2: extracted_techniques
class ExtractedTechnique(Base):
    """
    Barracuda core value - preserves technique extraction results.

    Each record represents a MITRE ATT&CK technique found in a threat report.
    Confidence and evidence are preserved for analyst review.
    """
    __tablename__ = "extracted_techniques"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(UUID(as_uuid=True), ForeignKey("threat_reports.id", ondelete="CASCADE"), nullable=False)
    technique_id = Column(String(20), nullable=False)  # e.g., "T1059.001"
    confidence = Column(Float, nullable=False)  # 0.0 to 1.0
    evidence = Column(Text)  # Text snippet that triggered detection
    extraction_method = Column(SQLEnum(ExtractionMethod), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship to report
    report = relationship("ThreatReport", back_populates="extracted_techniques")

    # Index for fast technique lookups
    __table_args__ = (
        Index("idx_extracted_techniques_technique_id", "technique_id"),
        Index("idx_extracted_techniques_report_id", "report_id"),
    )


# Table 3: vulnerability_scans
class VulnerabilityScan(Base):
    """
    Scan metadata for vulnerability assessments.

    Tracks Nessus scans and other vulnerability data sources.
    """
    __tablename__ = "vulnerability_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    filename = Column(String(255), nullable=False)
    scan_date = Column(DateTime(timezone=True), nullable=False)
    uploaded_by = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship to vulnerabilities
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


# Table 4: vulnerabilities
class Vulnerability(Base):
    """
    Individual vulnerabilities found in scans.

    Each record represents a CVE found on a specific asset.
    """
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability_scans.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String(20), nullable=False)  # e.g., "CVE-2024-1234"
    severity = Column(String(20), nullable=False)  # e.g., "Critical", "High"
    cvss_score = Column(Float, nullable=True)  # CVSS score (v2 or v3)
    asset = Column(String(255), nullable=False)  # Hostname or IP
    port = Column(String(20), nullable=True)  # Port/protocol (e.g., "443/tcp")
    plugin_id = Column(String(20), nullable=True)  # Nessus plugin ID
    plugin_name = Column(String(500), nullable=True)  # Nessus plugin name
    description = Column(Text, nullable=True)  # Vulnerability description
    solution = Column(Text, nullable=True)  # Remediation guidance

    # Relationship to scan
    scan = relationship("VulnerabilityScan", back_populates="vulnerabilities")

    # Index for fast lookups
    __table_args__ = (
        Index("idx_vulnerabilities_cve_id", "cve_id"),
        Index("idx_vulnerabilities_scan_id", "scan_id"),
        Index("idx_vulnerabilities_scan_cve", "scan_id", "cve_id"),  # Composite index for join queries
    )


# Table 5: cve_techniques (Piranha crown jewel)
class CVETechnique(Base):
    """
    Piranha crown jewel - CVE to TTP mapping.

    This table represents the critical IP: mapping CVEs to MITRE ATT&CK techniques
    via the CVE → CWE → CAPEC → Technique pipeline.

    The quality of this mapping determines blue/red accuracy in the correlation engine.
    """
    __tablename__ = "cve_techniques"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), nullable=False)
    technique_id = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)  # 0.0 to 1.0
    source = Column(String(50), nullable=False)  # "nvd", "capec", "manual"

    # Index for fast lookups + unique constraint to prevent duplicates
    __table_args__ = (
        Index("idx_cve_techniques_cve_id", "cve_id"),
        Index("idx_cve_techniques_technique_id", "technique_id"),
        UniqueConstraint("cve_id", "technique_id", "source", name="uq_cve_techniques"),
    )


# Table 6: layers
class Layer(Base):
    """
    Generated MITRE ATT&CK layers.

    Layers are immutable artifacts representing the correlation between
    threat intelligence and vulnerabilities at a point in time.
    """
    __tablename__ = "layers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationship to layer techniques
    layer_techniques = relationship("LayerTechnique", back_populates="layer", cascade="all, delete-orphan")


# Table 7: layer_techniques
class LayerTechnique(Base):
    """
    Layer content - techniques with correlation metadata.

    Each record represents a technique in a layer with its color and source flags.
    Color is determined by correlation logic:
    - Yellow: from_intel=True, from_vuln=False
    - Blue: from_intel=False, from_vuln=True
    - Red: from_intel=True, from_vuln=True (CRITICAL OVERLAP)
    """
    __tablename__ = "layer_techniques"

    id = Column(Integer, primary_key=True, autoincrement=True)
    layer_id = Column(UUID(as_uuid=True), ForeignKey("layers.id", ondelete="CASCADE"), nullable=False)
    technique_id = Column(String(20), nullable=False)
    color = Column(SQLEnum(TechniqueColor), nullable=False)
    confidence = Column(Float, nullable=False)  # max(intel_confidence, vuln_confidence)
    from_intel = Column(Integer, nullable=False, default=0)  # Boolean as int
    from_vuln = Column(Integer, nullable=False, default=0)  # Boolean as int

    # Relationship to layer
    layer = relationship("Layer", back_populates="layer_techniques")

    # Index for fast technique lookups within a layer
    __table_args__ = (
        Index("idx_layer_techniques_layer_id", "layer_id"),
        Index("idx_layer_techniques_technique_id", "technique_id"),
    )


# Table 8: threat_actors
class ThreatActor(Base):
    """
    APT definitions and metadata.

    Stores known threat actors (e.g., APT29, APT28, Lazarus) with their
    descriptions and associated techniques.
    """
    __tablename__ = "threat_actors"

    id = Column(String(50), primary_key=True)  # e.g., "APT29"
    name = Column(String(255), nullable=False)
    description = Column(Text)

    # Relationship to actor techniques
    actor_techniques = relationship("ActorTechnique", back_populates="actor", cascade="all, delete-orphan")


# Table 9: actor_techniques
class ActorTechnique(Base):
    """
    Actor TTPs - techniques used by threat actors.

    Each record represents a technique known to be used by a threat actor,
    with a weight indicating how frequently/significantly it's used.

    Used for deterministic attribution scoring.
    """
    __tablename__ = "actor_techniques"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor_id = Column(String(50), ForeignKey("threat_actors.id", ondelete="CASCADE"), nullable=False)
    technique_id = Column(String(20), nullable=False)
    weight = Column(Float, nullable=False)  # Relative importance/frequency

    # Relationship to actor
    actor = relationship("ThreatActor", back_populates="actor_techniques")

    # Index for fast lookups + unique constraint to prevent duplicates
    __table_args__ = (
        Index("idx_actor_techniques_actor_id", "actor_id"),
        Index("idx_actor_techniques_technique_id", "technique_id"),
        UniqueConstraint("actor_id", "technique_id", name="uq_actor_techniques"),
    )
