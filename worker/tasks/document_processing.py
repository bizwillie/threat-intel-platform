"""
Document Processing Celery Tasks

Handles async processing of threat intelligence documents:
- PDF reports
- STIX bundles
- Plain text files

Extracts TTPs using regex-based pattern matching (Phase 3).
LLM extraction deferred to Phase 4.
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Optional
from celery import Task
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from celery_app import app

logger = logging.getLogger(__name__)

# Database connection
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://utip:utip@postgres:5432/utip")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class CallbackTask(Task):
    """Base task class with database session management."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Update report status on task failure."""
        logger.error(f"Task {task_id} failed: {exc}")

        # Get report_id from args
        if args:
            report_id = args[0]
            db = SessionLocal()
            try:
                db.execute(
                    "UPDATE threat_reports SET status = 'failed', error_message = :error WHERE id = :id",
                    {"error": str(exc), "id": report_id}
                )
                db.commit()
            except Exception as e:
                logger.error(f"Failed to update report status: {e}")
            finally:
                db.close()


@app.task(bind=True, base=CallbackTask, name="tasks.document_processing.process_threat_report")
def process_threat_report(self, report_id: str, file_path: str, filename: str) -> Dict:
    """
    Process a threat intelligence document.

    Args:
        report_id: UUID of the threat_reports record
        file_path: Absolute path to uploaded file
        filename: Original filename

    Returns:
        Dict with processing results
    """
    logger.info(f"Processing threat report {report_id}: {filename}")

    db = SessionLocal()

    try:
        # Update status to processing
        db.execute(
            "UPDATE threat_reports SET status = 'processing' WHERE id = :id",
            {"id": report_id}
        )
        db.commit()

        # Detect document type from filename
        file_ext = os.path.splitext(filename)[1].lower()

        # Extract text based on document type
        extracted_text = None
        source_type = None

        if file_ext == ".pdf":
            logger.info(f"{report_id}: Detected PDF document")
            from extractors.pdf_parser import PDFParser
            extracted_text = PDFParser.extract_text(file_path)
            source_type = "pdf"

        elif file_ext == ".json" or filename.endswith(".stix") or filename.endswith(".stix2"):
            logger.info(f"{report_id}: Detected STIX document")
            from extractors.stix_parser import STIXParser
            extracted_text = STIXParser.extract_text(file_path)
            source_type = "stix"

        elif file_ext == ".txt":
            logger.info(f"{report_id}: Detected text document")
            with open(file_path, "r", encoding="utf-8") as f:
                extracted_text = f.read()
            source_type = "text"

        else:
            raise ValueError(f"Unsupported file type: {file_ext}")

        if not extracted_text or len(extracted_text.strip()) == 0:
            raise ValueError("No text extracted from document")

        logger.info(f"{report_id}: Extracted {len(extracted_text)} characters")

        # Extract TTPs using regex patterns (Phase 3)
        from extractors.regex_extractor import RegexExtractor
        techniques = RegexExtractor.extract_techniques(extracted_text)

        logger.info(f"{report_id}: Extracted {len(techniques)} techniques using regex")

        # Store extracted techniques in database
        stored_count = 0
        for technique in techniques:
            try:
                db.execute(
                    """
                    INSERT INTO extracted_techniques
                    (report_id, technique_id, confidence, evidence, extraction_method)
                    VALUES (:report_id, :technique_id, :confidence, :evidence, :method)
                    ON CONFLICT (report_id, technique_id) DO UPDATE
                    SET confidence = GREATEST(extracted_techniques.confidence, EXCLUDED.confidence),
                        evidence = EXCLUDED.evidence
                    """,
                    {
                        "report_id": report_id,
                        "technique_id": technique["technique_id"],
                        "confidence": technique["confidence"],
                        "evidence": technique["evidence"][:500],  # Limit evidence length
                        "method": "regex"
                    }
                )
                stored_count += 1
            except Exception as e:
                logger.error(f"{report_id}: Failed to store technique {technique['technique_id']}: {e}")

        db.commit()
        logger.info(f"{report_id}: Stored {stored_count} techniques in database")

        # Update report status to complete
        db.execute(
            "UPDATE threat_reports SET status = 'complete', processed_at = :now WHERE id = :id",
            {"now": datetime.utcnow(), "id": report_id}
        )
        db.commit()

        # Clean up uploaded file
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"{report_id}: Cleaned up file {file_path}")

        result = {
            "report_id": report_id,
            "filename": filename,
            "source_type": source_type,
            "techniques_found": len(techniques),
            "techniques_stored": stored_count,
            "status": "complete"
        }

        logger.info(f"{report_id}: Processing complete - {result}")
        return result

    except Exception as e:
        logger.error(f"{report_id}: Processing failed: {e}", exc_info=True)

        # Update status to failed
        db.execute(
            "UPDATE threat_reports SET status = 'failed', error_message = :error WHERE id = :id",
            {"error": str(e)[:500], "id": report_id}
        )
        db.commit()

        raise

    finally:
        db.close()


@app.task(name="tasks.document_processing.get_processing_statistics")
def get_processing_statistics() -> Dict:
    """
    Get statistics about threat report processing.

    Returns:
        Dict with processing statistics
    """
    db = SessionLocal()

    try:
        # Count reports by status
        result = db.execute(
            """
            SELECT status, COUNT(*) as count
            FROM threat_reports
            GROUP BY status
            """
        ).fetchall()

        status_counts = {row[0]: row[1] for row in result}

        # Count total techniques extracted
        total_techniques = db.execute(
            "SELECT COUNT(*) FROM extracted_techniques"
        ).scalar()

        # Average techniques per report
        avg_techniques = db.execute(
            """
            SELECT AVG(tech_count)
            FROM (
                SELECT COUNT(*) as tech_count
                FROM extracted_techniques
                GROUP BY report_id
            ) as subq
            """
        ).scalar() or 0

        return {
            "status_breakdown": status_counts,
            "total_techniques_extracted": total_techniques,
            "average_techniques_per_report": float(avg_techniques),
            "timestamp": datetime.utcnow().isoformat()
        }

    finally:
        db.close()
