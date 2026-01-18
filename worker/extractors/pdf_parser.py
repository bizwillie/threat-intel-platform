"""
PDF Parser using pdfplumber

Extracts text content from PDF threat intelligence reports.
Handles multi-page documents, tables, and various PDF formats.
"""

import logging
from typing import Optional
import pdfplumber

logger = logging.getLogger(__name__)


class PDFParser:
    """PDF text extraction using pdfplumber."""

    @staticmethod
    def extract_text(file_path: str) -> str:
        """
        Extract all text from a PDF file.

        Args:
            file_path: Absolute path to PDF file

        Returns:
            Extracted text content

        Raises:
            ValueError: If file cannot be read or is empty
            FileNotFoundError: If file does not exist
        """
        logger.info(f"Extracting text from PDF: {file_path}")

        try:
            extracted_pages = []

            with pdfplumber.open(file_path) as pdf:
                if len(pdf.pages) == 0:
                    raise ValueError("PDF has no pages")

                logger.debug(f"PDF has {len(pdf.pages)} pages")

                for page_num, page in enumerate(pdf.pages, start=1):
                    try:
                        # Extract text from page
                        page_text = page.extract_text()

                        if page_text:
                            extracted_pages.append(page_text)
                            logger.debug(f"Page {page_num}: Extracted {len(page_text)} characters")
                        else:
                            logger.warning(f"Page {page_num}: No text extracted")

                    except Exception as e:
                        logger.error(f"Page {page_num}: Extraction failed - {e}")
                        # Continue with other pages even if one fails
                        continue

            if not extracted_pages:
                raise ValueError("No text could be extracted from any page")

            # Join all pages with double newline
            full_text = "\n\n".join(extracted_pages)

            logger.info(f"Successfully extracted {len(full_text)} characters from {len(extracted_pages)} pages")

            return full_text

        except FileNotFoundError:
            logger.error(f"PDF file not found: {file_path}")
            raise

        except Exception as e:
            logger.error(f"PDF extraction failed: {e}", exc_info=True)
            raise ValueError(f"Failed to extract text from PDF: {str(e)}")

    @staticmethod
    def extract_metadata(file_path: str) -> dict:
        """
        Extract metadata from a PDF file.

        Args:
            file_path: Absolute path to PDF file

        Returns:
            Dictionary containing PDF metadata
        """
        try:
            with pdfplumber.open(file_path) as pdf:
                metadata = {
                    "page_count": len(pdf.pages),
                    "metadata": pdf.metadata or {},
                }

                # Get document info if available
                if hasattr(pdf, 'doc') and hasattr(pdf.doc, 'info'):
                    info = pdf.doc.info
                    if info:
                        metadata["title"] = info.get("Title", "")
                        metadata["author"] = info.get("Author", "")
                        metadata["subject"] = info.get("Subject", "")
                        metadata["creator"] = info.get("Creator", "")
                        metadata["producer"] = info.get("Producer", "")
                        metadata["creation_date"] = info.get("CreationDate", "")

                return metadata

        except Exception as e:
            logger.error(f"Failed to extract PDF metadata: {e}")
            return {"error": str(e)}
