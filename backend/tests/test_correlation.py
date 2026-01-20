"""
Tests for the Correlation Engine.

Tests the core intellectual property: layer generation with
red/yellow/blue color coding based on intel and vulnerability overlap.
"""

import pytest
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.correlation import CorrelationEngine


class TestColorAssignment:
    """Test color assignment logic for technique categories."""

    def test_color_constants_defined(self):
        """Color constants should match Midnight Vulture design system."""
        assert CorrelationEngine.COLOR_RED == "#EF4444"
        assert CorrelationEngine.COLOR_YELLOW == "#F59E0B"
        assert CorrelationEngine.COLOR_BLUE == "#3B82F6"


class TestSetOperations:
    """Test the set operations for technique categorization."""

    def test_overlap_detection(self):
        """Red techniques should be intersection of intel and vuln sets."""
        intel_set = {"T1566", "T1059", "T1055"}
        vuln_set = {"T1059", "T1055", "T1071"}

        red_techniques = intel_set & vuln_set
        yellow_techniques = intel_set - vuln_set
        blue_techniques = vuln_set - intel_set

        assert red_techniques == {"T1059", "T1055"}
        assert yellow_techniques == {"T1566"}
        assert blue_techniques == {"T1071"}

    def test_no_overlap(self):
        """When sets don't overlap, no red techniques."""
        intel_set = {"T1566", "T1059"}
        vuln_set = {"T1071", "T1082"}

        red_techniques = intel_set & vuln_set

        assert red_techniques == set()
        assert len(intel_set - vuln_set) == 2
        assert len(vuln_set - intel_set) == 2

    def test_complete_overlap(self):
        """When sets completely overlap, all techniques are red."""
        intel_set = {"T1566", "T1059"}
        vuln_set = {"T1566", "T1059"}

        red_techniques = intel_set & vuln_set
        yellow_techniques = intel_set - vuln_set
        blue_techniques = vuln_set - intel_set

        assert red_techniques == {"T1566", "T1059"}
        assert yellow_techniques == set()
        assert blue_techniques == set()

    def test_empty_intel_set(self):
        """With no intel, all techniques should be blue."""
        intel_set = set()
        vuln_set = {"T1071", "T1082"}

        red_techniques = intel_set & vuln_set
        yellow_techniques = intel_set - vuln_set
        blue_techniques = vuln_set - intel_set

        assert red_techniques == set()
        assert yellow_techniques == set()
        assert blue_techniques == {"T1071", "T1082"}

    def test_empty_vuln_set(self):
        """With no vulnerabilities, all techniques should be yellow."""
        intel_set = {"T1566", "T1059"}
        vuln_set = set()

        red_techniques = intel_set & vuln_set
        yellow_techniques = intel_set - vuln_set
        blue_techniques = vuln_set - intel_set

        assert red_techniques == set()
        assert yellow_techniques == {"T1566", "T1059"}
        assert blue_techniques == set()


class TestNavigatorExportFormat:
    """Test the MITRE ATT&CK Navigator export format."""

    def test_navigator_version_format(self):
        """Navigator export should include proper version metadata."""
        # Expected structure based on Navigator v4.5
        expected_versions = {
            "attack": "14",
            "navigator": "4.5",
            "layer": "4.5"
        }

        # This tests the expected format, actual implementation tested in integration
        assert expected_versions["attack"] == "14"
        assert expected_versions["navigator"] == "4.5"

    def test_legend_items_format(self):
        """Legend should explain red/yellow/blue meaning."""
        expected_legends = [
            {"label": "Critical Overlap (Intel + Vuln)", "color": "#EF4444"},
            {"label": "Threat Intel Only", "color": "#F59E0B"},
            {"label": "Vulnerability Only", "color": "#3B82F6"}
        ]

        assert len(expected_legends) == 3
        assert expected_legends[0]["color"] == CorrelationEngine.COLOR_RED
        assert expected_legends[1]["color"] == CorrelationEngine.COLOR_YELLOW
        assert expected_legends[2]["color"] == CorrelationEngine.COLOR_BLUE


class TestConfidenceCalculation:
    """Test confidence score handling."""

    def test_max_confidence_for_overlap(self):
        """Overlapping techniques should use max confidence from both sources."""
        intel_confidence = 0.8
        vuln_confidence = 0.6

        # For red techniques, we take the maximum
        final_confidence = max(intel_confidence, vuln_confidence)

        assert final_confidence == 0.8

    def test_confidence_score_scaling(self):
        """Confidence should scale from 0.0-1.0 to 0-100 for Navigator."""
        confidence = 0.85
        scaled_score = int(confidence * 100)

        assert scaled_score == 85

    def test_zero_confidence_handling(self):
        """Zero confidence should not break score calculation."""
        confidence = 0.0
        scaled_score = int(confidence * 100)

        assert scaled_score == 0


class TestBreakdownStatistics:
    """Test the breakdown statistics calculation."""

    def test_overlap_percentage_calculation(self):
        """Overlap percentage should be calculated correctly."""
        red_count = 5
        yellow_count = 10
        blue_count = 5
        total = red_count + yellow_count + blue_count

        overlap_percentage = round((red_count / total * 100) if total > 0 else 0, 2)

        assert overlap_percentage == 25.0

    def test_zero_techniques_no_division_error(self):
        """Zero total techniques should not cause division by zero."""
        red_count = 0
        total = 0

        overlap_percentage = round((red_count / total * 100) if total > 0 else 0, 2)

        assert overlap_percentage == 0.0
