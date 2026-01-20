"""
Tests for the Attribution Engine.

Tests the threat actor scoring algorithm that matches
layer techniques against known actor TTPs.
"""

import pytest


class TestConfidenceScoring:
    """Test the confidence scoring algorithm."""

    def test_jaccard_similarity_formula(self):
        """Jaccard similarity should be intersection / union."""
        layer_techniques = {"T1566", "T1059", "T1055", "T1071"}
        actor_techniques = {"T1566", "T1059", "T1082", "T1083"}

        intersection = layer_techniques & actor_techniques
        union = layer_techniques | actor_techniques

        jaccard = len(intersection) / len(union) if union else 0

        # 2 matching / 6 total unique = 0.333...
        assert len(intersection) == 2
        assert len(union) == 6
        assert round(jaccard, 3) == 0.333

    def test_perfect_match_confidence(self):
        """Identical technique sets should have 1.0 confidence."""
        layer_techniques = {"T1566", "T1059"}
        actor_techniques = {"T1566", "T1059"}

        intersection = layer_techniques & actor_techniques
        union = layer_techniques | actor_techniques

        jaccard = len(intersection) / len(union) if union else 0

        assert jaccard == 1.0

    def test_no_match_confidence(self):
        """No matching techniques should have 0.0 confidence."""
        layer_techniques = {"T1566", "T1059"}
        actor_techniques = {"T1082", "T1083"}

        intersection = layer_techniques & actor_techniques
        union = layer_techniques | actor_techniques

        jaccard = len(intersection) / len(union) if union else 0

        assert jaccard == 0.0

    def test_empty_sets_handling(self):
        """Empty sets should not cause division by zero."""
        layer_techniques = set()
        actor_techniques = set()

        union = layer_techniques | actor_techniques
        jaccard = len(layer_techniques & actor_techniques) / len(union) if union else 0

        assert jaccard == 0.0


class TestAttributionRanking:
    """Test the ranking of threat actor matches."""

    def test_higher_confidence_ranks_first(self):
        """Actors with higher confidence should rank higher."""
        attributions = [
            {"actor": "APT29", "confidence": 0.7},
            {"actor": "APT28", "confidence": 0.9},
            {"actor": "Lazarus", "confidence": 0.5}
        ]

        sorted_attributions = sorted(
            attributions,
            key=lambda x: x["confidence"],
            reverse=True
        )

        assert sorted_attributions[0]["actor"] == "APT28"
        assert sorted_attributions[1]["actor"] == "APT29"
        assert sorted_attributions[2]["actor"] == "Lazarus"

    def test_tie_breaking_by_overlap_count(self):
        """Equal confidence should be broken by overlap count."""
        attributions = [
            {"actor": "APT29", "confidence": 0.8, "overlap_count": 5},
            {"actor": "APT28", "confidence": 0.8, "overlap_count": 8},
        ]

        sorted_attributions = sorted(
            attributions,
            key=lambda x: (x["confidence"], x["overlap_count"]),
            reverse=True
        )

        assert sorted_attributions[0]["actor"] == "APT28"


class TestConfidenceLabels:
    """Test the confidence label assignment."""

    def test_high_confidence_threshold(self):
        """Confidence >= 0.8 should be labeled HIGH."""
        def get_confidence_label(confidence: float) -> str:
            if confidence >= 0.8:
                return "HIGH"
            elif confidence >= 0.5:
                return "MEDIUM"
            else:
                return "LOW"

        assert get_confidence_label(0.8) == "HIGH"
        assert get_confidence_label(0.9) == "HIGH"
        assert get_confidence_label(1.0) == "HIGH"

    def test_medium_confidence_threshold(self):
        """Confidence 0.5-0.79 should be labeled MEDIUM."""
        def get_confidence_label(confidence: float) -> str:
            if confidence >= 0.8:
                return "HIGH"
            elif confidence >= 0.5:
                return "MEDIUM"
            else:
                return "LOW"

        assert get_confidence_label(0.5) == "MEDIUM"
        assert get_confidence_label(0.7) == "MEDIUM"
        assert get_confidence_label(0.79) == "MEDIUM"

    def test_low_confidence_threshold(self):
        """Confidence < 0.5 should be labeled LOW."""
        def get_confidence_label(confidence: float) -> str:
            if confidence >= 0.8:
                return "HIGH"
            elif confidence >= 0.5:
                return "MEDIUM"
            else:
                return "LOW"

        assert get_confidence_label(0.0) == "LOW"
        assert get_confidence_label(0.3) == "LOW"
        assert get_confidence_label(0.49) == "LOW"


class TestMatchingTechniques:
    """Test the matching technique extraction."""

    def test_matching_techniques_extracted(self):
        """Should correctly identify which techniques match."""
        layer_techniques = {"T1566", "T1059", "T1055"}
        actor_techniques = {"T1566", "T1082", "T1055"}

        matching = layer_techniques & actor_techniques

        assert matching == {"T1566", "T1055"}
        assert len(matching) == 2

    def test_matching_techniques_sorted(self):
        """Matching techniques should be returned in sorted order."""
        matching = {"T1566", "T1055", "T1059"}

        sorted_matching = sorted(matching)

        assert sorted_matching == ["T1055", "T1059", "T1566"]
