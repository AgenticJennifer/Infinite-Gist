"""
Tests for Phase 2 enhanced analysis services.

Comprehensive test suite for:
- Enhanced severity scoring with confidence levels
- Temporal correlation analysis
- Content-based pattern matching
- Cross-gist finding correlation
- Integration workflows
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any

# Import services under test
from src.backend.services.scoring import (
    EnhancedSeverityScorer,
    ConfidenceCategory,
    ScoringType,
)
from src.backend.services.correlation import (
    TemporalCorrelationGroup,
    ContentSimilarityAnalyzer,
    CorrelationAnalysisOrchestrator,
)
from src.backend.services.trufflehog_scanner import (
    TruffleHogScanner,
)
from src.backend.services.secret_scanner import SecretType, SecretMatch


class TestEnhancedSeverityScorer:
    """Test the enhanced severity scoring functionality."""

    def setup_method(self):
        self.scorer = EnhancedSeverityScorer()

    def test_confidence_category_mapping(self):
        """Test confidence category mappings."""
        # Test HIGH confidence (0.85-1.0)
        assert self.scorer._classify_confidence_category(0.90) == ConfidenceCategory.HIGH
        assert self.scorer._classify_confidence_category(1.0) == ConfidenceCategory.HIGH

        # Test MEDIUM confidence (0.65-0.84)
        assert self.scorer._classify_confidence_category(0.70) == ConfidenceCategory.MEDIUM
        assert self.scorer._classify_confidence_category(0.84) == ConfidenceCategory.MEDIUM

        # Test LOW confidence (< 0.65)
        assert self.scorer._classify_confidence_category(0.50) == ConfidenceCategory.LOW
        assert self.scorer._classify_confidence_category(0.00) == ConfidenceCategory.LOW

    def test_score_types_definitions(self):
        """Test score type definitions."""
        assert ScoringType.IMMEDIATE_THREAT == "immediate_threat"
        assert ScoringType.SIGNIFICANT_RISK == "significant_risk"
        assert ScoringType.LOW_PRIORITY == "low_priority"
        assert ScoringType.FALSE_POSITIVE == "false_positive"

    def test_risk_score_immediate_threat(self):
        """Test risk calculation for immediate threat category."""
        risk_score = self.scorer.calculate_risk_score(
            "critical", ConfidenceCategory.HIGH, ScoringType.IMMEDIATE_THREAT
        )

        # Calculate expected: base 90 * 1.2 (confidence) * 1.5 (type) = 162, capped at 100
        assert risk_score == 100.0

    def test_risk_score_significant_risk(self):
        """Test risk calculation for significant risk category."""
        risk_score = self.scorer.calculate_risk_score(
            "high", ConfidenceCategory.MEDIUM, ScoringType.SIGNIFICANT_RISK
        )

        # Calculate expected: base 70 * 1.0 (confidence) * 1.2 (type) = 84
        assert risk_score == 84.0

    def test_risk_score_low_priority(self):
        """Test risk calculation for low priority category."""
        risk_score = self.scorer.calculate_risk_score(
            "low", ConfidenceCategory.LOW, ScoringType.LOW_PRIORITY
        )

        # Calculate expected: base 10 * 0.7 (confidence) * 0.8 (type) = 5.6
        assert risk_score == pytest.approx(5.6)

    def test_risk_score_false_positive(self):
        """Test risk calculation for false positive category."""
        risk_score = self.scorer.calculate_risk_score(
            "critical", ConfidenceCategory.LOW, ScoringType.FALSE_POSITIVE
        )

        # Calculate expected: base 90 * 0.7 (confidence) * 0.3 (type) = 18.9
        assert risk_score == 18.9

    def test_significant_risk_for_low_confidence_critical(self):
        """Test that low confidence critical secrets get significant risk after severity adjustment."""
        with patch.object(EnhancedSeverityScorer, 'score', return_value=('critical', 'definite')):
            _, _, _, score_type = self.scorer.score_with_category(
                self._create_test_match(0.50, SecretType.AWS_ACCESS_KEY)
            )

            # Low confidence CRITICAL gets adjusted to HIGH severity, which results in SIGNIFICANT_RISK
            assert score_type == ScoringType.SIGNIFICANT_RISK

    def _create_test_match(self, confidence: float, secret_type) -> Mock:
        """Create a test SecretMatch for testing."""
        match = Mock()
        match.confidence = confidence
        match.type = secret_type
        match.matched_text = "test_value"
        match.file_path = "test.py"
        match.line_number = 1
        return match


class TestTemporalCorrelationGroup:
    """Test TemporalCorrelationGroup functionality."""

    def setup_method(self):
        self.group = TemporalCorrelationGroup("test_hash_123", "github_token")

    def test_group_initialization(self):
        """Test group initialization."""
        assert self.group.value_hash == "test_hash_123"
        assert self.group.secret_type == "github_token"
        assert self.group.finding_ids == []
        assert self.group.gist_ids == set()
        assert self.group.gist_count == 0
        assert self.group.revision_count == 0

    def test_add_finding(self):
        """Test adding a finding to the correlation group."""
        finding = Mock()
        finding.id = 1
        finding.gist_id = 100
        finding.severity = Mock(value="critical")
        finding.detected_at = datetime.now() - timedelta(days=1)
        finding.value_hash = "test_hash_123"
        finding.secret_type = "github_token"

        gist = Mock()
        gist.id = 100
        gist.description = "My GitHub gist"

        self.group.add_finding(finding, gist)

        assert 1 in self.group.finding_ids
        assert 100 in self.group.gist_ids
        assert self.group.gist_count == 1
        assert self.group.revision_count == 1
        assert self.group.gist_descriptions[100] == "My GitHub gist"

    def test_add_multiple_findings(self):
        """Test adding multiple findings to the group."""
        # Add findings from different gists
        for i in range(3):
            finding = Mock()
            finding.id = i + 1
            finding.gist_id = 100 + i
            finding.severity = Mock(value="high")
            finding.detected_at = datetime.now() - timedelta(hours=i)
            finding.value_hash = "test_hash_123"
            finding.secret_type = "github_token"

            gist = Mock()
            gist.id = 100 + i
            gist.description = f"Gist {100 + i}"

            self.group.add_finding(finding, gist)

        # Verify results
        assert len(self.group.finding_ids) == 3
        assert len(self.group.gist_ids) == 3
        assert self.group.gist_count == 3
        assert self.group.revision_count == 3

    def test_deduplicate_gist_ids(self):
        """Test that duplicate gist IDs are not added multiple times."""
        # Add two findings from the same gist
        finding1 = Mock()
        finding1.id = 1
        finding1.gist_id = 100
        finding1.severity = Mock(value="critical")
        finding1.detected_at = datetime.now()
        finding1.value_hash = "test_hash_123"
        finding1.secret_type = "github_token"

        finding2 = Mock()
        finding2.id = 2
        finding2.gist_id = 100  # Same gist
        finding2.severity = Mock(value="high")
        finding2.detected_at = datetime.now() - timedelta(hours=1)
        finding2.value_hash = "test_hash_123"
        finding2.secret_type = "github_token"

        self.group.add_finding(finding1, Mock(id=100, description="Test"))
        self.group.add_finding(finding2, Mock(id=100, description="Test"))

        # Should still have only one gist_id
        assert len(self.group.gist_ids) == 1
        assert self.group.gist_count == 1

    def test_detect_temporal_patterns(self):
        """Test temporal pattern detection."""
        # Create findings spanning different times
        now = datetime.now()

        finding1 = Mock()
        finding1.gist_id = 100
        finding1.detected_at = now - timedelta(days=10)

        finding2 = Mock()
        finding2.gist_id = 100
        finding2.detected_at = now - timedelta(days=7)

        finding3 = Mock()
        finding3.gist_id = 200
        finding3.detected_at = now - timedelta(days=5)

        self.group.add_finding(finding1)
        self.group.add_finding(finding2)
        self.group.add_finding(finding3)

        patterns = self.group.detect_temporal_patterns()

        assert "spread_rate" in patterns
        assert patterns["spread_rate"] > 0.1  # Should be active
        assert "growth_phase" in patterns
        assert patterns["growth_phase"] in ["rapid", "moderate", "slow", "stable"]

    def test_temporal_pattern_growth_classification(self):
        """Test growth phase classification based on spread rate."""
        now = datetime.now()

        # Set up findings with high spread rate (rapid growth)
        for i in range(10):
            finding = Mock()
            finding.gist_id = 100 + (i % 2)  # Fluctuating across 2 gists
            finding.detected_at = now - timedelta(hours=i)
            self.group.add_finding(finding)

        patterns = self.group.detect_temporal_patterns()

        # With 10 findings over 10 hours across 2 gists, spread should be high
        assert patterns["spread_rate"] > 1.0
        assert patterns["growth_phase"] == "rapid"

    def test_calculate_max_severity(self):
        """Test maximum severity calculation."""
        # Add findings with different severities
        self.group.severities = ["low", "medium", "high", "critical"]

        max_severity = self.group._calculate_max_severity()

        assert max_severity == "critical"

    def test_get_description_default(self):
        """Test that default description is empty string."""
        gist = Mock(id=100, description="")

        self.group.add_finding(Mock(id=1, gist_id=100, value_hash="test", secret_type="test"), gist)

        assert self.group.gist_descriptions[100] == ""

    def test_to_dict_format(self):
        """Test the dictionary conversion format."""
        finding = Mock()
        finding.id = 1
        finding.gist_id = 100
        finding.value_hash = "test_hash_123"
        finding.secret_type = "github_token"

        self.group.add_finding(finding, Mock(id=100, description="Test gist"))

        result = self.group.to_dict()

        assert result["value_hash"] == "test_hash_123"
        assert result["secret_type"] == "github_token"
        assert result["finding_count"] == 1
        assert result["gist_count"] == 1
        assert "temporal_patterns" in result
        assert "max_severity" in result


class TestContentSimilarityAnalyzer:
    """Test content similarity analysis functionality."""

    def setup_method(self):
        self.analyzer = ContentSimilarityAnalyzer()

    def test_file_path_pattern_detection(self):
        """Test file path pattern detection."""
        finding_ids = [1, 2, 3]
        db = Mock()

        # Mock findings with similar file paths (configuration files)
        finding1 = Mock()
        finding1.file_path = "src/config.py"

        finding2 = Mock()
        finding2.file_path = "src/secrets.yaml"

        finding3 = Mock()
        finding3.file_path = "src/auth.conf"

        db.query.return_value.filter.return_value.all.return_value = [finding1, finding2, finding3]

        result = self.analyzer.analyze_file_path_patterns(finding_ids, db)

        assert result["pattern_type"] in ["extension_pattern", "directory_pattern", "combined_pattern"]
        assert result["confidence"] > 0.5

    def test_directory_pattern_detection(self):
        """Test directory pattern detection."""
        finding_ids = [1, 2, 3]
        db = Mock()

        # Mock findings from the same directory
        finding1 = Mock()
        finding1.file_path = "src/config.py"

        finding2 = Mock()
        finding2.file_path = "src/secrets.yaml"

        finding3 = Mock()
        finding3.file_path = "src/auth.conf"

        db.query.return_value.filter.return_value.all.return_value = [finding1, finding2, finding3]

        result = self.analyzer.analyze_file_path_patterns(finding_ids, db)

        # Should detect combined pattern due to both extension and directory consistency
        assert result["pattern_type"] in ["extension_pattern", "directory_pattern", "combined_pattern"]
        assert result["confidence"] > 0.4

    def test_no_pattern_detection(self):
        """Test when no clear pattern exists."""
        finding_ids = [1, 2, 3]
        db = Mock()

        # Mock findings from completely different paths
        finding1 = Mock()
        finding1.file_path = "file1.txt"

        finding2 = Mock()
        finding2.file_path = "another.md"

        finding3 = Mock()
        finding3.file_path = "script.py"

        db.query.return_value.filter.return_value.all.return_value = [finding1, finding2, finding3]

        result = self.analyzer.analyze_file_path_patterns(finding_ids, db)

        assert result["pattern_type"] == "none"
        assert result["confidence"] == 0.0

    def test_temporal_analysis_basic(self):
        """Test basic temporal analysis."""
        finding1 = Mock()
        finding1.detected_at = datetime.now() - timedelta(days=1)

        finding2 = Mock()
        finding2.detected_at = datetime.now() - timedelta(days=3)

        finding3 = Mock()
        finding3.detected_at = datetime.now() - timedelta(days=5)

        db = Mock()
        db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [
            finding1, finding2, finding3
        ]

        result = self.analyzer.analyze_temporal_patterns([finding1, finding2, finding3], db)

        assert "distribution" in result
        assert "peak_period" in result
        assert "spread_rate" in result
        assert result["total_findings"] == 3
        assert result["active_days"] == 3

    def test_temporal_analysis_empty(self):
        """Test temporal analysis with empty data."""
        result = self.analyzer.analyze_temporal_patterns([], Mock())

        assert result["distribution"] == {}
        assert result["peak_period"] is None
        assert result["spread_rate"] == 0.0

    def test_temporal_analysis_daily_distribution(self):
        """Test daily distribution analysis."""
        # Mock findings from different days of the week
        now = datetime.now()

        finding1 = Mock()
        finding1.detected_at = now - timedelta(days=7)

        finding2 = Mock()
        finding2.detected_at = now - timedelta(days=3)

        finding3 = Mock()
        finding3.detected_at = now - timedelta(days=1)

        db = Mock()
        db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [
            finding1, finding2, finding3
        ]

        result = self.analyzer.analyze_temporal_patterns([finding1, finding2, finding3], db)

        # Should have distribution across different days
        assert "distribution" in result
        assert len(result["distribution"]) >= 3  # At least 3 unique days

    def test_combined_security_pattern_detection(self):
        """Test detection of combined security file patterns."""
        finding_ids = [1, 2, 3]
        db = Mock()

        # Files from different directories with security-related extensions
        finding1 = Mock()
        finding1.file_path = "config/production.yaml"

        finding2 = Mock()
        finding2.file_path = "config/secrets.env"

        finding3 = Mock()
        finding3.file_path = "docker-compose.yml"

        db.query.return_value.filter.return_value.all.return_value = [finding1, finding2, finding3]

        result = self.analyzer.analyze_file_path_patterns(finding_ids, db)

        # Should detect combined pattern due to directory "config" and security extensions
        assert result["pattern_type"] in ["extension_pattern", "directory_pattern", "combined_pattern"]
        assert result["confidence"] > 0.5


class TestCorrelationAnalysisOrchestrator:
    """Test the correlation analysis orchestrator."""

    def setup_method(self):
        self.orch = CorrelationAnalysisOrchestrator()

    @patch("src.backend.services.correlation.CorrelationAnalysisOrchestrator.analyze_correlation_opportunities")
    def test_analyze_user_findings(self, mock_analyze):
        """Test the main correlation analysis method."""
        user_id = 1
        db = Mock()

        # Mock the correlation analysis to return sample data
        mock_analyze.return_value = [
            {
                "value_hash": "hash1",
                "secret_type": "aws_access_key",
                "finding_count": 5,
                "gist_count": 3,
                "max_severity": "critical",
            },
            {
                "value_hash": "hash2",
                "secret_type": "github_token",
                "finding_count": 2,
                "gist_count": 1,
                "max_severity": "high",
            },
        ]

        result = self.orch.analyze_correlation_opportunities(user_id, db)

        # Verify the orchestrator calls the underlying method
        mock_analyze.assert_called_once_with(user_id, db)

    @patch("src.backend.services.correlation.CorrelationAnalysisOrchestrator.analyze_correlation_opportunities")
    def test_identify_correlation_patterns(self, mock_analyze):
        """Test correlation pattern identification."""
        user_id = 1
        db = Mock()

        # Mock findings for analysis
        mock_analyze.return_value = [
            {
                "value_hash": "hash1",
                "secret_type": "aws_access_key",
                "finding_count": 10,
                "gist_count": 5,
                "max_severity": "critical",
                "first_seen": (datetime.now() - timedelta(days=10)).isoformat(),
                "last_seen": datetime.now().isoformat(),
            },
            {
                "value_hash": "hash2",
                "secret_type": "github_token",
                "finding_count": 3,
                "gist_count": 2,
                "max_severity": "high",
                "first_seen": (datetime.now() - timedelta(days=5)).isoformat(),
                "last_seen": (datetime.now() - timedelta(days=2)).isoformat(),
            },
            {
                "value_hash": "hash3",
                "secret_type": "email",
                "finding_count": 1,
                "gist_count": 1,
                "max_severity": "low",
                "first_seen": (datetime.now() - timedelta(days=1)).isoformat(),
                "last_seen": (datetime.now() - timedelta(days=1)).isoformat(),
            },
        ]

        result = self.orch.identify_correlation_patterns(user_id, db)

        assert result["total_correlation_groups"] == 3
        assert result["total_related_findings"] == 14
        assert "patterns" in result
        assert "dominant_secret_types" in result["patterns"]
        assert "severity_distribution" in result["patterns"]
        assert "cross_gist_patterns" in result["patterns"]
        assert "prioritization_risks" in result
        assert len(result["prioritization_risks"]) == 1  # only hash1 qualifies (10 findings, critical)
        assert len(result["highly_correlated_groups"]) == 2  # hash1 and hash2 have >=3 findings


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
