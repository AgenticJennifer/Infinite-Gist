"""
Tests for Phase 2 correlation and analysis services.

Tests for:
- Enhanced severity scoring (HIGH/MEDIUM/LOW confidence)
- Finding correlation across multiple gists
- Temporal analysis of findings
- Model-based triage for borderline cases
- Integration with TruffleHog scanner
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from typing import List

from src.backend.services.trufflehog_scanner import TruffleHogScanner, SecretMatch
from src.backend.services.scoring import EnhancedSeverityScorer, ConfidenceCategory, ScoringType
from src.backend.db.models import Finding, Gist
from src.backend.services.correlation import (
    TemporalCorrelationGroup,
    ContentSimilarityAnalyzer,
    CorrelationAnalysisOrchestrator,
)
from src.backend.services.secret_scanner import SecretType, SecretMatch as RegexSecretMatch


class TestEnhancedSeverityScorer:
    """Test enhanced severity scoring service."""

    def setup_method(self):
        self.scorer = EnhancedSeverityScorer()

    def test_confidence_category_high(self):
        """Test HIGH confidence category (0.85-1.0)."""
        confidence = 0.90
        category = self.scorer._classify_confidence_category(confidence)
        assert category == ConfidenceCategory.HIGH

    def test_confidence_category_medium(self):
        """Test MEDIUM confidence category (0.65-0.84)."""
        confidence = 0.70
        category = self.scorer._classify_confidence_category(confidence)
        assert category == ConfidenceCategory.MEDIUM

    def test_confidence_category_low(self):
        """Test LOW confidence category (< 0.65)."""
        confidence = 0.50
        category = self.scorer._classify_confidence_category(confidence)
        assert category == ConfidenceCategory.LOW

    def test_score_type_immediate_threat(self):
        """Test IMMEDIATE_THREAT score type for critical secrets."""
        # Mock the parent class scoring
        with patch.object(EnhancedSeverityScorer, 'score', return_value=('critical', 'definite')):
            severity, _, category, score_type = self.scorer.score_with_category(
                self._create_test_match(0.90, SecretType.AWS_ACCESS_KEY)
            )
            assert score_type == ScoringType.IMMEDIATE_THREAT

    def test_score_type_significant_risk(self):
        """Test SIGNIFICANT_RISK score type for high/medium secrets."""
        # Use API_KEY (maps to MEDIUM severity) with MEDIUM confidence → SIGNIFICANT_RISK
        severity, _, category, score_type = self.scorer.score_with_category(
            self._create_test_match(0.70, SecretType.API_KEY)
        )
        assert score_type == ScoringType.SIGNIFICANT_RISK

    def test_score_type_low_priority(self):
        """Test LOW_PRIORITY score type for low severity/low confidence."""
        with patch.object(EnhancedSeverityScorer, 'score', return_value=('low', 'possible')):
            severity, _, category, score_type = self.scorer.score_with_category(
                self._create_test_match(0.50, SecretType.EMAIL)
            )
            assert score_type == ScoringType.LOW_PRIORITY

    def test_risk_score_calculation(self):
        """Test numeric risk score calculation."""
        severity = 'high'
        category = ConfidenceCategory.HIGH
        score_type = ScoringType.IMMEDIATE_THREAT

        risk_score = self.scorer.calculate_risk_score(severity, category, score_type)

        # Expect: base 70 + multiplier 1.2 + multiplier 1.5 = 105, capped at 100
        assert risk_score == 100.0  # Capped at 100

    def test_risk_score_critical_default(self):
        """Test risk score for DEFAULT_CRITICAL severity."""
        severity = 'critical'
        category = ConfidenceCategory.HIGH
        score_type = ScoringType.IMMEDIATE_THREAT

        risk_score = self.scorer.calculate_risk_score(severity, category, score_type)

        # Expect: base 90 + multiplier 1.2 + multiplier 1.5 = 172.5, capped at 100
        assert risk_score == 100.0  # Capped at 100

    def test_risk_score_false_positive(self):
        """Test risk score for false positive."""
        severity = 'critical'
        category = ConfidenceCategory.LOW
        score_type = ScoringType.FALSE_POSITIVE

        risk_score = self.scorer.calculate_risk_score(severity, category, score_type)

        # Expect: base 90 + multiplier 0.7 + multiplier 0.3 = 18.9
        assert risk_score == 18.9

    def _create_test_match(self, confidence: float, secret_type: SecretType) -> SecretMatch:
        """Create a test SecretMatch for testing."""
        match = Mock(spec=SecretMatch)
        match.confidence = confidence
        match.type = secret_type
        match.matched_text = "test_value"
        match.file_path = "test.py"
        match.line_number = 1
        return match


class TestTemporalCorrelationGroup:
    """Test TemporalCorrelationGroup functionality."""

    def setup_method(self):
        self.group = TemporalCorrelationGroup("test_hash", "aws_access_key")

    def test_add_finding_basic(self):
        """Test adding a basic finding to group."""
        finding = Mock()
        finding.id = 1
        finding.gist_id = 100
        finding.severity = Mock(value='critical')
        finding.detected_at = datetime.now()
        finding.value_hash = "test_hash"
        finding.secret_type = "aws_access_key"
        finding.finding_type = "aws_key"

        gist = Mock()
        gist.id = 100
        gist.description = "Test gist"

        self.group.add_finding(finding, gist)

        assert 1 in self.group.finding_ids
        assert 100 in self.group.gist_ids
        assert self.group.gist_count == 1

    def test_add_finding_duplicates(self):
        """Test adding duplicate findings."""
        finding1 = Mock()
        finding1.id = 1
        finding1.gist_id = 100
        finding1.value_hash = "test_hash"
        finding1.secret_type = "aws_access_key"
        finding1.severity = Mock(value='critical')
        finding1.detected_at = datetime.now()

        finding2 = Mock()
        finding2.id = 2
        finding2.gist_id = 200
        finding2.value_hash = "test_hash"
        finding2.secret_type = "aws_access_key"
        finding2.severity = Mock(value='high')
        finding2.detected_at = datetime.now() - timedelta(hours=1)

        self.group.add_finding(finding1)
        self.group.add_finding(finding2)

        assert len(self.group.finding_ids) == 2
        assert len(self.group.gist_ids) == 2
        assert self.group.gist_count == 2

    def test_detect_temporal_patterns_simple(self):
        """Test temporal pattern detection."""
        # Mock findings with different timestamps
        finding1 = Mock()
        finding1.gist_id = 100
        finding1.detected_at = datetime.now() - timedelta(days=1)

        finding2 = Mock()
        finding2.gist_id = 100
        finding2.detected_at = datetime.now() - timedelta(days=2)

        finding3 = Mock()
        finding3.gist_id = 200
        finding3.detected_at = datetime.now() - timedelta(days=5)

        self.group.add_finding(finding1)
        self.group.add_finding(finding2)
        self.group.add_finding(finding3)

        patterns = self.group.detect_temporal_patterns()

        assert "spread_rate" in patterns
        assert patterns["spread_rate"] > 0
        assert "growth_phase" in patterns

    def test_temporal_patterns_different_spreads(self):
        """Test temporal patterns with different spread rates."""
        # Mock findings concentrated in short time period
        now = datetime.now()

        for i in range(10):
            finding = Mock()
            finding.gist_id = 100 + (i % 2)  # 2 different gists
            finding.detected_at = now - timedelta(hours=i)
            self.group.add_finding(finding)

        patterns = self.group.detect_temporal_patterns()

        # Should have rapid growth due to high spread rate
        assert patterns["spread_rate"] > 1.0
        assert patterns["growth_phase"] == "rapid"

    def test_calculate_max_severity(self):
        """Test maximum severity calculation."""
        finding1 = Mock()
        finding1.severity = Mock(value='medium')
        finding1.detected_at = datetime.now() - timedelta(hours=2)

        finding2 = Mock()
        finding2.severity = Mock(value='critical')
        finding2.detected_at = datetime.now() - timedelta(hours=1)

        finding3 = Mock()
        finding3.severity = Mock(value='high')
        finding3.detected_at = datetime.now()

        self.group.add_finding(finding1)
        self.group.add_finding(finding2)
        self.group.add_finding(finding3)

        # Mock the severities list (this is populated by add_finding)
        self.group.severities = ['medium', 'critical', 'high']

        max_severity = self.group._calculate_max_severity()
        assert max_severity == 'critical'

    def test_to_dict_format(self):
        """Test dictionary conversion format."""
        finding1 = Mock()
        finding1.id = 1
        finding1.gist_id = 100
        finding1.value_hash = "test_hash"
        finding1.secret_type = "aws_access_key"

        self.group.add_finding(finding1)

        result = self.group.to_dict()

        assert result["value_hash"] == "test_hash"
        assert result["secret_type"] == "aws_access_key"
        assert result["finding_count"] == 1
        assert result["gist_count"] == 1
        assert "temporal_patterns" in result
        assert "max_severity" in result


class TestContentSimilarityAnalyzer:
    """Test content similarity analysis."""

    def setup_method(self):
        self.analyzer = ContentSimilarityAnalyzer()

    def test_analyze_file_path_patterns_extension(self):
        """Test file extension pattern detection."""
        finding_ids = [1, 2, 3]
        db = Mock()

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

    def test_analyze_file_path_patterns_no_pattern(self):
        """Test with no dominant pattern."""
        finding_ids = [1, 2, 3]
        db = Mock()

        finding1 = Mock()
        finding1.file_path = "project/file1.txt"

        finding2 = Mock()
        finding2.file_path = "other/another.md"

        finding3 = Mock()
        finding3.file_path = "docs/script.py"

        db.query.return_value.filter.return_value.all.return_value = [finding1, finding2, finding3]

        result = self.analyzer.analyze_file_path_patterns(finding_ids, db)

        assert result["pattern_type"] == "none"
        assert result["confidence"] == 0.0

    def test_analyze_temporal_patterns(self):
        """Test temporal pattern analysis."""
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

        result = self.analyzer.analyze_temporal_patterns(
            [finding1, finding2, finding3], db
        )

        assert "distribution" in result
        assert "peak_period" in result
        assert "spread_rate" in result
        assert result["total_findings"] == 3
        assert result["active_days"] == 3

    def test_analyze_temporal_patterns_empty(self):
        """Test temporal patterns with no data."""
        result = self.analyzer.analyze_temporal_patterns([], Mock())

        assert result["distribution"] == {}
        assert result["peak_period"] is None
        assert result["spread_rate"] == 0.0


class TestCorrelationAnalysisOrchestrator:
    """Test correlation analysis orchestrator."""

    def setup_method(self):
        self.orch = CorrelationAnalysisOrchestrator()

    def test_correlate_user_findings_empty(self):
        """Test correlation with no findings."""
        user_id = 1
        db = Mock()

        db.query.return_value.join.return_value.filter.return_value.order_by.return_value.all.return_value = []

        result = self.orch.analyze_correlation_opportunities(user_id, db)

        assert result == []

    def test_analyze_correlation_opportunities(self):
        """Test finding correlation analysis."""
        user_id = 1
        db = Mock()

        # Mock findings with different value hashes
        finding1 = Mock(spec=Finding)
        finding1.id = 1
        finding1.gist_id = 100
        finding1.value_hash = "hash1"
        finding1.secret_type = "aws_access_key"
        finding1.finding_type = "aws_key"
        finding1.file_path = "config/production.yaml"
        finding1.detected_at = datetime.now()
        finding1.severity = Mock(value='critical')

        finding2 = Mock(spec=Finding)
        finding2.id = 2
        finding2.gist_id = 200
        finding2.value_hash = "hash2"
        finding2.secret_type = "github_token"
        finding2.finding_type = "gh_token"
        finding2.file_path = "config/secrets.env"
        finding2.detected_at = datetime.now() - timedelta(days=1)
        finding2.severity = Mock(value='high')

        finding3 = Mock(spec=Finding)
        finding3.id = 3
        finding3.gist_id = 100
        finding3.value_hash = "hash1"  # Same as finding1 - should be correlated
        finding3.secret_type = "aws_access_key"
        finding3.finding_type = "aws_key"
        finding3.file_path = "docker-compose.yml"
        finding3.detected_at = datetime.now() - timedelta(days=2)
        finding3.severity = Mock(value='critical')

        # Mock gists
        gist1 = Mock(spec=Gist)
        gist1.id = 100
        gist1.description = "First gist"

        gist2 = Mock(spec=Gist)
        gist2.id = 200
        gist2.description = "Second gist"

        def mock_query(model):
            if model == Finding:
                q = Mock(name="finding_query")
                q.join.return_value.filter.return_value.order_by.return_value.all.return_value = [
                    finding1, finding2, finding3
                ]
                return q
            elif model == Gist:
                q = Mock(name="gist_query")
                q.filter.return_value.all.return_value = [gist1, gist2]
                return q
            return Mock(name="other_query")

        db.query.side_effect = mock_query

        # Mock internal analyzers to return predictable data
        self.orch.content_analyzer.analyze_file_path_patterns = Mock(
            return_value={"pattern_type": "none", "confidence": 0.0}
        )
        self.orch.temporal_analyzer.analyze_temporal_patterns = Mock(
            return_value={"distribution": {}, "peak_period": None, "spread_rate": 0.0}
        )

        result = self.orch.analyze_correlation_opportunities(user_id, db)

        assert len(result) == 2  # hash1 and hash2
        assert result[0]["finding_count"] == 2  # hash1 has findings 1 and 3
        assert result[0]["gist_count"] == 1  # both findings are in gist 100
        assert result[1]["finding_count"] == 1  # hash2 has finding 2

    def test_identify_correlation_patterns(self):
        """Test high-level pattern identification."""
        user_id = 1
        db = Mock()

        self.orch.analyze_correlation_opportunities = Mock(return_value=[
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
            {
                "value_hash": "hash3",
                "secret_type": "email",
                "finding_count": 1,
                "gist_count": 1,
                "max_severity": "low",
            },
        ])

        result = self.orch.identify_correlation_patterns(user_id, db)

        assert result["total_correlation_groups"] == 3
        assert result["total_related_findings"] == 8
        assert "patterns" in result
        assert "dominant_secret_types" in result["patterns"]
        assert "severity_distribution" in result["patterns"]
        assert "cross_gist_patterns" in result["patterns"]
        assert len(result["prioritization_risks"]) == 1  # only hash1 qualifies (5 findings, critical)

    def test_prioritization_risks_high_risk(self):
        """Test high-risk prioritization."""
        high_risk_group = {
            "value_hash": "hash1",
            "secret_type": "aws_access_key",
            "finding_count": 5,
            "gist_count": 3,
            "max_severity": "critical",
        }

        risk_level = self.orch._calculate_risk_level(high_risk_group)
        assert risk_level == "CRITICAL"

    def test_prioritization_risks_significant_risk(self):
        """Test significant-risk prioritization."""
        significant_risk_group = {
            "value_hash": "hash2",
            "secret_type": "github_token",
            "finding_count": 10,
            "gist_count": 1,
            "max_severity": "high",
        }

        risk_level = self.orch._calculate_risk_level(significant_risk_group)
        assert risk_level == "HIGH"

    def test_prioritization_risks_medium_risk(self):
        """Test medium-risk prioritization."""
        medium_risk_group = {
            "value_hash": "hash3",
            "secret_type": "api_key",
            "finding_count": 2,
            "gist_count": 2,
            "max_severity": "high",
        }

        risk_level = self.orch._calculate_risk_level(medium_risk_group)
        assert risk_level == "MEDIUM"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
