"""
Phase 3 API Endpoints Tests

Tests for correlation, triage, evidence_masker, and trufflehog_scanner API endpoints.
This version uses a more isolated approach to avoid complex import dependencies.
"""
import pytest
from unittest.mock import Mock, patch
from datetime import datetime
from sqlalchemy.orm import Session
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Import what we need for testing
from src.backend.api.v1.endpoints import gists


class TestCorrelationEndpoints:
    """Test correlation service API endpoints."""

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session."""
        return Mock(spec=Session)

    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user."""
        user = Mock()
        user.id = 1
        user.username = "testuser"
        user.is_active = True
        return user

    @pytest.fixture
    def auth_headers(self):
        """Create test authentication headers."""
        return {"Authorization": "Bearer test_token"}

    @pytest.fixture
    def mock_correlation_groups(self):
        """Create mock correlation groups for testing."""
        groups = []
        for i in range(3):
            group = Mock()
            group.value_hash = f"hash_{i}"
            group.finding_count = i + 1
            group.severity = Mock()
            group.severity.value = "high"
            group.secret_type = "api_key"
            group.gist_ids = [1, 2, 3]
            group.first_detected = datetime.now()
            group.last_detected = datetime.now()
            groups.append(group)
        return groups

    def test_get_correlations_success(self, mock_db_session, mock_user, auth_headers, mock_correlation_groups):
        """Test GET /correlations endpoint returns correlation groups."""
        with patch('src.backend.api.v1.endpoints.gists.get_current_active_user',
                   return_value=mock_user):
            with patch('src.backend.api.v1.endpoints.gists.get_db',
                       return_value=mock_db_session):
                with patch('src.backend.api.v1.endpoints.gists.FindingCorrelator') as mock_correlator:
                    mock_instance = Mock()
                    mock_instance.find_correlations.return_value = mock_correlation_groups
                    mock_correlator.return_value = mock_instance

                    # Call the endpoint directly with mocks
                    response = gists.get_correlations(current_user=mock_user, db=mock_db_session)

                    # Verify response
                    assert len(response) == 3
                    assert response[0].value_hash == "hash_0"
                    assert response[0].finding_count == 1
                    assert response[0].severity == "high"
                    assert response[0].secret_type == "api_key"
                    assert response[0].gist_ids == [1, 2, 3]

    def test_get_finding_correlations_success(
        self, mock_db_session, mock_user, auth_headers, mock_correlation_groups
    ):
        """Test GET /findings/{finding_id}/correlations endpoint."""
        with patch('src.backend.api.v1.endpoints.gists.get_current_active_user',
                   return_value=mock_user):
            with patch('src.backend.api.v1.endpoints.gists.get_db',
                       return_value=mock_db_session):
                with patch('src.backend.api.v1.endpoints.gists.FindingCorrelator') as mock_correlator:
                    mock_instance = Mock()
                    # Mock find_correlations to return our test data
                    mock_instance.find_correlations.return_value = mock_correlation_groups
                    # Track calls to find_correlations
                    mock_instance.find_correlations.user_id = 1
                    mock_correlator.return_value = mock_instance

                    # Create a sample finding
                    sample_finding = Mock()
                    sample_finding.id = 42
                    sample_finding.value_hash = "test_hash_42"
                    sample_finding.gist_id = 1

                    # Mock the database query for finding access check
                    mock_db_session.query.return_value.join.return_value.filter.return_value.filter.return_value.filter.return_value.first.return_value = sample_finding

                    # Get the endpoint function
                    endpoint = gists.get_finding_correlations

                    # Call the endpoint directly (sync function)
                    response = endpoint(finding_id=42, current_user=mock_user, db=mock_db_session)

                    # Verify response - should return all correlation groups since we have a valid finding
                    assert len(response) == 3
                    assert response[0].value_hash == "hash_0"
                    # Verify access control - finding belongs to user

    def test_get_correlation_insights_success(self, mock_db_session, mock_user, auth_headers):
        """Test GET /correlations/insights endpoint."""
        with patch('src.backend.api.v1.endpoints.gists.get_current_active_user',
                   return_value=mock_user):
            with patch('src.backend.api.v1.endpoints.gists.get_db',
                       return_value=mock_db_session):
                with patch('src.backend.api.v1.endpoints.gists.FindingCorrelator') as mock_correlator:
                    mock_instance = Mock()
                    mock_instance.identify_correlation_patterns.return_value = {
                        "total_related_findings": 15,
                        "patterns": {
                            "dominant_secret_types": {"api_key": 8},
                            "severity_distribution": {"critical": 3},
                        },
                        "cross_gist_patterns": {},
                    }
                    mock_correlator.return_value = mock_instance

                    # Get the endpoint function
                    endpoint = gists.get_correlation_insights

                    # Call the endpoint directly (sync function)
                    response = endpoint(current_user=mock_user, db=mock_db_session)

                    # Verify insights
                    assert response["total_correlated_findings"] == 15
                    assert response["active_correlation_campaigns"] == 15
                    assert response["dominant_secret_types"]["api_key"] == 8
                    assert response["risk_distribution"]["critical"] == 3


class TestTriageEndpoints:
    """Test triage service API endpoints."""

    @pytest.fixture
    def mock_db_session(self):
        return Mock(spec=Session)

    @pytest.fixture
    def mock_user(self):
        user = Mock()
        user.id = 1
        user.username = "testuser"
        user.is_active = True
        return user

    @pytest.fixture
    def auth_headers(self):
        return {"Authorization": "Bearer test_token"}

    @pytest.fixture
    def mock_findings(self):
        """Create mock findings for testing."""
        findings = []
        for i in range(3):
            finding = Mock()
            finding.id = i + 1
            finding.gist_id = 1
            finding.value_hash = f"hash_{i}"
            finding.masked_value = f"value_{i}"
            finding.secret_type = "api_key"
            finding.severity = Mock()
            finding.severity.value = "high"
            finding.confidence = 0.5 + (i * 0.1)
            finding.gist_file_id = 1
            finding.line_start = i + 1
            finding.status = Mock()
            finding.status.value = "new"
            findings.append(finding)
        return findings

    def test_triage_findings_success(
        self, mock_db_session, mock_user, auth_headers, mock_findings
    ):
        """Test POST /triage endpoint."""
        finding_ids = [f.id for f in mock_findings[:2]]

        with patch('src.backend.api.v1.endpoints.gists.get_current_active_user',
                   return_value=mock_user):
            with patch('src.backend.api.v1.endpoints.gists.get_db',
                       return_value=mock_db_session):
                with patch('src.backend.api.v1.endpoints.gists.triage_service') as mock_triage:
                    mock_triage.triage_batch.return_value = [
                        {"finding_id": finding_ids[0], "verdict": "escalate", "confidence": 0.6, "reason": "Test reason 1"},
                        {"finding_id": finding_ids[1], "verdict": "accept", "confidence": 0.55, "reason": "Test reason 2"},
                    ]

                    # Mock the db query chain for ownership verification
                    mock_db_session.query.return_value.join.return_value.filter.return_value.filter.return_value.all.return_value = [
                        Mock(id=finding_ids[0]), Mock(id=finding_ids[1])
                    ]

                    # Get the endpoint function
                    endpoint = gists.triage_findings_endpoint

                    # Call the endpoint and await the coroutine
                    import asyncio
                    response = asyncio.run(endpoint(
                        finding_ids=finding_ids,
                        current_user=mock_user,
                        db=mock_db_session
                    ))

                    # Verify triage results
                    assert response["findings_count"] == 2
                    assert len(response["triage_results"]) == 2
                    assert response["triage_results"][0]["verdict"] == "escalate"
                    assert response["triage_results"][1]["verdict"] == "accept"

    def test_get_triage_status_success(
        self, mock_db_session, mock_user, auth_headers
    ):
        """Test GET /triage/status endpoint."""
        with patch('src.backend.api.v1.endpoints.gists.get_current_active_user',
                   return_value=mock_user):
            with patch('src.backend.api.v1.endpoints.gists.get_db',
                       return_value=mock_db_session):

                # Mock database queries for status endpoint
                mock_gist = Mock()
                mock_gist.id = 1

                mock_findings = []

                for confidence in [0.3, 0.4, 0.6, 0.7, 0.8]:
                    finding = Mock()
                    finding.confidence = confidence
                    mock_findings.append(finding)

                # Mock the gist query for user verification
                mock_db_session.query.return_value.filter.return_value.all.return_value = [mock_gist]
                # Mock the findings query for status calculation
                mock_db_session.query.return_value.join.return_value.filter.return_value.all.return_value = mock_findings
                # Mock the borderline findings query
                mock_db_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = []

                # Get the endpoint function
                endpoint = gists.get_triage_status

                # Call the endpoint directly (sync function)
                response = endpoint(current_user=mock_user, db=mock_db_session)

                # Verify status response
                assert "pending_findings" in response
                assert "pending_by_confidence" in response
                assert "triage_thresholds" in response

    def test_update_triage_verdict_success(
        self, mock_db_session, mock_user, auth_headers
    ):
        """Test PUT /triage/findings/{finding_id} endpoint."""
        finding_id = 123
        verdict = "accept"

        with patch('src.backend.api.v1.endpoints.gists.get_current_active_user',
                   return_value=mock_user):
            with patch('src.backend.api.v1.endpoints.gists.get_db',
                       return_value=mock_db_session):
                # Mock finding for user verification
                mock_finding = Mock()
                mock_finding.id = finding_id
                mock_finding.status = Mock()
                mock_finding.status.value = "resolved"

                # Mock the database query for finding access check
                mock_db_session.query.return_value.join.return_value.filter.return_value.filter.return_value.first.return_value = mock_finding

                # Get the endpoint function
                endpoint = gists.update_triage_verdict

                # Call the endpoint and await the coroutine
                import asyncio
                response = asyncio.run(endpoint(
                    finding_id=finding_id,
                    verdict=verdict,
                    current_user=mock_user,
                    db=mock_db_session
                ))

                # Verify verdict update
                assert response["finding_id"] == finding_id
                assert response["verdict"] == verdict
                assert response["status"] == "accepted"
                assert "Finding" in response["message"]


class TestEvidenceMaskerEndpoints:
    """Test evidence masker service API endpoints."""

    @pytest.fixture
    def mock_db_session(self):
        return Mock(spec=Session)

    @pytest.fixture
    def mock_user(self):
        user = Mock()
        user.id = 1
        user.username = "testuser"
        user.is_active = True
        return user

    @pytest.fixture
    def auth_headers(self):
        return {"Authorization": "Bearer test_token"}

    @pytest.fixture
    def mock_finding(self):
        """Create a mock finding for evidence masking."""
        finding = Mock()
        finding.id = 1
        finding.gist_id = 1
        finding.value_hash = "test_hash_123"
        finding.masked_value = "original_value"
        finding.secret_type = "github_token"
        finding.severity = Mock()
        finding.severity.value = "critical"
        finding.confidence = 0.95
        finding.gist_file_id = 1
        return finding

    def test_mask_finding_evidence_success(
        self, mock_db_session, mock_user, auth_headers, mock_finding
    ):
        """Test POST /evidence/mask endpoint."""
        with patch('src.backend.api.v1.endpoints.gists.get_current_active_user',
                   return_value=mock_user):
            with patch('src.backend.api.v1.endpoints.gists.get_db',
                       return_value=mock_db_session):
                with patch('src.backend.api.v1.endpoints.gists.evidence_masker') as mock_masker:
                    # Mock the masked evidence result
                    mock_masked_result = Mock()
                    mock_masked_result.masked_value = "********"
                    mock_masked_result.context_masked = "****"
                    mock_masked_result.snippet = "***value***"
                    mock_masked_result.value_hash = "masked_hash_123"
                    mock_masked_result.secret_type = "github_token"
                    mock_masked_result.severity = "critical"
                    mock_masked_result.confidence = 0.95
                    mock_masker.create_masked_evidence.return_value = mock_masked_result

                    # Mock finding access check
                    mock_db_session.query.return_value.join.return_value.filter.return_value.filter.return_value.first.return_value = mock_finding

                    # Get the endpoint function
                    endpoint = gists.mask_finding_evidence

                    # Call the endpoint and await the coroutine
                    import asyncio
                    response = asyncio.run(endpoint(
                        finding_id=mock_finding.id,
                        current_user=mock_user,
                        db=mock_db_session
                    ))

                    # Verify masking results
                    assert response["finding_id"] == mock_finding.id
                    assert "masked_value" in response
                    assert "finding_id" in response
                    assert response["finding_id"] == 1


class TestTruffleHogEndpoints:
    """Test TruffleHog scanner API endpoints."""

    @pytest.fixture
    def mock_db_session(self):
        """Mock database session."""
        return Mock(spec=Session)

    @pytest.fixture
    def mock_user(self):
        user = Mock()
        user.id = 1
        user.username = "testuser"
        user.is_active = True
        return user

    @pytest.fixture
    def auth_headers(self):
        return {"Authorization": "Bearer test_token"}

    def test_start_trufflehog_scan_success(
        self, mock_db_session, mock_user, auth_headers
    ):
        """Test POST /trufflehog/scan endpoint."""
        github_account_id = 1

        with patch('src.backend.api.v1.endpoints.gists.get_current_active_user',
                   return_value=mock_user):
            with patch('src.backend.api.v1.endpoints.gists.TruffleHogScanner.is_available',
                       return_value=True):
                with patch('src.backend.api.v1.endpoints.gists.TruffleHogScanner') as mock_scanner_class:
                    # Mock scanner instance
                    mock_scanner = Mock()
                    mock_scanner_class.return_value = mock_scanner

                    # Mock GitHub account ownership query
                    mock_github_account = Mock()
                    mock_github_account.id = github_account_id
                    mock_db_session.query.return_value.filter.return_value.filter.return_value.first.return_value = mock_github_account

                    # Mock background task setup
                    with patch('src.backend.api.v1.endpoints.gists.BackgroundTasks') as mock_background_tasks:
                        mock_background_task = Mock()
                        mock_background_tasks.return_value.add_task = mock_background_task.add_task

                        # Get the endpoint function
                        endpoint = gists.start_trufflehog_scan_endpoint

                        # Call the endpoint and await the coroutine
                        import asyncio
                        response = asyncio.run(endpoint(
                            github_account_id=github_account_id,
                            background_tasks=Mock(),
                            current_user=mock_user,
                            db=mock_db_session
                        ))

                        # Verify scan initiated — endpoint returns dict, not response object
                        assert response["status"] == "started"
                        assert response["github_account_id"] == github_account_id
                        assert "message" in response

    def test_get_trufflehog_status_success(self, mock_db_session, mock_user, auth_headers):
        """Test GET /trufflehog/status endpoint."""
        with patch('src.backend.api.v1.endpoints.gists.get_current_active_user',
                   return_value=mock_user):
            with patch('src.backend.api.v1.endpoints.gists.TruffleHogScanner.get_status',
                       return_value=Mock(
                           available=True,
                           scanner_path="/usr/local/bin/trufflehog",
                           capabilities=["s3", "github"],
                       )):

                # Get the endpoint function
                endpoint = gists.get_trufflehog_status_endpoint

                # Call the endpoint and await the coroutine
                import asyncio
                response = asyncio.run(endpoint(current_user=mock_user))

                # Verify status
                assert response["available"] is True
                assert "scanner_path" in response
                assert "capabilities" in response
                assert isinstance(response["capabilities"], list)


# Custom test runner for the current environment
if __name__ == "__main__":
    # This allows running specific tests or the full suite
    pytest.main([__file__, "-v"])
