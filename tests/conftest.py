"""Test fixtures for Phase 3 API endpoints testing."""
import sys
import os

# Add the parent directory to the path so imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from fastapi import FastAPI
from sqlalchemy.orm import Session

# Import the actual app
from src.backend.main import app

# Create a proper test environment
import pytest

# Mock database session
@pytest.fixture
def mock_db():
    return Mock(spec=Session)

# Mock user for authentication
@pytest.fixture
def mock_user():
    user = Mock()
    user.id = 1
    user.username = "testuser"
    user.is_active = True
    return user

# Mock auth headers
@pytest.fixture
def auth_headers(mock_user):
    return {"Authorization": "Bearer test_token"}

# Mock test client
@pytest.fixture
def client():
    return TestClient(app)

# Mock correlation analyzer
@pytest.fixture
def mock_correlation_analyzer():
    with patch('src.backend.api.v1.endpoints.gists.correlation_analyzer') as mock:
        yield mock

# Mock triage service
@pytest.fixture
def mock_triage_service():
    with patch('src.backend.api.v1.endpoints.gists.triage_service') as mock:
        yield mock

# Mock evidence masker
@pytest.fixture
def mock_evidence_masker():
    with patch('src.backend.api.v1.endpoints.gists.evidence_masker') as mock:
        yield mock

# Mock trufflehog scanner
@pytest.fixture
def mock_trufflehog_scanner():
    with patch('src.backend.api.v1.endpoints.gists.TruffleHogScanner') as mock:
        yield mock

# Mock finding models
@pytest.fixture
def mock_finding():
    finding = Mock()
    finding.id = 1
    finding.gist_id = 1
    finding.value_hash = "abc123"
    finding.masked_value = "test_value"
    finding.secret_type = "api_key"
    finding.severity = Mock()
    finding.severity.value = "high"
    finding.confidence = 0.9
    finding.gist_file_id = 1
    finding.line_start = 1
    finding.status = Mock()
    finding.status.value = "new"
    return finding

# Mock findings for batch operations
@pytest.fixture
def mock_findings():
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
        finding.line_start = 1
        finding.status = Mock()
        finding.status.value = "new"
        findings.append(finding)
    return findings

# Mock github account
@pytest.fixture
def mock_github_account():
    account = Mock()
    account.id = 1
    account.user_id = 1
    account.username = "testuser"
    account.token = "test_token"
    return account

# Mock scan result
@pytest.fixture
def mock_scan_result():
    scan = Mock()
    scan.id = 1
    scan.gist_id = 1
    scan.scan_type = "full"
    scan.status = "completed"
    scan.started_at = "2024-01-01T00:00:00"
    scan.completed_at = "2024-01-01T01:00:00"
    scan.secrets_found = 5
    scan.files_scanned = 10
    scan.error_message = None
    return scan

# Mock temporal analysis
@pytest.fixture
def mock_temporal_analysis():
    analysis = Mock()
    analysis.gist_id = 1
    analysis.total_events = 10
    analysis.re_exposure_count = 2
    analysis.persistence_count = 3
    analysis.posture_trend = "stable"
    analysis.first_detected = "2024-01-01T00:00:00"
    analysis.last_detected = "2024-01-02T00:00:00"
    
    # Mock events
    events = []
    for i in range(5):
        event = Mock()
        event.timestamp = f"2024-01-0{i+1}T00:0{i+1}:00"
        event.event_type = "scan"
        event.gist_id = 1
        event.finding_id = i + 1
        event.details = f"Scan event {i+1}"
        events.append(event)
    analysis.events = events
    return analysis

# Mock finding correlator
@pytest.fixture
def mock_finding_correlator():
    with patch('src.backend.api.v1.endpoints.gists.FindingCorrelator') as mock:
        yield mock

# Mock temporal analyzer
@pytest.fixture
def mock_temporal_analyzer():
    with patch('src.backend.api.v1.endpoints.gists.TemporalAnalyzer') as mock:
        yield mock

# Mock secret match for correlation tests
@pytest.fixture
def mock_secret_match():
    match = Mock()
    match.id = 1
    match.secret_type = "api_key"
    match.value = "***masked_value***"
    match.file_path = "/test/file.py"
    match.line_number = 42
    match.column_start = 0
    match.column_end = 20
    match.confidence = 0.95
    match.matched_text = "API_KEY"
    match.context = "http://example.com/api?key="
    match.gist_file_id = 1
    match.scan_id = 1
    return match