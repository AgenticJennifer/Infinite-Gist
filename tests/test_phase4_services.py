"""
Phase 4 Continuous Operation Service Tests
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, date, timedelta
from sqlalchemy.orm import Session

from src.backend.db.models import (
    ScanSchedule,
    AccountPolicy,
    SecurityTrend,
    DigestReport,
    Finding,
)
from src.backend.services.scheduler_service import SchedulerService
from src.backend.services.scan_executor import ScanExecutor
from src.backend.services.digest_service import DigestService
from src.backend.services.policy_service import PolicyService
from src.backend.services.trend_service import TrendService
from src.backend.services.auto_remediation_service import AutoRemediationService
from src.backend.services.audit_service import AuditService
from src.backend.services.remediation_service import RemediationService


@pytest.fixture
def mock_db():
    return Mock(spec=Session)


@pytest.fixture
def mock_schedule():
    schedule = Mock(spec=ScanSchedule)
    schedule.id = 1
    schedule.user_id = 1
    schedule.github_account_id = 1
    schedule.frequency = "daily"
    schedule.cron_expression = None
    schedule.enabled = True
    schedule.last_run_at = None
    schedule.next_run_at = datetime.utcnow() + timedelta(days=1)
    schedule.created_at = datetime.utcnow()
    schedule.updated_at = datetime.utcnow()
    return schedule


@pytest.fixture
def mock_policy():
    policy = Mock(spec=AccountPolicy)
    policy.id = 1
    policy.user_id = 1
    policy.auto_remediate = False
    policy.auto_remediate_types = "[]"
    policy.notify_on_scan = True
    policy.notify_on_finding = True
    policy.digest_frequency = "weekly"
    return policy


@pytest.fixture
def mock_finding():
    finding = Mock(spec=Finding)
    finding.id = 1
    finding.finding_type = "aws_key"
    finding.secret_type = "aws_access_key"
    return finding


@pytest.fixture
def mock_trend():
    trend = Mock(spec=SecurityTrend)
    trend.id = 1
    trend.user_id = 1
    trend.date = date.today()
    trend.total_findings = 5
    trend.critical_findings = 1
    trend.high_findings = 2
    trend.medium_findings = 1
    trend.low_findings = 1
    trend.gists_scanned = 10
    trend.remediated_count = 3
    trend.created_at = datetime.utcnow()
    return trend


class TestSchedulerService:

    def test_create_schedule(self, mock_db, mock_schedule):
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock(side_effect=lambda x: setattr(x, 'id', 1))

        with patch.object(AuditService, 'log_event', new_callable=AsyncMock):
            service = SchedulerService(mock_db)
            asyncio.run(service.create_schedule(
                user_id=1,
                github_account_id=1,
                frequency="daily",
            ))

            mock_db.add.assert_called_once()
            mock_db.commit.assert_called_once()

    def test_create_schedule_sets_next_run_at(self, mock_db):
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        with patch.object(AuditService, 'log_event', new_callable=AsyncMock):
            service = SchedulerService(mock_db)
            schedule = asyncio.run(service.create_schedule(
                user_id=1,
                github_account_id=1,
                frequency="daily",
            ))

            # next_run_at should be approximately 1 day from now
            assert schedule.next_run_at is not None

    def test_create_schedule_weekly(self, mock_db):
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        with patch.object(AuditService, 'log_event', new_callable=AsyncMock):
            service = SchedulerService(mock_db)
            schedule = asyncio.run(service.create_schedule(
                user_id=1,
                github_account_id=1,
                frequency="weekly",
            ))

            assert schedule.frequency == "weekly"
            assert schedule.next_run_at is not None

    def test_get_due_schedules(self, mock_db, mock_schedule):
        mock_schedule.next_run_at = datetime.utcnow() - timedelta(hours=1)
        mock_db.query.return_value.filter.return_value.all.return_value = [mock_schedule]

        service = SchedulerService(mock_db)
        result = asyncio.run(service.get_due_schedules())

        assert len(result) == 1
        assert result[0] == mock_schedule

    def test_get_due_schedules_empty(self, mock_db):
        mock_db.query.return_value.filter.return_value.all.return_value = []

        service = SchedulerService(mock_db)
        result = asyncio.run(service.get_due_schedules())

        assert result == []

    def test_mark_schedule_run(self, mock_db, mock_schedule):
        mock_db.query.return_value.filter.return_value.first.return_value = mock_schedule
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        service = SchedulerService(mock_db)
        result = asyncio.run(service.mark_schedule_run(1))

        assert result.last_run_at is not None
        assert result.next_run_at is not None
        mock_db.commit.assert_called_once()

    def test_mark_schedule_run_not_found(self, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None

        service = SchedulerService(mock_db)

        with pytest.raises(ValueError, match="Schedule 999 not found"):
            asyncio.run(service.mark_schedule_run(999))

    def test_update_schedule(self, mock_db, mock_schedule):
        mock_db.query.return_value.filter.return_value.first.return_value = mock_schedule
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        with patch.object(AuditService, 'log_event', new_callable=AsyncMock):
            service = SchedulerService(mock_db)
            asyncio.run(service.update_schedule(1, enabled=False))

            assert mock_schedule.enabled is False
            mock_db.commit.assert_called_once()

    def test_update_schedule_not_found(self, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None

        service = SchedulerService(mock_db)

        with pytest.raises(ValueError, match="Schedule 999 not found"):
            asyncio.run(service.update_schedule(999, frequency="weekly"))

    def test_update_schedule_recalculates_next_run(self, mock_db, mock_schedule):
        mock_db.query.return_value.filter.return_value.first.return_value = mock_schedule
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        with patch.object(AuditService, 'log_event', new_callable=AsyncMock):
            service = SchedulerService(mock_db)
            asyncio.run(service.update_schedule(1, frequency="weekly"))

            assert mock_schedule.frequency == "weekly"
            # next_run_at should have been recalculated
            assert mock_schedule.next_run_at is not None

    def test_delete_schedule(self, mock_db, mock_schedule):
        mock_db.query.return_value.filter.return_value.first.return_value = mock_schedule
        mock_db.delete = Mock()
        mock_db.commit = Mock()

        service = SchedulerService(mock_db)
        result = asyncio.run(service.delete_schedule(1))

        assert result is True
        mock_db.delete.assert_called_once_with(mock_schedule)

    def test_delete_schedule_not_found(self, mock_db):
        mock_db.query.return_value.filter.return_value.first.return_value = None

        service = SchedulerService(mock_db)
        result = asyncio.run(service.delete_schedule(999))

        assert result is False

    def test_get_user_schedules(self, mock_db, mock_schedule):
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [mock_schedule]

        service = SchedulerService(mock_db)
        result = asyncio.run(service.get_user_schedules(1))

        assert len(result) == 1

    def test_calculate_next_run_daily(self, mock_db):
        service = SchedulerService(mock_db)
        next_run = service._calculate_next_run("daily")
        assert next_run is not None
        assert next_run > datetime.utcnow()

    def test_calculate_next_run_weekly(self, mock_db):
        service = SchedulerService(mock_db)
        next_run = service._calculate_next_run("weekly")
        assert next_run is not None

    def test_calculate_next_run_custom(self, mock_db):
        service = SchedulerService(mock_db)
        next_run = service._calculate_next_run("custom")
        assert next_run is not None


class TestScanExecutor:

    def test_execute_scheduled_scan(self, mock_db, mock_schedule):
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        with patch.object(SchedulerService, 'mark_schedule_run', new_callable=AsyncMock):
            service = ScanExecutor(mock_db)
            result = asyncio.run(service.execute_scheduled_scan(mock_schedule))

            mock_db.add.assert_called_once()
            mock_db.commit.assert_called_once()
            assert result.status == "completed"

    def test_execute_all_due_scans(self, mock_db, mock_schedule):
        with patch.object(SchedulerService, 'get_due_schedules', new_callable=AsyncMock, return_value=[mock_schedule]):
            with patch.object(ScanExecutor, 'execute_scheduled_scan', new_callable=AsyncMock) as mock_exec:
                mock_scan_run = Mock()
                mock_scan_run.id = 1
                mock_scan_run.status = "completed"
                mock_exec.return_value = mock_scan_run

                service = ScanExecutor(mock_db)
                results = asyncio.run(service.execute_all_due_scans())

                assert len(results) == 1

    def test_execute_all_due_scans_with_failure(self, mock_db, mock_schedule):
        schedule2 = Mock()
        schedule2.id = 2
        schedule2.user_id = 1

        with patch.object(SchedulerService, 'get_due_schedules', new_callable=AsyncMock, return_value=[mock_schedule, schedule2]):
            call_count = 0

            async def mock_execute(schedule):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return Mock(id=1, status="completed")
                else:
                    raise Exception("Scan failed")

            with patch.object(ScanExecutor, 'execute_scheduled_scan', side_effect=mock_execute):
                mock_db.add = Mock()
                mock_db.commit = Mock()
                mock_db.refresh = Mock()
                service = ScanExecutor(mock_db)
                results = asyncio.run(service.execute_all_due_scans())

                # First succeeded, second failed — should get 1 result
                assert len(results) == 1

    def test_execute_all_due_scans_empty(self, mock_db):
        with patch.object(SchedulerService, 'get_due_schedules', new_callable=AsyncMock, return_value=[]):
            service = ScanExecutor(mock_db)
            results = asyncio.run(service.execute_all_due_scans())

            assert results == []

    def test_run_scan_for_account(self, mock_db):
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        service = ScanExecutor(mock_db)
        result = asyncio.run(service.run_scan_for_account(1, user_id=1))

        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
        assert result.status == "completed"


class TestDigestService:

    def test_generate_daily_digest(self, mock_db):
        # Mock query chains for counts
        mock_db.query.return_value.filter.return_value.count.return_value = 3
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        service = DigestService(mock_db)
        result = asyncio.run(service.generate_daily_digest(user_id=1))

        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
        assert result.report_type == "daily"

    def test_generate_weekly_digest(self, mock_db):
        mock_db.query.return_value.filter.return_value.count.return_value = 5
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        service = DigestService(mock_db)
        result = asyncio.run(service.generate_weekly_digest(user_id=1))

        assert result.report_type == "weekly"
        mock_db.add.assert_called_once()

    def test_send_digest(self, mock_db):
        report = Mock(spec=DigestReport)
        report.report_type = "daily"
        report.period_start = datetime.utcnow() - timedelta(days=1)
        report.period_end = datetime.utcnow()
        report.summary = '{"new_findings": 3}'

        with patch.object(DigestService, '__init__', lambda self, db: None):
            service = DigestService.__new__(DigestService)
            service.db = mock_db
            service.notification_service = Mock()
            service.notification_service.send_email = AsyncMock(return_value=True)

            result = asyncio.run(service.send_digest(report, "test@example.com"))

            assert result is True
            service.notification_service.send_email.assert_called_once()

    def test_get_user_digests(self, mock_db):
        mock_report = Mock(spec=DigestReport)
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [mock_report]

        service = DigestService(mock_db)
        result = asyncio.run(service.get_user_digests(user_id=1))

        assert len(result) == 1


class TestPolicyService:

    def test_get_user_policy_existing(self, mock_db, mock_policy):
        mock_db.query.return_value.filter.return_value.first.return_value = mock_policy

        service = PolicyService(mock_db)
        result = asyncio.run(service.get_user_policy(1))

        assert result == mock_policy
        assert result.auto_remediate is False

    def test_get_user_policy_creates_default(self, mock_db):
        # No existing policy
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        service = PolicyService(mock_db)
        asyncio.run(service.get_user_policy(1))

        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    def test_update_policy(self, mock_db, mock_policy):
        mock_db.query.return_value.filter.return_value.first.return_value = mock_policy
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        service = PolicyService(mock_db)
        asyncio.run(service.update_policy(1, auto_remediate=True))

        assert mock_policy.auto_remediate is True
        mock_db.commit.assert_called_once()

    def test_should_auto_remediate_disabled(self, mock_db, mock_policy):
        mock_policy.auto_remediate = False
        mock_db.query.return_value.filter.return_value.first.return_value = mock_policy

        service = PolicyService(mock_db)
        result = asyncio.run(service.should_auto_remediate(1, "aws_key"))

        assert result is False

    def test_should_auto_remediate_enabled_empty_types(self, mock_db, mock_policy):
        mock_policy.auto_remediate = True
        mock_policy.auto_remediate_types = "[]"
        mock_db.query.return_value.filter.return_value.first.return_value = mock_policy

        service = PolicyService(mock_db)
        result = asyncio.run(service.should_auto_remediate(1, "aws_key"))

        # Empty list means all types allowed
        assert result is True

    def test_should_auto_remediate_enabled_matching_type(self, mock_db, mock_policy):
        mock_policy.auto_remediate = True
        mock_policy.auto_remediate_types = '["aws_key", "private_key"]'
        mock_db.query.return_value.filter.return_value.first.return_value = mock_policy

        service = PolicyService(mock_db)
        result = asyncio.run(service.should_auto_remediate(1, "aws_key"))

        assert result is True

    def test_should_auto_remediate_enabled_non_matching_type(self, mock_db, mock_policy):
        mock_policy.auto_remediate = True
        mock_policy.auto_remediate_types = '["aws_key"]'
        mock_db.query.return_value.filter.return_value.first.return_value = mock_policy

        service = PolicyService(mock_db)
        result = asyncio.run(service.should_auto_remediate(1, "password"))

        assert result is False

    def test_should_notify_scan(self, mock_db, mock_policy):
        mock_policy.notify_on_scan = True
        mock_db.query.return_value.filter.return_value.first.return_value = mock_policy

        service = PolicyService(mock_db)
        result = asyncio.run(service.should_notify(1, "scan"))

        assert result is True

    def test_should_notify_finding_disabled(self, mock_db, mock_policy):
        mock_policy.notify_on_finding = False
        mock_db.query.return_value.filter.return_value.first.return_value = mock_policy

        service = PolicyService(mock_db)
        result = asyncio.run(service.should_notify(1, "finding"))

        assert result is False


class TestTrendService:

    def test_record_daily_snapshot(self, mock_db):
        # Mock the count queries
        mock_db.query.return_value.filter.return_value.count.return_value = 5
        mock_db.add = Mock()
        mock_db.commit = Mock()
        mock_db.refresh = Mock()

        service = TrendService(mock_db)
        asyncio.run(service.record_daily_snapshot(user_id=1))

        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    def test_get_trends(self, mock_db, mock_trend):
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [mock_trend]

        service = TrendService(mock_db)
        result = asyncio.run(service.get_trends(user_id=1, days=30))

        assert len(result) == 1

    def test_get_posture_summary_with_data(self, mock_db, mock_trend):
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [mock_trend]

        service = TrendService(mock_db)
        with patch.object(TrendService, 'calculate_trend_direction', new_callable=AsyncMock, return_value="improving"):
            result = asyncio.run(service.get_posture_summary(user_id=1))

            assert result["current_total"] == 5
            assert result["direction"] == "improving"

    def test_get_posture_summary_empty(self, mock_db):
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []

        service = TrendService(mock_db)
        with patch.object(TrendService, 'calculate_trend_direction', new_callable=AsyncMock, return_value="stable"):
            result = asyncio.run(service.get_posture_summary(user_id=1))

            assert result["current_total"] == 0
            assert result["direction"] == "stable"

    def test_calculate_trend_direction_improving(self, mock_db):
        # Recent: fewer findings → improving
        recent_trends = [Mock(total_findings=2), Mock(total_findings=3)]
        older_trends = [Mock(total_findings=8), Mock(total_findings=10)]

        mock_db.query.return_value.filter.return_value.all.side_effect = [
            recent_trends, older_trends
        ]

        service = TrendService(mock_db)
        result = asyncio.run(service.calculate_trend_direction(user_id=1))

        assert result == "improving"

    def test_calculate_trend_direction_degrading(self, mock_db):
        # Recent: more findings → degrading
        recent_trends = [Mock(total_findings=10), Mock(total_findings=12)]
        older_trends = [Mock(total_findings=2), Mock(total_findings=3)]

        mock_db.query.return_value.filter.return_value.all.side_effect = [
            recent_trends, older_trends
        ]

        service = TrendService(mock_db)
        result = asyncio.run(service.calculate_trend_direction(user_id=1))

        assert result == "degrading"

    def test_calculate_trend_direction_stable(self, mock_db):
        # Recent and older have similar averages
        recent_trends = [Mock(total_findings=5), Mock(total_findings=5)]
        older_trends = [Mock(total_findings=5), Mock(total_findings=5)]

        mock_db.query.return_value.filter.return_value.all.side_effect = [
            recent_trends, older_trends
        ]

        service = TrendService(mock_db)
        result = asyncio.run(service.calculate_trend_direction(user_id=1))

        assert result == "stable"

    def test_calculate_trend_direction_no_data(self, mock_db):
        mock_db.query.return_value.filter.return_value.all.return_value = []

        service = TrendService(mock_db)
        result = asyncio.run(service.calculate_trend_direction(user_id=1))

        assert result == "stable"


class TestAutoRemediationService:

    def test_check_and_remediate_allowed(self, mock_db, mock_finding):
        mock_action = Mock()
        mock_action.id = 1
        mock_action.status = "completed"

        with patch.object(PolicyService, 'should_auto_remediate', new_callable=AsyncMock, return_value=True):
            with patch.object(RemediationService, 'make_private', new_callable=AsyncMock, return_value=mock_action):
                with patch.object(AuditService, 'log_event', new_callable=AsyncMock):
                    service = AutoRemediationService(mock_db)
                    result = asyncio.run(service.check_and_remediate(mock_finding, user_id=1))

                    assert result == mock_action

    def test_check_and_remediate_denied(self, mock_db, mock_finding):
        with patch.object(PolicyService, 'should_auto_remediate', new_callable=AsyncMock, return_value=False):
            service = AutoRemediationService(mock_db)
            result = asyncio.run(service.check_and_remediate(mock_finding, user_id=1))

            assert result is None

    def test_check_and_remediate_exception(self, mock_db, mock_finding):
        with patch.object(PolicyService, 'should_auto_remediate', new_callable=AsyncMock, return_value=True):
            with patch.object(RemediationService, 'make_private', new_callable=AsyncMock, side_effect=Exception("API error")):
                with patch.object(AuditService, 'log_event', new_callable=AsyncMock):
                    service = AutoRemediationService(mock_db)
                    result = asyncio.run(service.check_and_remediate(mock_finding, user_id=1))

                    assert result is None

    def test_batch_check_and_remediate(self, mock_db, mock_finding):
        finding2 = Mock(spec=Finding)
        finding2.id = 2
        finding2.finding_type = "password"
        finding2.secret_type = "hardcoded_password"

        mock_action = Mock()
        mock_action.id = 1
        mock_action.status = "completed"

        with patch.object(AutoRemediationService, 'check_and_remediate', new_callable=AsyncMock) as mock_check:
            async def side_effect(finding, user_id):
                if finding.id == 1:
                    return mock_action
                return None

            mock_check.side_effect = side_effect

            service = AutoRemediationService(mock_db)
            result = asyncio.run(service.batch_check_and_remediate([mock_finding, finding2], user_id=1))

            # Only first finding was auto-remediated
            assert len(result) == 1
            assert result[0][0] == mock_finding
            assert result[0][1] == mock_action
