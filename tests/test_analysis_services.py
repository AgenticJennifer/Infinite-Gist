"""Focused unit tests for finding correlation and temporal analysis services."""

from datetime import datetime, timedelta
from types import SimpleNamespace

from src.backend.db.models import Finding, Gist
from src.backend.services.finding_correlator import FindingCorrelator
from src.backend.services.temporal_analyzer import TemporalAnalyzer


class QueryStub:
    """Minimal SQLAlchemy query double that records scoping expressions."""

    def __init__(self, session, model):
        self.session = session
        self.model = model

    def join(self, *args):
        self.session.joins.append((self.model, args))
        return self

    def filter(self, *criteria):
        self.session.filters.append((self.model, criteria))
        return self

    def order_by(self, *args):
        return self

    def all(self):
        return list(self.session.results.get(self.model, []))

    def first(self):
        values = self.session.first_results.get(self.model)
        if values is not None:
            return values.pop(0) if values else None
        results = self.session.results.get(self.model, [])
        return results[0] if results else None


class SessionStub:
    def __init__(self, *, findings=(), gists=(), first_findings=None):
        self.results = {Finding: list(findings), Gist: list(gists)}
        self.first_results = {}
        if first_findings is not None:
            self.first_results[Finding] = list(first_findings)
        self.filters = []
        self.joins = []

    def query(self, model):
        return QueryStub(self, model)


def enum_value(value):
    return SimpleNamespace(value=value)


def finding(
    finding_id,
    gist_id,
    value_hash,
    detected_at,
    *,
    severity="low",
    status="new",
    revision_id=None,
    secret_type="api_key",
):
    return SimpleNamespace(
        id=finding_id,
        gist_id=gist_id,
        value_hash=value_hash,
        detected_at=detected_at,
        severity=enum_value(severity),
        status=enum_value(status),
        gist_revision_id=revision_id,
        secret_type=secret_type,
        finding_type=secret_type,
        masked_value="ab****yz",
        confidence=90,
        file_path="config.env",
        line_start=finding_id,
    )


def filter_text(session, model):
    return " ".join(
        str(criterion)
        for filtered_model, criteria in session.filters
        if filtered_model is model
        for criterion in criteria
    )


def test_correlator_groups_hashes_tracks_dates_and_uses_explicit_session():
    older = datetime(2025, 1, 2, 8, 30)
    newer = datetime(2025, 1, 5, 17, 45)
    findings = [
        finding(2, 20, "shared", newer, severity="critical", secret_type="token"),
        finding(1, 10, "shared", older, severity="medium", secret_type="token"),
        finding(3, 10, "solo", newer, severity="high"),
        finding(4, 10, None, newer),
    ]
    session = SessionStub(
        findings=findings,
        gists=[
            SimpleNamespace(id=10, description="first"),
            SimpleNamespace(id=20, description="second"),
        ],
    )

    # Passing db explicitly must override the unusable constructor session.
    groups = FindingCorrelator(db=object()).correlate_user_findings(42, db=session)

    assert [group.value_hash for group in groups] == ["shared", "solo"]
    shared = groups[0]
    assert shared.finding_ids == [2, 1]
    assert shared.gist_ids == [20, 10]
    assert shared.gist_descriptions == {20: "second", 10: "first"}
    assert shared.max_severity == "critical"
    assert shared.first_seen == older
    assert shared.last_seen == newer
    assert shared.to_dict()["first_seen"] == "2025-01-02T08:30:00"
    assert "gists.user_id" in filter_text(session, Finding)
    assert any(model is Finding for model, _ in session.joins)


def test_correlator_scopes_target_lookup_and_correlations_to_user():
    target = finding(7, 10, "shared", datetime(2025, 2, 1))
    session = SessionStub(
        findings=[target, finding(8, 20, "shared", datetime(2025, 2, 2))],
        gists=[SimpleNamespace(id=10, description="a"), SimpleNamespace(id=20, description="b")],
        first_findings=[target],
    )

    groups = FindingCorrelator().find_correlations(99, finding_id=7, db=session)

    assert len(groups) == 1
    assert groups[0].finding_ids == [7, 8]
    scopes = filter_text(session, Finding)
    # Both the target lookup and subsequent same-hash query retain user scope.
    assert scopes.count("gists.user_id") == 2
    assert "findings.id" in scopes
    assert "findings.value_hash" in scopes


def test_temporal_history_tracks_dates_persistence_and_single_re_exposure():
    first = datetime(2025, 3, 1, 9)
    fixed = datetime(2025, 3, 2, 9)
    re_exposed = datetime(2025, 3, 4, 11)
    findings = [
        finding(1, 10, "secret", first, severity="high", revision_id=101),
        finding(2, 10, "secret", fixed, status="fixed", revision_id=102),
        finding(3, 10, "secret", re_exposed, severity="critical", revision_id=103),
        finding(4, 20, "other-gist", re_exposed, revision_id=201),
    ]
    session = SessionStub(findings=findings)

    analysis = TemporalAnalyzer().analyze_gist_history(10, session)

    assert analysis.first_seen == {"secret": first, "other-gist": re_exposed}
    assert analysis.last_seen["secret"] == re_exposed
    assert analysis.persistence_counts == {"secret": 3, "other-gist": 1}
    assert analysis.re_exposures == [{
        "value_hash": "secret",
        "original_fixed_at": "2025-03-02T09:00:00",
        "re_exposed_at": "2025-03-04T11:00:00",
        "finding_id": 3,
        "severity": "critical",
    }]
    assert [event.event_type for event in analysis.events].count("re_exposed") == 1
    assert "findings.gist_id" in filter_text(session, Finding)


def test_user_posture_is_user_scoped_groups_dates_and_detects_worsening_trend():
    start = datetime(2025, 4, 1, 12)
    findings = []
    finding_id = 1
    for day in range(14):
        daily_count = 1 if day < 7 else 2
        for _ in range(daily_count):
            findings.append(
                finding(
                    finding_id,
                    10,
                    f"hash-{finding_id}",
                    start + timedelta(days=day),
                    severity="high" if day >= 7 else "low",
                )
            )
            finding_id += 1

    session = SessionStub(
        gists=[SimpleNamespace(id=10, user_id=5), SimpleNamespace(id=11, user_id=5)],
        findings=findings,
    )

    posture = TemporalAnalyzer().analyze_user_posture(5, session)

    assert posture["gists_count"] == 2
    assert posture["total_findings"] == 21
    assert posture["findings_by_date"]["2025-04-01"] == 1
    assert posture["findings_by_date"]["2025-04-14"] == 2
    assert posture["severity_counts"] == {"low": 7, "high": 14}
    assert posture["findings_trend"] == "worsening"
    assert "gists.user_id" in filter_text(session, Gist)
    assert "findings.gist_id" in filter_text(session, Finding)
