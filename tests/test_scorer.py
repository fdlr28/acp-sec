"""Unit tests for the scoring engine."""

import pytest

from acpsec.models import CheckResult, CheckStatus, DimensionResult, Severity
from acpsec.scorer import ScoringEngine, make_check, CRITICAL_PENALTY


def _passing_check(check_id: str, max_score: float = 3.0, severity: Severity = Severity.MEDIUM) -> CheckResult:
    return make_check(
        check_id=check_id,
        name=f"Check {check_id}",
        dimension="TEST",
        severity=severity,
        max_score=max_score,
        passed=True,
    )


def _failing_check(check_id: str, max_score: float = 3.0, severity: Severity = Severity.MEDIUM) -> CheckResult:
    return make_check(
        check_id=check_id,
        name=f"Check {check_id}",
        dimension="TEST",
        severity=severity,
        max_score=max_score,
        passed=False,
    )


class TestMakeCheck:
    def test_passing_check_has_full_score(self):
        c = _passing_check("T-01", max_score=5.0)
        assert c.score == 5.0
        assert c.status == CheckStatus.PASS
        assert c.passed

    def test_failing_check_has_zero_score(self):
        c = _failing_check("T-01", max_score=5.0)
        assert c.score == 0.0
        assert c.status == CheckStatus.FAIL
        assert not c.passed

    def test_partial_score_sets_warn_status(self):
        c = make_check(
            check_id="T-01",
            name="Partial",
            dimension="TEST",
            severity=Severity.MEDIUM,
            max_score=4.0,
            passed=False,
            partial_score=2.0,
        )
        assert c.score == 2.0
        assert c.status == CheckStatus.WARN

    def test_zero_partial_score_is_fail(self):
        c = make_check(
            check_id="T-01",
            name="Partial zero",
            dimension="TEST",
            severity=Severity.MEDIUM,
            max_score=4.0,
            passed=False,
            partial_score=0.0,
        )
        assert c.status == CheckStatus.FAIL

    def test_score_pct(self):
        c = make_check(
            check_id="T-01",
            name="Pct",
            dimension="TEST",
            severity=Severity.LOW,
            max_score=4.0,
            passed=False,
            partial_score=2.0,
        )
        assert c.score_pct == 50.0


class TestScoringEngine:
    def setup_method(self):
        self.engine = ScoringEngine()

    def test_all_passing_scores_max(self):
        checks = [_passing_check(f"T-{i:02d}", max_score=5.0) for i in range(4)]
        assert self.engine.score_dimension(checks) == 20.0

    def test_band_secure(self):
        band, verdict = self.engine.band(95.0)
        assert band == "SECURE"

    def test_band_compromised(self):
        band, verdict = self.engine.band(10.0)
        assert band == "COMPROMISED"

    def test_band_boundaries(self):
        assert self.engine.band(90.0)[0] == "SECURE"
        assert self.engine.band(89.9)[0] == "HARDENED"
        assert self.engine.band(70.0)[0] == "HARDENED"
        assert self.engine.band(69.9)[0] == "VULNERABLE"
        assert self.engine.band(50.0)[0] == "VULNERABLE"
        assert self.engine.band(49.9)[0] == "CRITICAL"
        assert self.engine.band(30.0)[0] == "CRITICAL"
        assert self.engine.band(29.9)[0] == "COMPROMISED"

    def test_critical_penalty_applied(self):
        checks = [
            _passing_check("T-01", max_score=50.0),
            _failing_check("T-02", max_score=50.0, severity=Severity.CRITICAL),
        ]
        raw = 50.0
        penalized = self.engine.apply_penalties(raw, checks)
        assert penalized == raw - CRITICAL_PENALTY

    def test_penalty_does_not_go_below_zero(self):
        checks = [
            _failing_check(f"T-{i:02d}", severity=Severity.CRITICAL)
            for i in range(20)
        ]
        penalized = self.engine.apply_penalties(0.0, checks)
        assert penalized == 0.0

    def test_no_penalty_for_passing_critical(self):
        checks = [_passing_check("T-01", severity=Severity.CRITICAL)]
        assert self.engine.apply_penalties(100.0, checks) == 100.0

    def test_build_assessment(self):
        dims = [
            DimensionResult(
                dimension_id="AUTH",
                name="Auth",
                score=12.0,
                max_score=15.0,
                checks=[_passing_check("A-01", 12.0)],
            )
        ]
        result = self.engine.build_assessment("TestAgent", "1.0", dims)
        assert result.agent_name == "TestAgent"
        assert result.final_score == 12.0
        assert result.band in {"COMPROMISED", "CRITICAL", "VULNERABLE", "HARDENED", "SECURE"}
