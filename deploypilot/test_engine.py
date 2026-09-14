"""Unit tests for DeployPilot engine."""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from deploypilot.engine import (
    AutoRemediator,
    CIFailure,
    ConfidenceLevel,
    DeployPilot,
    PatternEngine,
    RiskScorer,
)


class TestPatternEngine(unittest.TestCase):
    def setUp(self):
        self.engine = PatternEngine()

    def test_import_error_detection(self):
        log = "ModuleNotFoundError: No module named 'fastapi'"
        failures = self.engine.analyze_log(log)
        self.assertTrue(any(f"import" in f.error_message.lower() or "modulenotfound" in f.error_message.lower() for f in failures))

    def test_lint_error_detection(self):
        log = "src/app.py:42:1: E302 expected 2 blank lines, found 1"
        failures = self.engine.analyze_log(log)
        self.assertTrue(any("E302" in f.error_message for f in failures))

    def test_test_failure_detection(self):
        log = "tests/test_app.py:10: FAIL\nAssertionError: Expected 200 but got 500"
        failures = self.engine.analyze_log(log)
        self.assertTrue(any("AssertionError" in f.error_message for f in failures))

    def test_docker_error_detection(self):
        log = "Error: failed to pull image python:3.13-slim"
        failures = self.engine.analyze_log(log)
        self.assertTrue(any("failed to pull" in f.error_message.lower() for f in failures))

    def test_timeout_error_detection(self):
        log = "TimeoutError: command timed out after 3600 seconds"
        failures = self.engine.analyze_log(log)
        self.assertTrue(any("timed out" in f.error_message.lower() for f in failures))

    def test_no_false_positives(self):
        log = "Build completed successfully. All tests passed."
        failures = self.engine.analyze_log(log)
        self.assertEqual(len(failures), 0)


class TestRiskScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = RiskScorer()

    def test_low_risk_clean_pr(self):
        risk, confidence, warnings = self.scorer.score_pr(
            changed_files=["src/utils.py", "tests/test_utils.py"],
            ci_failures=[],
            lines_changed=50,
            has_tests=True,
        )
        self.assertLess(risk, 0.25)
        self.assertEqual(confidence, ConfidenceLevel.HIGH)
        self.assertEqual(len(warnings), 0)

    def test_high_risk_pr_with_ci_failures(self):
        failures = [
            CIFailure(job_name="ci", step_name="test", error_message="AssertionError", auto_fixable=False),
            CIFailure(job_name="ci", step_name="build", error_message="OutOfMemoryError", auto_fixable=False),
        ]
        risk, confidence, warnings = self.scorer.score_pr(
            changed_files=["src/core.py", "migrations/big_change.sql"],
            ci_failures=failures,
            lines_changed=1500,
            has_tests=False,
        )
        self.assertGreaterEqual(risk, 0.6)
        self.assertEqual(confidence, ConfidenceLevel.LOW)
        self.assertTrue(len(warnings) >= 3)

    def test_critical_file_warning(self):
        risk, confidence, warnings = self.scorer.score_pr(
            changed_files=["terraform/main.tf"],
            ci_failures=[],
            lines_changed=10,
            has_tests=False,
        )
        self.assertTrue(any("Critical file" in w for w in warnings))

    def test_large_diff_warning(self):
        risk, confidence, warnings = self.scorer.score_pr(
            changed_files=["src/file.py"],
            ci_failures=[],
            lines_changed=2500,
            has_tests=False,
        )
        self.assertTrue(any("Massive diff" in w for w in warnings))


class TestAutoRemediator(unittest.TestCase):
    def test_fixable_import_error(self):
        with TemporaryDirectory() as tmpdir:
            rem = AutoRemediator(Path(tmpdir))
            failure = CIFailure(
                job_name="ci",
                step_name="test",
                error_message="ModuleNotFoundError: No module named 'requests'",
                auto_fixable=True,
            )
            # Should attempt fix (may fail if no requirements.txt, but shouldn't crash)
            success, message = rem.attempt_fix(failure)
            # Result depends on environment; just verify it doesn't crash
            self.assertIsInstance(success, bool)
            self.assertIsInstance(message, str)

    def test_non_fixable_returns_early(self):
        with TemporaryDirectory() as tmpdir:
            rem = AutoRemediator(Path(tmpdir))
            failure = CIFailure(
                job_name="ci",
                step_name="test",
                error_message="AssertionError: test failed",
                auto_fixable=False,
            )
            success, message = rem.attempt_fix(failure)
            self.assertFalse(success)
            self.assertEqual(message, "Not auto-fixable")


class TestDeployPilot(unittest.TestCase):
    def test_full_pr_analysis(self):
        pilot = DeployPilot()
        result = pilot.analyze_pr(
            pr_number=1,
            title="Fix login bug",
            author="alice",
            changed_files=["src/auth.py", "tests/test_auth.py"],
            ci_log="src/auth.py:42: E302 expected 2 blank lines",
            lines_changed=30,
            has_tests=True,
        )
        self.assertEqual(result.pr_number, 1)
        self.assertGreaterEqual(result.risk_score, 0)
        self.assertLessEqual(result.risk_score, 1.0)
        self.assertTrue(len(result.ci_failures) > 0)

    def test_risk_score_bounds(self):
        pilot = DeployPilot()
        # Extreme case: massive changes, many failures
        result = pilot.analyze_pr(
            pr_number=2,
            title="Big refactor",
            author="bob",
            changed_files=["migrations/huge.sql"],
            ci_log=" ".join(["AssertionError"] * 20),
            lines_changed=5000,
            is_draft=True,
        )
        self.assertLessEqual(result.risk_score, 1.0)
        self.assertGreaterEqual(result.risk_score, 0)

    def test_prediction(self):
        pilot = DeployPilot()
        result = pilot.predict_pipeline(
            changed_files=["src/models.py"],
            ci_history=[{"passed": False}, {"passed": False}, {"passed": True}],
        )
        self.assertIsInstance(result.will_pass, bool)
        self.assertGreater(result.confidence, 0)

    def test_auto_remediation_flag(self):
        pilot = DeployPilot()
        result = pilot.analyze_pr(
            pr_number=3,
            title="Test auto-fix",
            author="carol",
            changed_files=["src/app.py"],
            ci_log="src/app.py:10: E302 expected 2 blank lines",
            auto_remediate=False,
        )
        self.assertEqual(len(result.auto_fixes_applied), 0)

    def test_recommendation_text(self):
        pilot = DeployPilot()
        result = pilot.analyze_pr(
            pr_number=4,
            title="Safe change",
            author="dave",
            changed_files=["README.md"],
            ci_log=None,
            lines_changed=5,
            has_tests=False,
        )
        self.assertIn("Safe", result.recommendation)


class TestCIFailure(unittest.TestCase):
    def test_dataclass_defaults(self):
        f = CIFailure(job_name="ci", step_name="test", error_message="error")
        self.assertFalse(f.auto_fixable)
        self.assertIsNone(f.remediation)


if __name__ == "__main__":
    unittest.main()
