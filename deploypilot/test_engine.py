"""Unit tests for DeployPilot engine."""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from deploypilot.engine import (
    CIFailure,
    ConfigValidator,
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
        self.assertTrue(any("import" in f.error_message.lower() or "modulenotfound" in f.error_message.lower() for f in failures))

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

    def test_new_patterns(self):
        """Test newly added patterns."""
        # Network
        log = "ECONNREFUSED: connection refused"
        failures = self.engine.analyze_log(log)
        self.assertTrue(any(f.category == "network" for f in failures))
        
        # Database
        log = "database error: table users already exists"
        failures = self.engine.analyze_log(log)
        self.assertTrue(any(f.category == "database" for f in failures))
        
        # Security
        log = "CVE-2024-1234: high severity vulnerability found"
        failures = self.engine.analyze_log(log)
        self.assertTrue(any(f.category == "security" for f in failures))

    def test_no_false_positives(self):
        log = "Build completed successfully. All tests passed."
        failures = self.engine.analyze_log(log)
        self.assertEqual(len(failures), 0)

    def test_flaky_detection(self):
        log = "Test is flaky — intermittently fails. Possible race condition."
        failures = self.engine.analyze_log(log)
        self.assertTrue(any(f.category == "test" and "flaky" in f.error_message.lower() for f in failures))


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
            CIFailure(job_name="ci", step_name="test", error_message="AssertionError", auto_fixable=False, category="test"),
            CIFailure(job_name="ci", step_name="build", error_message="OutOfMemoryError", auto_fixable=False, category="performance"),
        ]
        risk, confidence, warnings = self.scorer.score_pr(
            changed_files=["src/core.py", "migrations/big_change.sql"],
            ci_failures=failures,
            lines_changed=1500,
            has_tests=False,
        )
        self.assertGreaterEqual(risk, 0.55)
        self.assertEqual(confidence, ConfidenceLevel.LOW)

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

    def test_security_failure_high_risk(self):
        """Security vulnerabilities should significantly increase risk."""
        failures = [
            CIFailure(job_name="ci", step_name="audit", error_message="CVE-2024-1234", auto_fixable=False, category="security"),
        ]
        risk, confidence, warnings = self.scorer.score_pr(
            changed_files=["src/app.py"],
            ci_failures=failures,
            lines_changed=100,
            has_tests=True,
        )
        self.assertGreater(risk, 0.3)

    def test_config_issues_increase_risk(self):
        from deploypilot.engine import ConfigIssue
        issues = [
            ConfigIssue(file_path=".github/workflows/ci.yml", issue="Missing checkout", severity="critical", suggestion="Add checkout"),
            ConfigIssue(file_path=".github/workflows/ci.yml", issue="No cache", severity="warning", suggestion="Add cache"),
        ]
        risk, confidence, warnings = self.scorer.score_pr(
            changed_files=["src/app.py"],
            ci_failures=[],
            config_issues=issues,
            lines_changed=100,
            has_tests=True,
        )
        self.assertGreater(risk, 0.1)


class TestConfigValidator(unittest.TestCase):
    def setUp(self):
        self.validator = ConfigValidator()

    def test_missing_checkout(self):
        config = "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello"
        issues = self.validator.validate_github_actions(config)
        self.assertTrue(any("checkout" in i.issue.lower() for i in issues))

    def test_missing_trigger(self):
        config = "name: CI\njobs:\n  test:\n    runs-on: ubuntu-latest"
        issues = self.validator.validate_github_actions(config)
        self.assertTrue(any("checkout" in i.issue.lower() for i in issues))

    def test_no_caching_warning(self):
        config = "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: pip install -r requirements.txt"
        issues = self.validator.validate_github_actions(config)
        self.assertTrue(any("caching" in i.issue.lower() for i in issues))

    def test_outdated_actions(self):
        config = "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v2"
        issues = self.validator.validate_github_actions(config)
        self.assertTrue(any("outdated" in i.issue.lower() for i in issues))

    def test_pinned_actions_ok(self):
        config = "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7"
        issues = self.validator.validate_github_actions(config)
        unpinned = [i for i in issues if "unpinned" in i.issue.lower()]
        self.assertEqual(len(unpinned), 0)


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

    def test_config_validation_in_analysis(self):
        pilot = DeployPilot()
        config = "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello"
        result = pilot.analyze_pr(
            pr_number=2,
            title="Test config",
            author="bob",
            changed_files=[".github/workflows/ci.yml"],
            ci_config_text=config,
            ci_config_type="github_actions",
            lines_changed=10,
            has_tests=False,
        )
        self.assertTrue(len(result.config_issues) > 0)
        self.assertTrue(any("checkout" in i.issue.lower() for i in result.config_issues))

    def test_risk_score_bounds(self):
        pilot = DeployPilot()
        result = pilot.analyze_pr(
            pr_number=3,
            title="Big refactor",
            author="carol",
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
        self.assertGreater(result.estimated_ci_time_minutes, 0)

    def test_prediction_with_migration(self):
        pilot = DeployPilot()
        result = pilot.predict_pipeline(
            changed_files=["migrations/001_init.sql"],
            ci_history=[{"passed": True}, {"passed": True}],
        )
        self.assertTrue(any("migration" in r.lower() for r in result.predicted_failure_reasons))

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


if __name__ == "__main__":
    unittest.main()
