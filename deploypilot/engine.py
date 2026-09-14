"""DeployPilot: AI-powered deployment intelligence.

The core engine analyzes CI/CD patterns, predicts failures,
and auto-remediates common pipeline issues.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ConfidenceLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def emoji(self) -> str:
        return {"high": "✅", "medium": "⚠️", "low": "❌"}[self.value]


@dataclass
class CIFailure:
    """Represents a CI failure with context for remediation."""
    job_name: str
    step_name: str
    error_message: str
    line_number: int | None = None
    file_path: str | None = None
    remediation: str | None = None
    auto_fixable: bool = False


@dataclass
class PRAnalysis:
    """Full analysis of a PR's deploy readiness."""
    pr_number: int
    title: str
    author: str
    changed_files: list[str] = field(default_factory=list)
    ci_failures: list[CIFailure] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 (safe) to 1.0 (risky)
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    recommendation: str = ""
    auto_fixes_applied: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass 
class PipelinePrediction:
    """Prediction for whether a pipeline will pass."""
    will_pass: bool
    confidence: float
    predicted_failure_reasons: list[str] = field(default_factory=list)
    suggested_actions: list[str] = field(default_factory=list)
    risk_factors: dict[str, float] = field(default_factory=dict)


class PatternEngine:
    """Analyzes CI log patterns and suggests fixes."""
    
    # Known failure patterns with regex + remediation
    PATTERNS: list[dict[str, Any]] = [
        {
            "name": "import_error",
            "regex": r"ModuleNotFoundError|ImportError|Cannot find module",
            "remediation": "Run `pip install -r requirements.txt` or `npm install`",
            "auto_fixable": True,
            "fix_command": "pip install -r requirements.txt 2>/dev/null || npm install 2>/dev/null",
        },
        {
            "name": "test_failure",
            "regex": r"FAILED|AssertionError|Expected.*but got",
            "remediation": "Review failing test output. Check for recent changes to the affected module.",
            "auto_fixable": False,
        },
        {
            "name": "lint_error",
            "regex": r"E\d{3}|F\d{3}|W\d{3}|flake8|eslint|prettier",
            "remediation": "Run formatter: `black .` or `npx prettier --write .` or `ruff check --fix .`",
            "auto_fixable": True,
            "fix_command": "ruff check --fix . 2>/dev/null || black . 2>/dev/null || prettier --write . 2>/dev/null",
        },
        {
            "name": "type_error",
            "regex": r"error TS\d+|Type.*is not assignable|Argument of type",
            "remediation": "Run TypeScript compiler: `tsc --noEmit` and fix type errors.",
            "auto_fixable": False,
        },
        {
            "name": "dependency_conflict",
            "regex": r"Could not find a version|conflict|RESOLVE|peer dep",
            "remediation": "Check dependency versions. Try `pip-compile` or `npm audit fix`.",
            "auto_fixable": False,
        },
        {
            "name": "docker_error",
            "regex": r"docker\s+(build|pull|run|push|login)|docker.*error|docker.*failed|failed to pull|container.*error|image not found",
            "remediation": "Check Docker daemon and image availability.",
            "auto_fixable": False,
        },
        {
            "name": "memory_error",
            "regex": r"OutOfMemoryError|heap|memory limit|Killed",
            "remediation": "Reduce memory usage. Consider splitting tests or increasing runner resources.",
            "auto_fixable": False,
        },
        {
            "name": "timeout_error",
            "regex": r"timeout|timed out|deadline exceeded|SIGTERM",
            "remediation": "Increase timeout or optimize slow tests/steps.",
            "auto_fixable": False,
        },
        {
            "name": "config_error",
            "regex": r"Invalid configuration|config.*not found|missing.*variable|environment.*not set",
            "remediation": "Check CI configuration and environment variables.",
            "auto_fixable": False,
        },
        {
            "name": "security_vulnerability",
            "regex": r"vulnerability|CVE-\d+|severity|bandit|safety",
            "remediation": "Run `pip-audit` or `npm audit` and update vulnerable dependencies.",
            "auto_fixable": False,
        },
    ]

    def analyze_log(self, log_content: str) -> list[CIFailure]:
        """Parse CI log and extract structured failures."""
        failures: list[CIFailure] = []
        lines = log_content.split("\n")
        
        for pattern in self.PATTERNS:
            for i, line in enumerate(lines):
                if re.search(pattern["regex"], line, re.IGNORECASE):
                    # Find context: look back for step name
                    step_name = "unknown"
                    for j in range(max(0, i - 10), i):
                        if "Step" in lines[j] or "##" in lines[j] or "RUN" in lines[j]:
                            step_name = lines[j].strip()[:80]
                    
                    failure = CIFailure(
                        job_name="ci",
                        step_name=step_name,
                        error_message=line.strip(),
                        line_number=i + 1,
                        remediation=pattern.get("remediation"),
                        auto_fixable=pattern.get("auto_fixable", False),
                    )
                    failures.append(failure)
        
        return failures


class RiskScorer:
    """Calculate risk score for a PR based on multiple signals."""
    
    def score_pr(
        self,
        changed_files: list[str],
        ci_failures: list[CIFailure],
        lines_changed: int = 0,
        has_tests: bool = False,
        is_draft: bool = False,
        review_comments: int = 0,
        author_past_failure_rate: float = 0.0,
    ) -> tuple[float, ConfidenceLevel, list[str]]:
        """
        Returns (risk_score, confidence, warnings).
        Score: 0.0 = safe, 1.0 = merge at your own risk.
        """
        risk = 0.0
        warnings: list[str] = []

        # CI failures are the strongest signal
        if ci_failures:
            fixable = sum(1 for f in ci_failures if f.auto_fixable)
            unfixable = len(ci_failures) - fixable
            risk += 0.5 * min(1.0, unfixable * 0.3)
            risk += 0.15 * min(1.0, fixable * 0.1)
            
            if unfixable > 0:
                warnings.append(f"{unfixable} un-fixable CI failure(s)")
            if fixable > 0:
                warnings.append(f"{fixable} auto-fixable CI issue(s)")

        # File change scope
        if lines_changed > 500:
            risk += 0.1
            warnings.append("Large diff (>500 lines)")
        if lines_changed > 1000:
            risk += 0.1
            warnings.append("Very large diff (>1000 lines)")
        if lines_changed > 2000:
            risk += 0.1
            warnings.append("Massive diff (>2000 lines) — consider splitting")

        # File types matter
        critical_files = {"migration", "schema", "seed", "infra", "terraform", "k8s", "dockerfile"}
        for f in changed_files:
            fname = f.lower()
            if any(cf in fname for cf in critical_files):
                risk += 0.15
                warnings.append(f"Critical file changed: {f}")
                break

        # Test coverage
        if not has_tests and changed_files:
            risk += 0.05
            warnings.append("No test files detected in PR")

        # Draft status
        if is_draft:
            risk += 0.1
            warnings.append("Draft PR")

        # Author track record
        if author_past_failure_rate > 0.3:
            risk += 0.05
            warnings.append(f"Author has {author_past_failure_rate:.0%} historical CI failure rate")

        # Review friction
        if review_comments > 5:
            risk += 0.05
            warnings.append("High review comment count — possible unresolved concerns")

        # Clamp
        risk = min(1.0, risk)

        if risk < 0.25:
            confidence = ConfidenceLevel.HIGH
        elif risk < 0.6:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW

        return risk, confidence, warnings


class AutoRemediator:
    """Attempts to auto-fix common CI issues."""
    
    def __init__(self, working_dir: Path):
        self.working_dir = working_dir

    def attempt_fix(self, failure: CIFailure) -> tuple[bool, str]:
        """Try to auto-fix a CI failure. Returns (success, message)."""
        if not failure.auto_fixable:
            return False, "Not auto-fixable"

        # Determine fix command from error type
        cmd = self._get_fix_command(failure)
        if not cmd:
            return False, "No fix command available"

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                return True, f"Applied: `{cmd}`"
            else:
                return False, f"Fix command failed: {result.stderr[:200]}"
        except subprocess.TimeoutExpired:
            return False, "Fix command timed out"
        except Exception as e:
            return False, f"Fix error: {e}"

    def _get_fix_command(self, failure: CIFailure) -> str | None:
        """Map error to fix command."""
        error_lower = failure.error_message.lower()
        
        if "modulenotfound" in error_lower or "importerror" in error_lower:
            return "pip install -r requirements.txt 2>/dev/null || npm install 2>/dev/null || poetry install 2>/dev/null"
        
        if "lint" in error_lower or "format" in error_lower or "prettier" in error_lower:
            return "ruff check --fix . 2>/dev/null || black . 2>/dev/null || npx prettier --write . 2>/dev/null"
        
        if "type" in error_lower and "ts" in error_lower:
            return "npx tsc --noEmit 2>/dev/null"
        
        return None


class DeployPilot:
    """Main engine: orchestrates analysis, prediction, and remediation."""
    
    def __init__(self, working_dir: str | Path | None = None):
        self.working_dir = Path(working_dir) if working_dir else Path.cwd()
        self.pattern_engine = PatternEngine()
        self.risk_scorer = RiskScorer()
        self.remediator = AutoRemediator(self.working_dir)

    def analyze_pr(
        self,
        pr_number: int,
        title: str,
        author: str,
        changed_files: list[str],
        ci_log: str | None = None,
        lines_changed: int = 0,
        has_tests: bool = False,
        is_draft: bool = False,
        review_comments: int = 0,
        auto_remediate: bool = False,
    ) -> PRAnalysis:
        """Full PR analysis pipeline."""
        
        # 1. Parse CI log
        ci_failures = []
        if ci_log:
            ci_failures = self.pattern_engine.analyze_log(ci_log)

        # 2. Score risk
        risk, confidence, warnings = self.risk_scorer.score_pr(
            changed_files=changed_files,
            ci_failures=ci_failures,
            lines_changed=lines_changed,
            has_tests=has_tests,
            is_draft=is_draft,
            review_comments=review_comments,
        )

        # 3. Auto-remediate if requested
        auto_fixes = []
        if auto_remediate and ci_failures:
            for failure in ci_failures:
                if failure.auto_fixable:
                    success, message = self.remediator.attempt_fix(failure)
                    if success:
                        auto_fixes.append(f"✅ {failure.error_message[:60]}: {message}")
                    else:
                        auto_fixes.append(f"❌ {failure.error_message[:60]}: {message}")

        # 4. Generate recommendation
        recommendation = self._generate_recommendation(risk, confidence, ci_failures)

        return PRAnalysis(
            pr_number=pr_number,
            title=title,
            author=author,
            changed_files=changed_files,
            ci_failures=ci_failures,
            risk_score=risk,
            confidence=confidence,
            recommendation=recommendation,
            auto_fixes_applied=auto_fixes,
            warnings=warnings,
        )

    def _generate_recommendation(
        self, risk: float, confidence: ConfidenceLevel, failures: list[CIFailure]
    ) -> str:
        if confidence == ConfidenceLevel.HIGH:
            return "Safe to merge. Low risk."
        elif confidence == ConfidenceLevel.MEDIUM:
            fixable = sum(1 for f in failures if f.auto_fixable)
            if fixable > 0:
                return f"Mergeable with caution. {fixable} issue(s) can be auto-fixed."
            return "Review recommended before merging."
        else:
            return "DO NOT MERGE. Address CI failures and review warnings first."

    def predict_pipeline(
        self,
        changed_files: list[str],
        ci_history: list[dict[str, Any]] | None = None,
    ) -> PipelinePrediction:
        """Predict CI outcome for a set of changes without running CI."""
        
        risk_factors: dict[str, float] = {}
        failure_reasons: list[str] = []
        actions: list[str] = []
        confidence = 0.7

        # Historical pattern analysis
        if ci_history:
            failure_rate = sum(1 for r in ci_history if not r.get("passed", True)) / len(ci_history)
            if failure_rate > 0.2:
                risk_factors["historical_failure_rate"] = failure_rate
                failure_reasons.append(f"Repository has {failure_rate:.0%} historical CI failure rate")
                confidence = min(0.95, confidence + 0.1)

        # File-based heuristics
        test_files = [f for f in changed_files if "test" in f.lower() or "spec" in f.lower()]
        source_files = [f for f in changed_files if any(f.endswith(ext) for ext in [".py", ".js", ".ts", ".tsx", ".jsx"])]
        config_files = [f for f in changed_files if any(k in f.lower() for k in ["config", "setup", "pyproject", "package.json", "dockerfile", "ci", ".github"])]

        if source_files and not test_files:
            risk_factors["missing_tests"] = 0.3
            failure_reasons.append("Source files changed without corresponding test changes")
            actions.append("Consider adding tests for the changes")

        if config_files:
            risk_factors["config_change"] = 0.2
            failure_reasons.append("Configuration/build files modified — may affect CI environment")
            actions.append("Verify CI configuration changes don't break existing pipeline")

        # Determine overall prediction
        total_risk = sum(risk_factors.values())
        will_pass = total_risk < 0.4
        
        if not actions:
            actions.append("No specific actions suggested — changes appear low-risk")

        return PipelinePrediction(
            will_pass=will_pass,
            confidence=confidence,
            predicted_failure_reasons=failure_reasons,
            suggested_actions=actions,
            risk_factors=risk_factors,
        )
