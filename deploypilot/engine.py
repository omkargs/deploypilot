"""DeployPilot: Advanced CI intelligence with config validation and smart scoring."""
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
    category: str = "unknown"
    severity: str = "error"  # error, warning, info


@dataclass
class ConfigIssue:
    """Represents a CI configuration issue."""
    file_path: str
    issue: str
    severity: str  # critical, warning, info
    suggestion: str
    line_number: int | None = None


@dataclass
class PRAnalysis:
    """Full analysis of a PR's deploy readiness."""
    pr_number: int
    title: str
    author: str
    changed_files: list[str] = field(default_factory=list)
    ci_failures: list[CIFailure] = field(default_factory=list)
    config_issues: list[ConfigIssue] = field(default_factory=list)
    risk_score: float = 0.0
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    recommendation: str = ""
    auto_fixes_applied: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelinePrediction:
    """Prediction for whether a pipeline will pass."""
    will_pass: bool
    confidence: float
    predicted_failure_reasons: list[str] = field(default_factory=list)
    suggested_actions: list[str] = field(default_factory=list)
    risk_factors: dict[str, float] = field(default_factory=dict)
    estimated_ci_time_minutes: float = 0.0


class PatternEngine:
    """Analyzes CI log patterns with 25+ known failure types."""
    
    PATTERNS: list[dict[str, Any]] = [
        # Build & Compilation
        {
            "name": "import_error",
            "regex": r"ModuleNotFoundError|ImportError|Cannot find module|package not found|No module named",
            "category": "build",
            "remediation": "Install dependencies: `pip install -r requirements.txt` or `npm install`",
            "auto_fixable": True,
        },
        {
            "name": "syntax_error",
            "regex": r"SyntaxError|syntax error|unexpected token|ParseError|expected.*but found",
            "category": "build",
            "remediation": "Fix syntax error. Check for missing brackets, commas, or incorrect indentation.",
            "auto_fixable": False,
        },
        {
            "name": "type_error",
            "regex": r"error TS\d+|Type.*is not assignable|Argument of type|Type mismatch|cannot be assigned to",
            "category": "build",
            "remediation": "Run TypeScript checker: `tsc --noEmit` and fix type errors.",
            "auto_fixable": False,
        },
        {
            "name": "compilation_error",
            "regex": r"error:|fatal error|compilation failed|build failed|cannot find symbol|undefined reference",
            "category": "build",
            "remediation": "Review compilation errors. Check for missing dependencies or incorrect imports.",
            "auto_fixable": False,
        },
        # Tests
        {
            "name": "test_failure",
            "regex": r"FAILED|AssertionError|AssertionError|Expect.*but got|Expected.*received|test failed",
            "category": "test",
            "remediation": "Review failing test. Check if behavior change is intentional.",
            "auto_fixable": False,
        },
        {
            "name": "test_flaky",
            "regex": r"flaky|intermittent|timed out.*test|race condition|deadlock",
            "category": "test",
            "remediation": "Test may be flaky. Retry or add retry logic. Consider making test deterministic.",
            "auto_fixable": False,
        },
        # Linting & Formatting
        {
            "name": "lint_error",
            "regex": r"E\d{3}|F\d{3}|W\d{3}|flake8|eslint|prettier|stylelint|rubocop|pylint",
            "category": "lint",
            "remediation": "Auto-format: `ruff check --fix .` or `black .` or `npx prettier --write .`",
            "auto_fixable": True,
        },
        {
            "name": "formatting_error",
            "regex": r"would reformat|file reformatted|imports not sorted|isort",
            "category": "lint",
            "remediation": "Run formatter: `black .` or `ruff format .` or `npx prettier --write .`",
            "auto_fixable": True,
        },
        # Dependencies
        {
            "name": "dependency_conflict",
            "regex": r"Could not find a version|conflict|RESOLVE|peer dep|version mismatch|incompatible",
            "category": "dependency",
            "remediation": "Check dependency versions. Try `pip-compile` or `npm audit fix` or `poetry lock`.",
            "auto_fixable": False,
        },
        {
            "name": "outdated_dependency",
            "regex": r"deprecated|no longer maintained|end of life|upgrade required|version.*outdated",
            "category": "dependency",
            "remediation": "Update deprecated dependencies to latest versions.",
            "auto_fixable": False,
        },
        {
            "name": "security_vulnerability",
            "regex": r"vulnerability|CVE-\d+|severity|bandit|safety|npm audit|pip-audit",
            "category": "security",
            "remediation": "Run `pip-audit` or `npm audit` and update vulnerable packages.",
            "auto_fixable": False,
        },
        # Infrastructure
        {
            "name": "docker_error",
            "regex": r"docker\s+(build|pull|run|push|login)|docker.*error|docker.*failed|failed to pull|container.*error|image not found",
            "category": "infrastructure",
            "remediation": "Check Docker daemon, image tags, and registry authentication.",
            "auto_fixable": False,
        },
        {
            "name": "kubernetes_error",
            "regex": r"kubectl|kubernetes|k8s.*error|pod.*failed|deployment.*error|helm.*error",
            "category": "infrastructure",
            "remediation": "Check cluster status, resource limits, and configuration.",
            "auto_fixable": False,
        },
        {
            "name": "terraform_error",
            "regex": r"terraform|tf.*error|state.*lock|resource.*already exists|plan.*failed",
            "category": "infrastructure",
            "remediation": "Run `terraform plan` locally to validate. Check state and provider configuration.",
            "auto_fixable": False,
        },
        # Performance & Resources
        {
            "name": "memory_error",
            "regex": r"OutOfMemoryError|heap|memory limit|Killed|OOM|allocation failed",
            "category": "performance",
            "remediation": "Reduce memory usage. Split tests, increase runner resources, or optimize allocations.",
            "auto_fixable": False,
        },
        {
            "name": "timeout_error",
            "regex": r"timeout|timed out|deadline exceeded|SIGTERM|signal killed|context deadline",
            "category": "performance",
            "remediation": "Increase timeout, optimize slow tests, or split into parallel jobs.",
            "auto_fixable": False,
        },
        {
            "name": "slow_test",
            "regex": r"slow.*test|performance.*regression|benchmark.*failed|took longer than",
            "category": "performance",
            "remediation": "Investigate slow tests. Consider optimization or increasing timeout threshold.",
            "auto_fixable": False,
        },
        # Configuration
        {
            "name": "config_error",
            "regex": r"Invalid configuration|config.*not found|missing.*variable|environment.*not set|secret.*not found",
            "category": "configuration",
            "remediation": "Check CI configuration and environment variables/secrets.",
            "auto_fixable": False,
        },
        {
            "name": "yaml_error",
            "regex": r"yaml.*error|yaml.*parse|mapping values|indentation.*error|scanner.*error",
            "category": "configuration",
            "remediation": "Fix YAML syntax. Check indentation and special characters.",
            "auto_fixable": False,
        },
        # Network
        {
            "name": "network_error",
            "regex": r"ECONNREFUSED|ETIMEDOUT|ENOTFOUND|network.*error|connection.*refused|getaddrinfo",
            "category": "network",
            "remediation": "Check network connectivity. Verify service endpoints and DNS resolution.",
            "auto_fixable": False,
        },
        {
            "name": "ssl_error",
            "regex": r"SSL.*error|certificate.*error|self-signed|tls.*error|verify.*certificate",
            "category": "network",
            "remediation": "Check SSL certificates and TLS configuration.",
            "auto_fixable": False,
        },
        # Database
        {
            "name": "database_error",
            "regex": r"database.*error|connection.*refused.*database|migration.*failed|table.*already exists|column.*not found",
            "category": "database",
            "remediation": "Check database connection, run migrations, and verify schema.",
            "auto_fixable": False,
        },
        # Permissions
        {
            "name": "permission_error",
            "regex": r"permission denied|EACCES|forbidden|access.*denied|403|401",
            "category": "permissions",
            "remediation": "Check file permissions and API token scopes.",
            "auto_fixable": False,
        },
        # Lock files
        {
            "name": "lock_file_error",
            "regex": r"lock.*file|concurrent.*modification|another.*process|lock.*timeout|Unable to lock",
            "category": "lock",
            "remediation": "Wait for other CI jobs to finish. Check for stuck processes.",
            "auto_fixable": False,
        },
        # Cache
        {
            "name": "cache_error",
            "regex": r"cache.*error|cache.*miss.*upload|cache.*corrupted|Unable to save cache",
            "category": "cache",
            "remediation": "Clear cache and retry. Check cache key patterns and storage limits.",
            "auto_fixable": False,
        },
        # Deployment
        {
            "name": "deployment_error",
            "regex": r"deployment.*error|deploy.*failed|rollback.*required|release.*error|service.*unavailable",
            "category": "deployment",
            "remediation": "Check deployment logs and service health. Consider rolling back.",
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
                    step_name = self._find_step_name(lines, i)
                    
                    failure = CIFailure(
                        job_name=self._find_job_name(lines, i),
                        step_name=step_name,
                        error_message=line.strip(),
                        line_number=i + 1,
                        remediation=pattern.get("remediation"),
                        auto_fixable=pattern.get("auto_fixable", False),
                        category=pattern.get("category", "unknown"),
                        severity="error" if "error" in line.lower() or "FAIL" in line else "warning",
                    )
                    failures.append(failure)
        
        return failures

    def _find_step_name(self, lines: list[str], current_idx: int) -> str:
        """Look backwards to find the step name."""
        for j in range(max(0, current_idx - 15), current_idx):
            line = lines[j].strip()
            if any(kw in line for kw in ["Step", "##", "RUN", "Running", "━━", "==>", "📍"]):
                return line[:80]
        return "unknown"

    def _find_job_name(self, lines: list[str], current_idx: int) -> str:
        """Look backwards for job name."""
        for j in range(max(0, current_idx - 30), current_idx):
            line = lines[j].strip()
            if "Job" in line or "job:" in line.lower() or "🏗️" in line:
                return line[:80]
        return "ci"


class ConfigValidator:
    """Validates CI configuration files for common issues."""
    
    def validate_github_actions(self, config_text: str, file_path: str = ".github/workflows/ci.yml") -> list[ConfigIssue]:
        """Validate GitHub Actions workflow."""
        issues: list[ConfigIssue] = []
        
        # Check for common issues
        if "actions/checkout" not in config_text:
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="Missing actions/checkout step",
                severity="critical",
                suggestion="Add `- uses: actions/checkout@v4` as first step",
            ))
        
        if "on:" not in config_text and "true:" not in config_text:
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="No trigger events defined",
                severity="critical",
                suggestion="Add `on: [push, pull_request]` to define when workflow runs",
            ))
        
        if "actions/setup-python" in config_text and "python-version" not in config_text:
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="Python setup without version specified",
                severity="warning",
                suggestion="Add `python-version: '3.12'` for reproducible builds",
            ))
        
        if "actions/setup-node" in config_text and "node-version" not in config_text:
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="Node setup without version specified",
                severity="warning",
                suggestion="Add `node-version: '20'` for reproducible builds",
            ))
        
        if "pip install" in config_text and "cache" not in config_text.lower():
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="No dependency caching configured",
                severity="warning",
                suggestion="Add `cache: 'pip'` to speed up installs by 30-60%",
            ))
        
        if "npm install" in config_text and "cache" not in config_text.lower():
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="No npm caching configured",
                severity="warning",
                suggestion="Add `cache: 'npm'` to speed up installs",
            ))
        
        if "actions/checkout@v3" in config_text or "actions/checkout@v2" in config_text:
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="Using outdated actions/checkout version",
                severity="info",
                suggestion="Upgrade to `actions/checkout@v4`",
            ))
        
        if "actions/setup-python@v3" in config_text or "actions/setup-python@v2" in config_text:
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="Using outdated actions/setup-python version",
                severity="info",
                suggestion="Upgrade to `actions/setup-python@v5`",
            ))
        
        # Check for unpinnded actions (security risk)
        unpinned = re.findall(r"uses: ([^@]+)@(?:main|master|latest)", config_text)
        if unpinned:
            issues.append(ConfigIssue(
                file_path=file_path,
                issue=f"Unpinned actions: {', '.join(unpinned[:3])}. Use SHA pins for security.",
                severity="warning",
                suggestion="Pin actions to full commit SHAs for supply chain security",
            ))
        
        return issues

    def validate_circleci_config(self, config_text: str) -> list[ConfigIssue]:
        """Validate CircleCI configuration."""
        issues: list[ConfigIssue] = []
        
        if "docker:" in config_text and "image:" not in config_text:
            issues.append(ConfigIssue(
                file_path=".circleci/config.yml",
                issue="No Docker image specified",
                severity="critical",
                suggestion="Add `image: cimg/python:3.12` or appropriate base image",
            ))
        
        if "restore_cache" not in config_text and ("pip install" in config_text or "npm install" in config_text):
            issues.append(ConfigIssue(
                file_path=".circleci/config.yml",
                issue="No cache restoration configured",
                severity="warning",
                suggestion="Add `restore_cache` step before dependency install",
            ))
        
        return issues

    def validate_dockerfile(self, content: str, file_path: str = "Dockerfile") -> list[ConfigIssue]:
        """Validate Dockerfile for CI-relevant issues."""
        issues: list[ConfigIssue] = []
        
        if "latest" in content.split("\n")[0] if content else "":
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="Using :latest base tag",
                severity="warning",
                suggestion="Pin to specific version for reproducible builds: `python:3.12-slim`",
            ))
        
        if "RUN pip install" in content and "--no-cache-dir" not in content:
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="pip install without --no-cache-dir",
                severity="info",
                suggestion="Add `--no-cache-dir` to reduce image size",
            ))
        
        if "USER root" in content and "USER" not in content.split("USER root")[-1]:
            issues.append(ConfigIssue(
                file_path=file_path,
                issue="Running as root without switching to non-root user",
                severity="warning",
                suggestion="Add `USER appuser` at end of Dockerfile for security",
            ))
        
        return issues


class RiskScorer:
    """Calculate risk score using weighted multi-signal analysis."""
    
    # Category weights — some failures are more severe
    CATEGORY_WEIGHTS = {
        "build": 0.30,
        "test": 0.25,
        "security": 0.40,
        "infrastructure": 0.25,
        "configuration": 0.20,
        "dependency": 0.20,
        "lint": 0.10,
        "performance": 0.15,
        "database": 0.25,
        "permissions": 0.20,
        "network": 0.15,
        "lock": 0.10,
        "cache": 0.05,
        "deployment": 0.30,
    }

    def score_pr(
        self,
        changed_files: list[str],
        ci_failures: list[CIFailure],
        config_issues: list[ConfigIssue] | None = None,
        lines_changed: int = 0,
        has_tests: bool = False,
        is_draft: bool = False,
        review_comments: int = 0,
        author_past_failure_rate: float = 0.0,
    ) -> tuple[float, ConfidenceLevel, list[str]]:
        risk = 0.0
        warnings: list[str] = []

        # CI failures weighted by category
        if ci_failures:
            category_risks: dict[str, float] = {}
            for f in ci_failures:
                weight = self.CATEGORY_WEIGHTS.get(f.category, 0.15)
                if f.auto_fixable:
                    weight *= 0.3  # Reduce weight for auto-fixable
                category_risks[f.category] = category_risks.get(f.category, 0) + weight
            
            # Sum category risks, capped per category
            for cat, cat_risk in category_risks.items():
                risk += min(cat_risk, 0.4)  # Cap per category
            
            fixable = sum(1 for f in ci_failures if f.auto_fixable)
            unfixable = len(ci_failures) - fixable
            
            if unfixable > 0:
                warnings.append(f"{unfixable} un-fixable CI failure(s)")
            if fixable > 0:
                warnings.append(f"{fixable} auto-fixable")

        # Config issues
        if config_issues:
            critical = sum(1 for i in config_issues if i.severity == "critical")
            warning = sum(1 for i in config_issues if i.severity == "warning")
            risk += 0.15 * critical + 0.05 * warning
            if critical > 0:
                warnings.append(f"{critical} critical config issue(s)")
            if warning > 0:
                warnings.append(f"{warning} config warning(s)")

        # File change scope
        if lines_changed > 500:
            risk += 0.05
            warnings.append("Large diff (>500 lines)")
        if lines_changed > 1000:
            risk += 0.05
            warnings.append("Very large diff (>1000 lines)")
        if lines_changed > 2000:
            risk += 0.10
            warnings.append("Massive diff (>2000 lines) — split recommended")
        if lines_changed > 5000:
            risk += 0.15
            warnings.append("Extreme diff (>5000 lines)")

        # Critical file patterns
        critical_patterns = {
            "migration": 0.10, "schema": 0.10, "seed": 0.05,
            "terraform": 0.15, "k8s": 0.10, "dockerfile": 0.05,
            "infrastructure": 0.10, "infra": 0.08,
        }
        for f in changed_files:
            fname = f.lower()
            for pattern, weight in critical_patterns.items():
                if pattern in fname:
                    risk += weight
                    warnings.append(f"Critical file: {f}")
                    break  # One critical file warning per file

        # Test coverage
        if not has_tests and changed_files:
            source_files = [f for f in changed_files if any(f.endswith(ext) for ext in [".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java"])]
            if source_files:
                risk += 0.05
                warnings.append("No test files detected")

        # Draft status
        if is_draft:
            risk += 0.10
            warnings.append("Draft PR")

        # Review friction
        if review_comments > 5:
            risk += 0.05
            warnings.append(f"{review_comments} review comments — possible concerns")

        # Author track record
        if author_past_failure_rate > 0.3:
            risk += 0.05
            warnings.append(f"Author has {author_past_failure_rate:.0%} historical CI failure rate")

        # Clamp and classify
        risk = min(1.0, max(0.0, risk))

        if risk < 0.25:
            confidence = ConfidenceLevel.HIGH
        elif risk < 0.55:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW

        return risk, confidence, warnings


class DeployPilot:
    """Main engine: orchestrates analysis, prediction, and remediation."""
    
    def __init__(self, working_dir: str | Path | None = None):
        self.working_dir = Path(working_dir) if working_dir else Path.cwd()
        self.pattern_engine = PatternEngine()
        self.config_validator = ConfigValidator()
        self.risk_scorer = RiskScorer()

    def analyze_pr(
        self,
        pr_number: int,
        title: str,
        author: str,
        changed_files: list[str],
        ci_log: str | None = None,
        ci_config_text: str | None = None,
        ci_config_type: str = "github_actions",
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

        # 2. Validate CI config
        config_issues = []
        if ci_config_text:
            if ci_config_type == "github_actions":
                config_issues = self.config_validator.validate_github_actions(ci_config_text)
            elif ci_config_type == "circleci":
                config_issues = self.config_validator.validate_circleci_config(ci_config_text)
            elif ci_config_type == "dockerfile":
                config_issues = self.config_validator.validate_dockerfile(ci_config_text)

        # 3. Score risk
        risk, confidence, warnings = self.risk_scorer.score_pr(
            changed_files=changed_files,
            ci_failures=ci_failures,
            config_issues=config_issues,
            lines_changed=lines_changed,
            has_tests=has_tests,
            is_draft=is_draft,
            review_comments=review_comments,
        )

        # 4. Auto-remediate if requested
        auto_fixes = []
        if auto_remediate:
            for failure in ci_failures:
                if failure.auto_fixable:
                    # In production, actually apply fix; here we just report
                    auto_fixes.append(f"Would fix: {failure.error_message[:60]}")

        # 5. Generate recommendation
        recommendation = self._generate_recommendation(risk, confidence, ci_failures, config_issues)

        # 6. Compute stats
        stats = {
            "ci_failures_by_category": {},
            "fixable_count": sum(1 for f in ci_failures if f.auto_fixable),
            "unfixable_count": sum(1 for f in ci_failures if not f.auto_fixable),
            "config_critical": sum(1 for i in config_issues if i.severity == "critical"),
            "config_warnings": sum(1 for i in config_issues if i.severity == "warning"),
        }
        for f in ci_failures:
            cat = f.category
            stats["ci_failures_by_category"][cat] = stats["ci_failures_by_category"].get(cat, 0) + 1

        return PRAnalysis(
            pr_number=pr_number,
            title=title,
            author=author,
            changed_files=changed_files,
            ci_failures=ci_failures,
            config_issues=config_issues,
            risk_score=risk,
            confidence=confidence,
            recommendation=recommendation,
            auto_fixes_applied=auto_fixes,
            warnings=warnings,
            stats=stats,
        )

    def _generate_recommendation(
        self, risk: float, confidence: ConfidenceLevel, failures: list[CIFailure], config_issues: list[ConfigIssue]
    ) -> str:
        if confidence == ConfidenceLevel.HIGH:
            if not failures and not config_issues:
                return "✅ Safe to merge. No issues detected."
            return "✅ Low risk. Safe to merge with standard review."
        elif confidence == ConfidenceLevel.MEDIUM:
            fixable = sum(1 for f in failures if f.auto_fixable)
            if fixable > 0:
                return f"⚠️ Review recommended. {fixable} issue(s) auto-fixable."
            return "⚠️ Review recommended before merging."
        else:
            critical = sum(1 for i in config_issues if i.severity == "critical")
            if critical > 0:
                return f"🚫 DO NOT MERGE. {critical} critical config issue(s) and {len(failures)} CI failure(s)."
            return f"🚫 DO NOT MERGE. {len(failures)} CI failure(s) need resolution."

    def predict_pipeline(
        self,
        changed_files: list[str],
        ci_history: list[dict[str, Any]] | None = None,
    ) -> PipelinePrediction:
        """Predict CI outcome without running it."""
        
        risk_factors: dict[str, float] = {}
        failure_reasons: list[str] = []
        actions: list[str] = []
        confidence = 0.70

        # Historical analysis
        if ci_history:
            total = len(ci_history)
            failures = sum(1 for r in ci_history if not r.get("passed", True))
            failure_rate = failures / total if total > 0 else 0
            
            if failure_rate > 0.25:
                risk_factors["historical_failure_rate"] = failure_rate
                failure_reasons.append(f"Repository has {failure_rate:.0%} historical CI failure rate")
                confidence = min(0.95, confidence + 0.15)
            
            # Time trend analysis
            recent = ci_history[-10:]
            recent_failures = sum(1 for r in recent if not r.get("passed", True))
            if recent_failures > len(recent) * 0.4:
                failure_reasons.append(f"Recent CI runs failing ({recent_failures}/{len(recent)})")
                confidence = min(0.95, confidence + 0.10)

        # File-based risk heuristics
        test_files = [f for f in changed_files if any(kw in f.lower() for kw in ["test", "spec", "__tests__"])]
        source_files = [f for f in changed_files if any(f.endswith(ext) for ext in [".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs"])]
        config_files = [f for f in changed_files if any(k in f.lower() for k in ["config", "setup", "pyproject", "package.json", "dockerfile", "ci", ".github", ".circleci"])]
        
        if source_files and not test_files:
            risk_factors["missing_tests"] = 0.25
            failure_reasons.append("Source files changed without test changes")
            actions.append("Consider adding tests for changed behavior")

        if config_files:
            risk_factors["config_change"] = 0.15
            failure_reasons.append("CI/build configuration modified")
            actions.append("Verify config changes don't break existing pipeline")

        if any("migration" in f.lower() for f in changed_files):
            risk_factors["migration"] = 0.20
            failure_reasons.append("Database migration present")
            actions.append("Ensure migrations are backward-compatible")

        total_risk = min(1.0, sum(risk_factors.values()))
        will_pass = total_risk < 0.40

        if not actions:
            actions.append("No specific actions needed — changes appear low-risk")

        # Estimate CI time based on file count and history
        est_time = 5.0 + len(changed_files) * 0.5
        if ci_history:
            avg_time = sum(r.get("duration_minutes", 5) for r in ci_history) / len(ci_history)
            est_time = avg_time

        return PipelinePrediction(
            will_pass=will_pass,
            confidence=confidence,
            predicted_failure_reasons=failure_reasons,
            suggested_actions=actions,
            risk_factors=risk_factors,
            estimated_ci_time_minutes=est_time,
        )
