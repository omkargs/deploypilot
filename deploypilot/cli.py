"""DeployPilot CLI — analyze PRs and predict CI outcomes from the terminal."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from deploypilot.engine import (
    DeployPilot,
    PatternEngine,
    RiskScorer,
    ConfigValidator,
)

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="DeployPilot — AI-powered deployment intelligence",
)
console = Console()


@app.command()
def analyze(
    pr_number: int = typer.Option(..., "--pr", help="PR number"),
    title: str = typer.Option("Manual analysis", "--title", help="PR title"),
    author: str = typer.Option("unknown", "--author", help="PR author"),
    files: str = typer.Option("", "--files", help="Comma-separated changed files"),
    log_file: str = typer.Option("", "--log", help="Path to CI log file"),
    config_file: str = typer.Option("", "--config", help="Path to CI config file"),
    config_type: str = typer.Option("github_actions", "--config-type", help="Config type: github_actions, circleci, dockerfile"),
    lines_changed: int = typer.Option(0, "--lines", help="Lines changed"),
    has_tests: bool = typer.Option(False, "--tests/--no-tests", help="Has test changes"),
    draft: bool = typer.Option(False, "--draft", help="Is draft PR"),
    auto_fix: bool = typer.Option(False, "--auto-fix", help="Attempt auto-fixes"),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
):
    """Analyze a PR and get deploy confidence score."""
    pilot = DeployPilot()
    
    ci_log = None
    if log_file:
        ci_log = Path(log_file).read_text()

    ci_config = None
    if config_file:
        ci_config = Path(config_file).read_text()

    changed_files = [f.strip() for f in files.split(",") if f.strip()]

    result = pilot.analyze_pr(
        pr_number=pr_number,
        title=title,
        author=author,
        changed_files=changed_files,
        ci_log=ci_log,
        ci_config_text=ci_config,
        ci_config_type=config_type,
        lines_changed=lines_changed,
        has_tests=has_tests,
        is_draft=draft,
        auto_remediate=auto_fix,
    )

    if json_output:
        output = {
            "pr_number": result.pr_number,
            "risk_score": result.risk_score,
            "confidence": result.confidence.value,
            "recommendation": result.recommendation,
            "ci_failures": [
                {"error": f.error_message, "category": f.category, "auto_fixable": f.auto_fixable}
                for f in result.ci_failures
            ],
            "config_issues": [
                {"issue": i.issue, "severity": i.severity, "suggestion": i.suggestion}
                for i in result.config_issues
            ],
            "warnings": result.warnings,
            "stats": result.stats,
        }
        print(json.dumps(output, indent=2))
        return

    # Rich display
    risk_color = "green" if result.risk_score < 0.25 else "yellow" if result.risk_score < 0.55 else "red"
    risk_bar = "█" * int(result.risk_score * 20) + "░" * (20 - int(result.risk_score * 20))

    console.print()
    console.print(Panel(
        f"[bold]PR #{result.pr_number}[/bold]: {result.title}\n"
        f"Author: {result.author} | Files: {len(result.changed_files)}",
        title="DeployPilot Analysis",
        border_style=risk_color,
    ))

    console.print(f"\n[bold]Risk Score:[/bold] [{risk_color}]{risk_bar}[/{risk_color}] {result.risk_score:.0%}")
    console.print(f"[bold]Confidence:[/bold] {result.confidence.emoji} {result.confidence.value.upper()}")
    console.print(f"[bold]Recommendation:[/bold] {result.recommendation}")

    if result.ci_failures:
        console.print(f"\n[bold red]CI Failures ({len(result.ci_failures)}):[/bold red]")
        for f in result.ci_failures:
            fixable = "🔧" if f.auto_fixable else "🔴"
            console.print(f"  {fixable} [{f.category}] {f.error_message[:80]}")
            if f.remediation:
                console.print(f"     [dim]→ {f.remediation}[/dim]")

    if result.config_issues:
        console.print(f"\n[bold yellow]Config Issues ({len(result.config_issues)}):[/bold yellow]")
        for i in result.config_issues:
            sev = "🔴" if i.severity == "critical" else "⚠️" if i.severity == "warning" else "ℹ️"
            console.print(f"  {sev} {i.issue}")
            console.print(f"     [dim]→ {i.suggestion}[/dim]")

    if result.warnings:
        console.print(f"\n[bold yellow]Warnings:[/bold yellow]")
        for w in result.warnings:
            console.print(f"  ⚠️  {w}")

    if result.auto_fixes_applied:
        console.print(f"\n[bold green]Auto-fixes applied:[/bold green]")
        for fix in result.auto_fixes_applied:
            console.print(f"  {fix}")

    console.print()


@app.command()
def predict(
    files: str = typer.Option(..., "--files", help="Comma-separated changed files"),
    history_file: str = typer.Option("", "--history", help="Path to CI history JSON"),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
):
    """Predict CI outcome without running CI."""
    pilot = DeployPilot()
    
    changed_files = [f.strip() for f in files.split(",") if f.strip()]
    
    ci_history = None
    if history_file:
        ci_history = json.loads(Path(history_file).read_text())

    result = pilot.predict_pipeline(changed_files, ci_history)

    if json_output:
        print(json.dumps({
            "will_pass": result.will_pass,
            "confidence": result.confidence,
            "failure_reasons": result.predicted_failure_reasons,
            "actions": result.suggested_actions,
            "risk_factors": result.risk_factors,
            "estimated_time_min": result.estimated_ci_time_minutes,
        }, indent=2))
        return

    console.print()
    verdict = "✅ PASS" if result.will_pass else "❌ FAIL"
    console.print(Panel(
        f"[bold]Prediction:[/bold] {verdict}\n"
        f"[bold]Confidence:[/bold] {result.confidence:.0%}\n"
        f"[bold]Est. CI Time:[/bold] {result.estimated_ci_time_minutes:.1f} min",
        title="DeployPilot Prediction",
        border_style="green" if result.will_pass else "red",
    ))

    if result.predicted_failure_reasons:
        console.print("\n[bold]Risk factors:[/bold]")
        for reason in result.predicted_failure_reasons:
            console.print(f"  ⚠️  {reason}")

    if result.suggested_actions:
        console.print("\n[bold]Suggested actions:[/bold]")
        for action in result.suggested_actions:
            console.print(f"  → {action}")
    console.print()


@app.command()
def parse_log(
    log_file: str = typer.Argument(..., help="Path to CI log file"),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
):
    """Parse a CI log file and extract failures."""
    engine = PatternEngine()
    log_content = Path(log_file).read_text()
    failures = engine.analyze_log(log_content)

    if json_output:
        output = [
            {
                "job": f.job_name,
                "step": f.step_name,
                "error": f.error_message,
                "line": f.line_number,
                "category": f.category,
                "remediation": f.remediation,
                "auto_fixable": f.auto_fixable,
            }
            for f in failures
        ]
        print(json.dumps(output, indent=2))
        return

    console.print()
    console.print(Panel(
        f"Found [bold]{len(failures)}[/bold] issue(s) in CI log",
        title="DeployPilot Log Analysis",
    ))
    for f in failures:
        fixable = "🔧" if f.auto_fixable else "🔴"
        console.print(f"\n{fixable} [bold]Line {f.line_number}:[/bold] [{f.category}] {f.error_message[:80]}")
        if f.remediation:
            console.print(f"   [dim]→ {f.remediation}[/dim]")
    console.print()


@app.command()
def validate_config(
    config_file: str = typer.Argument(..., help="Path to CI config file"),
    config_type: str = typer.Option("github_actions", "--type", help="Config type"),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
):
    """Validate CI configuration for common issues."""
    validator = ConfigValidator()
    content = Path(config_file).read_text()
    
    if config_type == "github_actions":
        issues = validator.validate_github_actions(content, config_file)
    elif config_type == "circleci":
        issues = validator.validate_circleci_config(content)
    elif config_type == "dockerfile":
        issues = validator.validate_dockerfile(content, config_file)
    else:
        console.print(f"[red]Unknown config type: {config_type}[/red]")
        return

    if json_output:
        output = [
            {"issue": i.issue, "severity": i.severity, "suggestion": i.suggestion}
            for i in issues
        ]
        print(json.dumps(output, indent=2))
        return

    console.print()
    console.print(Panel(
        f"Found [bold]{len(issues)}[/bold] issue(s) in {config_file}",
        title="DeployPilot Config Validation",
    ))
    for i in issues:
        sev = "🔴" if i.severity == "critical" else "⚠️" if i.severity == "warning" else "ℹ️"
        console.print(f"\n{sev} [bold]{i.issue}[/bold]")
        console.print(f"   [dim]→ {i.suggestion}[/dim]")
    console.print()


@app.command()
def version():
    """Show version."""
    from importlib.metadata import version as get_version
    try:
        v = get_version("deploypilot")
    except Exception:
        v = "0.2.0"
    console.print(f"DeployPilot v{v}")


if __name__ == "__main__":
    app()
