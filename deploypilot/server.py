"""DeployPilot server — FastAPI with inline HTML for reliability."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from deploypilot.engine import DeployPilot

app = FastAPI(title="DeployPilot", version="0.2.0")

BASE_DIR = Path(__file__).parent
TEMPLATE_DIR = BASE_DIR / "templates"

pr_analyses: dict[int, Any] = {}
ci_history: list[dict[str, Any]] = []


def verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not signature:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def render_template(name: str) -> str:
    return (TEMPLATE_DIR / name).read_text()


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=render_template("index.html"))


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.2.0", "analyses": len(pr_analyses)}


@app.get("/api/analyses")
async def list_analyses():
    return {"analyses": list(pr_analyses.values())}


@app.get("/api/analyses/{pr_number}")
async def get_analysis(pr_number: int):
    if pr_number not in pr_analyses:
        raise HTTPException(status_code=404, detail="PR not found")
    return pr_analyses[pr_number]


@app.post("/api/analyze")
async def analyze_pr_api(request: Request):
    """Analyze a PR via API."""
    data = await request.json()
    pilot = DeployPilot()

    analysis = pilot.analyze_pr(
        pr_number=data.get("pr_number", 0),
        title=data.get("title", "Untitled"),
        author=data.get("author", "unknown"),
        changed_files=data.get("changed_files", []),
        ci_log=data.get("ci_log"),
        ci_config_text=data.get("ci_config"),
        ci_config_type=data.get("ci_config_type", "github_actions"),
        lines_changed=data.get("lines_changed", 0),
        has_tests=data.get("has_tests", False),
        is_draft=data.get("is_draft", False),
    )

    # Store in memory for retrieval
    pr_analyses[analysis.pr_number] = {
        "pr_number": analysis.pr_number,
        "title": analysis.title,
        "author": analysis.author,
        "risk_score": analysis.risk_score,
        "confidence": analysis.confidence.value,
        "recommendation": analysis.recommendation,
        "warnings": analysis.warnings,
        "ci_failures": [
            {"error": f.error_message, "category": f.category, "auto_fixable": f.auto_fixable}
            for f in analysis.ci_failures
        ],
        "config_issues": [
            {"issue": i.issue, "severity": i.severity, "suggestion": i.suggestion}
            for i in analysis.config_issues
        ],
        "stats": analysis.stats,
    }

    return pr_analyses[analysis.pr_number]


@app.post("/webhook/github")
async def github_webhook(request: Request):
    payload = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "deploypilot-dev-secret")

    if not verify_github_signature(payload, signature, secret):
        if signature:
            raise HTTPException(status_code=401, detail="Invalid signature")

    event_type = request.headers.get("X-GitHub-Event", "")
    data = json.loads(payload)

    if event_type == "pull_request":
        return await handle_pr_event(data)
    elif event_type == "check_run":
        return await handle_check_run(data)

    return {"status": "ok", "event": event_type}


async def handle_pr_event(data: dict[str, Any]) -> dict[str, Any]:
    action = data.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        return {"status": "ok", "action": action}

    pr = data.get("pull_request", {})
    pr_number = pr.get("number", 0)
    title = pr.get("title", "Untitled")
    author = pr.get("user", {}).get("login", "unknown")
    is_draft = pr.get("draft", False)

    pilot = DeployPilot()
    analysis = pilot.analyze_pr(
        pr_number=pr_number,
        title=title,
        author=author,
        changed_files=[],
        is_draft=is_draft,
    )

    pr_analyses[pr_number] = {
        "pr_number": analysis.pr_number,
        "title": analysis.title,
        "author": analysis.author,
        "risk_score": analysis.risk_score,
        "confidence": analysis.confidence.value,
        "recommendation": analysis.recommendation,
        "warnings": analysis.warnings,
        "ci_failures": len(analysis.ci_failures),
    }

    return {"status": "analyzed", "pr": pr_number, "risk": analysis.risk_score}


async def handle_check_run(data: dict[str, Any]) -> dict[str, Any]:
    check_run = data.get("check_run", {})
    conclusion = check_run.get("conclusion")
    name = check_run.get("name", "unknown")
    pr_number = check_run.get("pull_requests", [{}])[0].get("number", 0)

    event = {"name": name, "conclusion": conclusion, "pr_number": pr_number}
    ci_history.append(event)

    if conclusion == "failure" and pr_number in pr_analyses:
        pr_analyses[pr_number]["ci_failures"] = pr_analyses[pr_number].get("ci_failures", 0) + 1
        pr_analyses[pr_number]["risk_score"] = min(1.0, pr_analyses[pr_number].get("risk_score", 0) + 0.2)

    return {"status": "recorded", "check_run": name}
