# DeployPilot

**AI-powered deployment intelligence. Predict CI failures before they happen.**

Every day, developers waste 10+ hours waiting for CI, debugging flaky pipelines, and guessing whether it's safe to merge. DeployPilot fixes that.

DeployPilot is a GitHub App + CLI that analyzes your PRs, predicts CI failures, auto-remediates common issues, and posts clear deploy confidence scores directly on your pull requests.

## Quick Start

### Option 1: GitHub App (recommended)

```bash
# Install from GitHub Marketplace (coming soon)
# Then add to your repo — zero config needed
```

### Option 2: CLI

```bash
pip install deploypilot

# Analyze a PR with CI log
deploypilot analyze --pr 42 --title "Add auth" --author "alice" \
  --files "src/auth.py,tests/test_auth.py" \
  --log ci-output.txt --lines 150 --tests

# Predict CI without running it
deploypilot predict --files "src/models.py,src/handler.py"

# Parse a CI log
deploypilot parse-log ci-output.txt
```

### Option 3: Web Server

```bash
pip install deploypilot[server]
uvicorn deploypilot.server:app --port 8000

# API endpoint
curl -X POST http://localhost:8000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"pr_number":1,"title":"Fix bug","changed_files":["src/app.py"],"ci_log":"E302 error"}'
```

## How It Works

```
PR Opened → DeployPilot analyzes files + CI log
                ↓
    ┌─────────────────────┐
    │  Pattern Detection  │ ← 10+ known CI failure patterns
    │  Risk Scoring       │ ← Weighted multi-signal scoring
    │  Auto-Remediation   │ ← Fix lint, imports, formatting
    │  Prediction         │ ← Forecast CI from history + files
    └─────────────────────┘
                ↓
    Deploy Confidence Score posted on PR
```

## Features

| Feature | Description |
|---------|-------------|
| 🔮 Failure Prediction | Predict CI outcomes before running |
| 🔧 Auto-Remediation | Fix lint, imports, formatting automatically |
| 📊 Risk Scoring | Clear 0-100% risk score per PR |
| 🛡️ Security | Source code never leaves your infra |
| ⚡ Zero Config | Install and go — no YAML changes |
| 🔗 GitHub Native | PR comments + status checks |

## Risk Scoring

| Score | Confidence | Meaning |
|-------|-----------|---------|
| 0-25% | ✅ High | Safe to merge |
| 25-60% | ⚠️ Medium | Review recommended |
| 60-100% | ❌ Low | Do not merge |

Scoring weights:
- CI failures (unfixable): +50% each
- CI failures (auto-fixable): +15% each
- Critical files (migrations, infra): +15%
- Missing tests: +5%
- Large diffs (>500 lines): +10%
- Draft status: +10%

## Architecture

```
deploypilot/
├── engine.py     # Core analysis engine
├── cli.py        # Terminal interface
├── server.py     # FastAPI webhook server
└── action/       # GitHub Action integration
```

## License

MIT
