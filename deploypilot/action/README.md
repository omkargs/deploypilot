# DeployPilot GitHub Action

AI-powered deployment intelligence for every PR. Predicts CI failures, auto-remediates common issues, and posts deploy confidence scores directly on your pull requests.

## Usage

Add `.github/workflows/deploypilot.yml`:

```yaml
name: DeployPilot
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: DeployPilot Analysis
        uses: deploypilot/action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          deploypilot-api-key: ${{ secrets.DEPLOYPILOT_API_KEY }}
```

## What It Does

1. **Analyzes your PR** — changed files, diff size, risk signals
2. **Checks CI status** — runs your existing CI, collects logs
3. **Predicts failures** — if CI is still running, predicts outcome
4. **Posts a comment** — clear risk score + recommendation on the PR
5. **Status check** — passes/fails based on risk threshold

## Outputs

| Output | Description |
|--------|-------------|
| `risk_score` | 0.0 (safe) to 1.0 (risky) |
| `confidence` | high / medium / low |
| `recommendation` | Human-readable merge guidance |

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `github-token` | Yes | — | GitHub token for PR comments |
| `deploypilot-api-key` | No | — | API key for Pro features |
| `risk-threshold` | No | `0.7` | Fail status check above this |
| `auto-fix` | No | `false` | Attempt auto-remediation |
