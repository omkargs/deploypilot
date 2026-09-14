"""Analytics and billing engine."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from deploypilot.database import User, Repository, Analysis


class Analytics:
    """Track and report on platform metrics."""
    
    @staticmethod
    def get_dashboard_stats(db: Session, user_id: int) -> dict[str, Any]:
        """Get dashboard stats for a user."""
        repos_count = db.query(func.count(Repository.id)).filter(Repository.owner_id == user_id).scalar() or 0
        
        analyses = (
            db.query(Analysis)
            .join(Repository, Analysis.repo_id == Repository.id)
            .filter(Repository.owner_id == user_id)
            .all()
        )
        
        total_analyses = len(analyses)
        high_risk = sum(1 for a in analyses if a.risk_score >= 0.6)
        medium_risk = sum(1 for a in analyses if 0.25 <= a.risk_score < 0.6)
        low_risk = sum(1 for a in analyses if a.risk_score < 0.25)
        
        avg_risk = sum(a.risk_score for a in analyses) / len(analyses) if analyses else 0
        
        # Top failure categories
        failure_categories: dict[str, int] = {}
        for a in analyses:
            if a.ci_failures:
                try:
                    failures = json.loads(a.ci_failures) if isinstance(a.ci_failures, str) else a.ci_failures
                    if isinstance(failures, list):
                        for f in failures:
                            if isinstance(f, dict):
                                cat = f.get("category", "unknown")
                                failure_categories[cat] = failure_categories.get(cat, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    pass
        
        # Recent activity (last 7 days)
        cutoff = datetime.utcnow() - timedelta(days=7)
        recent = [a for a in analyses if a.created_at > cutoff]
        
        return {
            "total_repos": repos_count,
            "total_analyses": total_analyses,
            "risk_distribution": {
                "high": high_risk,
                "medium": medium_risk,
                "low": low_risk,
            },
            "avg_risk_score": avg_risk,
            "failure_categories": failure_categories,
            "recent_analyses_7d": len(recent),
            "recommendations": Analytics._generate_recommendations(analyses),
        }
    
    @staticmethod
    def _generate_recommendations(analyses: list[Analysis]) -> list[str]:
        """Generate actionable recommendations from analysis history."""
        recommendations: list[str] = []
        
        if not analyses:
            return ["No analyses yet. Install DeployPilot on your first repo!"]
        
        avg_risk = sum(a.risk_score for a in analyses) / len(analyses)
        if avg_risk > 0.5:
            recommendations.append("Your PRs are frequently high-risk. Consider adding more tests.")
        
        # Check for common failure patterns
        all_failures: list[dict] = []
        for a in analyses:
            if a.ci_failures:
                try:
                    failures = json.loads(a.ci_failures) if isinstance(a.ci_failures, str) else a.ci_failures
                    if isinstance(failures, list):
                        for f in failures:
                            if isinstance(f, dict):
                                all_failures.append(f)
                except (json.JSONDecodeError, TypeError):
                    pass
        
        lint_count = sum(1 for f in all_failures if f.get("category") == "lint")
        if lint_count > 3:
            recommendations.append("Frequent lint failures detected. Consider adding auto-formatting to your pre-commit hooks.")
        
        test_count = sum(1 for f in all_failures if f.get("category") == "test")
        if test_count > 3:
            recommendations.append("Test failures are common. Review flaky tests and consider splitting slow tests.")
        
        return recommendations


class Billing:
    """Plan management and feature gating."""
    
    PLANS: dict[str, dict[str, Any]] = {
        "free": {
            "name": "Free",
            "price_monthly": 0,
            "analyses_per_month": 100,
            "repos": 3,
            "features": ["basic_detection", "pr_comments"],
        },
        "pro": {
            "name": "Pro",
            "price_monthly": 29,
            "analyses_per_month": None,  # unlimited
            "repos": None,  # unlimited
            "features": ["basic_detection", "pr_comments", "auto_fix", "prediction", "slack"],
        },
        "enterprise": {
            "name": "Enterprise",
            "price_monthly": None,  # custom
            "analyses_per_month": None,
            "repos": None,
            "features": ["basic_detection", "pr_comments", "auto_fix", "prediction", "slack", "self_hosted", "sso", "custom_models"],
        },
    }
    
    @staticmethod
    def check_feature_access(user: User, feature: str) -> bool:
        """Check if a user has access to a feature."""
        plan_name: str = user.plan if user.plan else "free"
        plan = Billing.PLANS.get(plan_name, Billing.PLANS["free"])
        features = plan.get("features", [])
        return feature in features
    
    @staticmethod
    def check_usage_limits(user: User, db: Session) -> dict[str, Any]:
        """Check if user has exceeded their plan limits."""
        plan_name: str = user.plan if user.plan else "free"
        plan = Billing.PLANS.get(plan_name, Billing.PLANS["free"])
        
        current_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0)
        
        analyses_count: int = (
            db.query(func.count(Analysis.id))
            .join(Repository, Analysis.repo_id == Repository.id)
            .filter(
                Repository.owner_id == user.id,
                Analysis.created_at >= current_month,
            )
            .scalar() or 0
        )
        
        repos_count: int = db.query(func.count(Repository.id)).filter(Repository.owner_id == user.id).scalar() or 0
        
        analyses_limit = plan.get("analyses_per_month")
        repos_limit = plan.get("repos")
        
        analyses_remaining: int | None = None
        if analyses_limit is not None:
            analyses_remaining = analyses_limit - analyses_count
        
        can_create_repo = True
        if repos_limit is not None:
            can_create_repo = repos_count < repos_limit
        
        return {
            "plan": plan_name,
            "analyses_used": analyses_count,
            "analyses_limit": analyses_limit,
            "repos_used": repos_count,
            "repos_limit": repos_limit,
            "analyses_remaining": analyses_remaining,
            "can_create_repo": can_create_repo,
        }
