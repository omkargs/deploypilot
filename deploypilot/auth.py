"""GitHub OAuth authentication and user management."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from deploypilot.database import SessionLocal, User, Repository, init_db

router = APIRouter(prefix="/auth", tags=["auth"])

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_CALLBACK_URL = os.environ.get("GITHUB_CALLBACK_URL", "http://localhost:8000/auth/github/callback")
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))

# In-memory session store (use Redis in production)
sessions: dict[str, dict[str, Any]] = {}


def create_session(user_id: int, username: str) -> str:
    """Create a session token."""
    token = secrets.token_urlsafe(32)
    sessions[token] = {
        "user_id": user_id,
        "username": username,
        "created_at": datetime.utcnow().isoformat(),
    }
    return token


def get_session(token: str) -> dict[str, Any] | None:
    """Validate and return session."""
    return sessions.get(token)


@router.get("/github/login")
async def github_login():
    """Redirect to GitHub OAuth."""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")
    
    url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_CALLBACK_URL}"
        f"&scope=read:user user:email repo"
    )
    return RedirectResponse(url=url)


@router.get("/github/callback")
async def github_callback(code: str, state: str | None = None):
    """Handle GitHub OAuth callback."""
    if not code:
        raise HTTPException(status_code=400, detail="No code provided")
    
    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to get access token")
        
        token_data = resp.json()
        access_token = token_data.get("access_token")
        
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token in response")
        
        # Get user info
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        
        if user_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to get user info")
        
        github_user = user_resp.json()
    
    # Create or update user
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.github_id == github_user["id"]).first()
        if not user:
            user = User(
                github_id=github_user["id"],
                username=github_user["login"],
                email=github_user.get("email"),
                avatar_url=github_user.get("avatar_url"),
                access_token=access_token,
            )
            db.add(user)
        else:
            user.access_token = access_token
            user.last_login = datetime.utcnow()
            if github_user.get("email"):
                user.email = github_user["email"]
        
        db.commit()
        db.refresh(user)
        
        # Create session
        session_token = create_session(user.id, user.username)
        
        # Redirect to dashboard with session
        response = RedirectResponse(url="/dashboard")
        response.set_cookie(
            key="session",
            value=session_token,
            httponly=True,
            secure=False,  # Set True in production with HTTPS
            samesite="lax",
            max_age=86400 * 7,  # 7 days
        )
        return response
    finally:
        db.close()


@router.get("/me")
async def get_current_user(request: Request):
    """Get current authenticated user."""
    session_token = request.cookies.get("session")
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    session = get_session(session_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == session["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "avatar_url": user.avatar_url,
            "plan": user.plan,
            "created_at": user.created_at.isoformat(),
        }
    finally:
        db.close()


@router.post("/logout")
async def logout(request: Request):
    """Clear session."""
    session_token = request.cookies.get("session")
    if session_token and session_token in sessions:
        del sessions[session_token]
    
    response = RedirectResponse(url="/")
    response.delete_cookie("session")
    return response
