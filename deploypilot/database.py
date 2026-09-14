"""Database models and persistence layer."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "sqlite:///./deploypilot.db"
)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    github_id = Column(Integer, unique=True, index=True, nullable=True)
    email = Column(String(255), unique=True, index=True, nullable=True)
    username = Column(String(100), unique=True, index=True)
    avatar_url = Column(String(500), nullable=True)
    access_token = Column(String(500), nullable=True)
    plan = Column(String(20), default="free")  # free, pro, enterprise
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    repos = relationship("Repository", back_populates="owner")
    analyses = relationship("Analysis", back_populates="user")


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, index=True)
    github_id = Column(Integer, unique=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String(255))
    full_name = Column(String(500), index=True)
    webhook_id = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_analysis = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="repos")
    analyses = relationship("Analysis", back_populates="repo")


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    repo_id = Column(Integer, ForeignKey("repositories.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    pr_number = Column(Integer, index=True)
    pr_title = Column(String(500))
    pr_author = Column(String(100))
    risk_score = Column(Float)
    confidence = Column(String(10))
    recommendation = Column(String(500))
    ci_failures = Column(Text, default="[]")  # JSON list
    warnings = Column(Text, default="[]")  # JSON list
    created_at = Column(DateTime, default=datetime.utcnow)

    repo = relationship("Repository", back_populates="analyses")
    user = relationship("User", back_populates="analyses")


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)


def seed_demo_data():
    """Create demo user and repo for testing."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "demo").first()
        if not user:
            user = User(
                username="demo",
                email="demo@deploypilot.dev",
                plan="pro",
                github_id=12345,
            )
            db.add(user)
            db.flush()

            repo = Repository(
                github_id=1,
                owner_id=user.id,
                name="demo-repo",
                full_name="demo/demo-repo",
            )
            db.add(repo)
            db.commit()
    finally:
        db.close()
