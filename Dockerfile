FROM python:3.13-slim

WORKDIR /app

# Install dependencies first for better caching
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy application code
COPY deploypilot/ ./deploypilot/

# Create non-root user
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "deploypilot.server:app", "--host", "0.0.0.0", "--port", "8000"]
