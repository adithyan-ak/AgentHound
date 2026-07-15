# Authored MCP target with an admin surface for the offline collector harness.
# Multi-arch (arm64 + amd64) from the official slim base.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./

# Drop privileges.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8080

# GATED_RESOURCE_TOKEN_HASH is injected at runtime by the harness (sha256hex of
# the test bearer token). Absent it, the gate simply denies every read of the
# gated resource, which is still the correct unauth-control behavior.
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=5 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status==200 else 1)"]

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
