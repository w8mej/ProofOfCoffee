# ------------------------------------------------------------------------------
# Dockerfile — FastAPI mint-api service (Python 3.11 slim)
#
# Purpose:
#   Containerizes the mint-api service for Zero-Trust Minting PoC.
#   Runs as non-root, with a minimal base image and pip-installed dependencies.
#
# Security:
#   • Uses python:3.11-slim (Debian minimal) to reduce image size and attack surface.
#   • Drops root privileges by creating UID/GID 10001 user (`appuser`).
#   • No unnecessary packages installed; no build tools left behind.
#
# Performance:
#   • Uses pip's --no-cache-dir to reduce image bloat.
#   • COPY requirements.txt separately to leverage Docker layer caching for deps.
#
# Operational:
#   • HEALTHCHECK ensures readiness via /healthz endpoint.
#   • Exposes 8080 (FastAPI via uvicorn).
#   • PYTHONPATH set to /app so modules resolve without modifying sys.path.
# ------------------------------------------------------------------------------

FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Install Python dependencies (layer-cached)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code into image
COPY . .

# Ensure Python can locate modules from /app
ENV PYTHONPATH=/app

# ------------------------------------------------------------------------------
# Security hardening: add non-root user
# ------------------------------------------------------------------------------
# UID/GID 10001 is used consistently in docker-compose.yml
RUN useradd -m -u 10001 appuser
USER 10001

# ------------------------------------------------------------------------------
# Network and process startup
# ------------------------------------------------------------------------------
EXPOSE 8080

# Default command: run FastAPI app via uvicorn
CMD ["uvicorn", "src.server.api:app", "--host", "0.0.0.0", "--port", "8080"]

# ------------------------------------------------------------------------------
# Healthcheck — queries /healthz every 30s, times out in 5s, retries 3 times
# ------------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz').read()"