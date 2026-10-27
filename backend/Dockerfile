# ==============================================================================
# SecAudit / Aura Glass - Standalone Backend Dockerfile (VPS Deployment)
# ==============================================================================

# --- Stage 1: Extract Nuclei Security Scanner Binary ---
FROM projectdiscovery/nuclei:v3.3.8 AS nuclei-bin

# --- Stage 2: Production Python Runtime ---
FROM python:3.11-slim AS runtime

# Install system dependencies (git for Whitebox repo cloning, ca-certificates, curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Nuclei binary from ProjectDiscovery official image
COPY --from=nuclei-bin /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app

# Install Python backend dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code into /app/backend
COPY . ./backend/

# Create dedicated directory for persistent SQLite database
RUN mkdir -p /app/data

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    DATABASE_PATH="/app/data/secaudit.db" \
    NUCLEI_TEMPLATES_DIR="/app/backend/rules/nuclei" \
    HOST="0.0.0.0" \
    PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
