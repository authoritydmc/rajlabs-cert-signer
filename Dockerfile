# ==============================================================================
# Rajlabs Certificate Signer v2 — React (Vite) + FastAPI
# Multi-stage build for Coolify / Docker Compose / standalone containers.
# API contract is identical to v1 (Node engine), so existing database.json
# files and FreeRADIUS integrations carry over untouched.
# ==============================================================================

# ---- Stage 1: build the React UI ----
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: Python runtime ----
FROM python:3.13-slim
LABEL maintainer="Rajlabs PKI Team"
LABEL description="Enterprise PKI Certificate Authority & Signer (FastAPI + React)"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=9000 \
    DATA_DIR=/app/data

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY --from=ui /ui/dist ./app/static

VOLUME /app/data
EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${PORT:-9000}/health || exit 1

# Single worker: sessions + JSON store are in-process.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-9000} --workers 1"]
