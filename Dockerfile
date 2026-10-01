# ==============================================================================
# Production Dockerfile for Rajlabs Certificate Signer
# Optimized for Coolify, Docker Compose, and standalone container deployments
# ==============================================================================
FROM node:22-alpine

LABEL maintainer="Rajlabs PKI Team"
LABEL description="Enterprise PKI Certificate Authority & ACME Signer"

WORKDIR /app

# Install openssl, bash, sqlite, and build dependencies for native compilation
RUN apk add --no-cache openssl bash curl ca-certificates sqlite python3 make g++

# Copy package descriptors
COPY signer-engine/package*.json ./

# Install production dependencies
RUN npm install --production

# Copy application source
COPY signer-engine/server.js ./
COPY signer-engine/public ./public

# Set environment defaults
ENV NODE_ENV=production
ENV PORT=9000
ENV DATA_DIR=/app/data
ENV CA_CERTS_DIR=/app/ca-certs
ENV CA_KEYS_DIR=/app/ca-keys
ENV CA_NAME=int-server
ENV DAYS_VALID=90

# Expose standard application port for Coolify
EXPOSE 9000

# Healthcheck for Coolify container monitoring
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:9000/health || exit 1

CMD ["node", "server.js"]
