# Dockerfile - Kompletný Docker súbor pre SKTorrent Hybrid Addon
FROM node:18-alpine AS base

# Metadata
LABEL maintainer="Martin22"
LABEL description="SKTorrent Hybrid Stremio Addon s direct streaming podporou"
LABEL version="2.0.0"

# Nastavenie pracovného adresára
WORKDIR /app

# Inštalácia systémových závislostí
RUN apk add --no-cache \
    curl \
    ca-certificates \
    tzdata \
    tini

# Nastavenie timezone
ENV TZ=Europe/Prague
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Vytvorenie non-root používateľa
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Kopírovanie package files
COPY package*.json ./

# Production stage
FROM base AS production

# Build argument pre NODE_ENV
ARG NODE_ENV=production
ENV NODE_ENV=$NODE_ENV

# Inštalácia production dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Kopírovanie aplikačných súborov
COPY --chown=nodejs:nodejs . .

# Vytvorenie potrebných adresárov
RUN mkdir -p /app/logs /app/cache && \
    chown -R nodejs:nodejs /app/logs /app/cache

# Nastavenie permissions
RUN chmod +x /app/sktorrent-addon.js

# Prepnutie na non-root používateľa
USER nodejs

# Exponovanie portu
EXPOSE 7000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:7000/health || exit 1

# Použitie tini ako init systém
ENTRYPOINT ["/sbin/tini", "--"]

# Spustenie aplikácie
CMD ["node", "sktorrent-addon.js"]

# Development stage
FROM base AS development

# Build argument pre NODE_ENV
ARG NODE_ENV=development
ENV NODE_ENV=$NODE_ENV

# Inštalácia všetkých dependencies vrátane dev
RUN npm ci && \
    npm cache clean --force

# Inštalácia globálnych dev nástrojov
RUN npm install -g nodemon

# Kopírovanie aplikačných súborov
COPY --chown=nodejs:nodejs . .

# Vytvorenie potrebných adresárov
RUN mkdir -p /app/logs /app/cache /app/coverage && \
    chown -R nodejs:nodejs /app/logs /app/cache /app/coverage

# Prepnutie na non-root používateľa
USER nodejs

# Exponovanie portu
EXPOSE 7000

# Development health check (kratšie intervaly)
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=2 \
    CMD curl -f http://localhost:7000/health || exit 1

# Použitie tini ako init systém
ENTRYPOINT ["/sbin/tini", "--"]

# Development command s nodemon
CMD ["nodemon", "--inspect=0.0.0.0:9229", "sktorrent-addon.js"]

# Multi-stage build završenie
FROM ${NODE_ENV} AS final

# Runtime labels
LABEL org.opencontainers.image.title="SKTorrent Hybrid Addon"
LABEL org.opencontainers.image.description="Stremio addon s direct streaming podporou"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.authors="Martin22"
LABEL org.opencontainers.image.source="https://github.com/Martin22/SKTorrent-Hybrid-Stremio-Addon"
LABEL org.opencontainers.image.licenses="MIT"

# Runtime environment variables
ENV NODE_OPTIONS="--max-old-space-size=512"
ENV UV_THREADPOOL_SIZE=4

# Final workdir setup
WORKDIR /app

# Signal handling
STOPSIGNAL SIGTERM
