# Dockerfile - fix bez dynamického FROM

FROM node:18-alpine AS base
LABEL maintainer="Martin22"
LABEL description="SKTorrent Hybrid Stremio Addon s direct streaming podporou"
LABEL version="2.0.0"

WORKDIR /app

RUN apk add --no-cache \
    curl \
    ca-certificates \
    tzdata \
    tini

ENV TZ=Europe/Prague
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

COPY package*.json ./

# Production stage
FROM base AS production
ENV NODE_ENV=production
RUN npm ci --only=production && npm cache clean --force
COPY --chown=nodejs:nodejs . .
RUN mkdir -p /app/logs /app/cache && chown -R nodejs:nodejs /app/logs /app/cache
RUN chmod +x /app/sktorrent-addon.js
USER nodejs
EXPOSE 7000
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:7000/health || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "sktorrent-addon.js"]

# Development stage
FROM base AS development
ENV NODE_ENV=development
RUN npm ci && npm cache clean --force && npm install -g nodemon
COPY --chown=nodejs:nodejs . .
RUN mkdir -p /app/logs /app/cache /app/coverage && chown -R nodejs:nodejs /app/logs /app/cache /app/coverage
USER nodejs
EXPOSE 7000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=2 \
    CMD curl -f http://localhost:7000/health || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["nodemon", "--inspect=0.0.0.0:9229", "sktorrent-addon.js"]
