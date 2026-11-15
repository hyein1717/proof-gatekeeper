# Proof Gatekeeper — deploy draft (prepared 2026-11-15, NOT deployed)
# Node 24, no framework. The service listens on $PORT (default 8080) and
# serves POST /agent plus GET /healthz. Single instance only: decisions and
# idempotency live in data/store.json, so the volume mount in fly.toml matters.
FROM node:24-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
COPY test ./test
COPY circuits ./circuits
RUN npm run build
EXPOSE 8080
CMD ["node", "dist/src/server.js"]
