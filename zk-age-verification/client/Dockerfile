# client/Dockerfile
# The ZK wallet's static web server (port 3002). It serves the wasm/zkey from the read-only
# `artifacts` volume; proving happens in the user's browser. Build context: the repo root.
FROM node:22-bookworm-slim

WORKDIR /app/client
COPY client/package.json client/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY shared /app/shared
COPY client/src ./src
COPY client/public ./public
COPY client/test ./test

USER node
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3002 ARTIFACTS_DIR=/artifacts
EXPOSE 3002
CMD ["node", "src/server.js"]
