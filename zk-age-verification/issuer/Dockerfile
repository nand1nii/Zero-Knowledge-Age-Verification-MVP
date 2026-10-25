# issuer/Dockerfile
# Issuer server (port 3001) plus Chromium for rendering ID cards. docker-compose.yml also
# reuses this image for the one-shot `keygen` service. Build context: the repo root.
FROM node:22-bookworm-slim

# Headless Chromium for Puppeteer, plus fonts for Latin, Devanagari and other scripts.
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-dejavu-core fonts-noto-core \
 && rm -rf /var/lib/apt/lists/*

# Use Debian's Chromium instead of downloading one. Its sandbox cannot run in Docker,
# so it is switched off (the card page has no JavaScript and no network anyway).
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    CHROMIUM_PATH=/usr/bin/chromium \
    CHROMIUM_NO_SANDBOX=1

WORKDIR /app/issuer
COPY issuer/package.json issuer/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY shared /app/shared
COPY issuer/src ./src
COPY issuer/public ./public
COPY issuer/test ./test

# keygen writes the issuer public key here (a named volume shared with the verifier).
RUN mkdir -p /app/shared/generated && chown node:node /app/shared/generated
USER node

ENV NODE_ENV=production HOST=0.0.0.0 PORT=3001
EXPOSE 3001
CMD ["node", "src/server.js"]
