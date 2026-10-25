# verifier/Dockerfile
# The age-locked website (port 3003). Reads verification_key.json from the read-only
# `artifacts` volume and the issuer public key from the keygen volume. Build context: repo root.
FROM node:22-bookworm-slim

WORKDIR /app/verifier
COPY verifier/package.json verifier/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY shared /app/shared
COPY verifier/src ./src
COPY verifier/public ./public
COPY verifier/protected ./protected
COPY verifier/test ./test

USER node
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3003 ARTIFACTS_DIR=/artifacts \
    ISSUER_PUBKEY_PATH=/app/shared/generated/issuer-pubkey.json
EXPOSE 3003
CMD ["node", "src/server.js"]
