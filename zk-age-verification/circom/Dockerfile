# circom/Dockerfile
# One-shot "circuit builder" (not a server): compiles the circuit and runs the local,
# NOT secure trusted setup, writing the wasm / zkey / verification key to /artifacts.
# Build context is the repo root (see docker-compose.yml) so shared/ can be copied in.

# ---- Stage 1: build the Circom compiler from source (works on amd64 and arm64) ----
# The full (non-slim) Rust image already has git, so no apt step is needed.
# Only the compiled binary is kept; this stage is thrown away.
FROM rust:1.79-bookworm AS circom
ARG CIRCOM_VERSION=v2.1.9
RUN git clone --depth 1 --branch "${CIRCOM_VERSION}" https://github.com/iden3/circom.git /circom \
 && cd /circom \
 && cargo build --release --locked \
 && install -m 0755 target/release/circom /usr/local/bin/circom \
 && circom --version

# ---- Stage 2: Node + snarkjs to run scripts/build.sh ----
FROM node:22-bookworm-slim
COPY --from=circom /usr/local/bin/circom /usr/local/bin/circom

WORKDIR /app/circom
COPY circom/package.json circom/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY shared /app/shared
COPY circom/circuits ./circuits
COPY circom/scripts ./scripts
COPY circom/test ./test

# The artifacts volume is mounted here. Creating it owned by `node` makes a fresh
# named volume writable by the non-root user.
RUN mkdir -p /artifacts && chown node:node /artifacts
USER node
ENV ARTIFACTS_DIR=/artifacts

CMD ["bash", "scripts/build.sh"]
