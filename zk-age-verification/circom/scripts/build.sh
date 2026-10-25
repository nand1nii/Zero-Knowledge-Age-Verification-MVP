#!/usr/bin/env bash
# circom/scripts/build.sh
# Compiles the circuit and runs a LOCAL, NOT SECURE Groth16 trusted setup (demo only).
# Writes age_check.wasm, age_check_final.zkey and verification_key.json to $ARTIFACTS_DIR.
#
# Usage:  bash scripts/build.sh            (skips the build if the circuit is unchanged)
#         FORCE_REBUILD=1 bash scripts/build.sh
# Env:    ARTIFACTS_DIR  output folder (default: ../artifacts next to this module)
set -euo pipefail

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="$MODULE_DIR/scripts/build.sh"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$MODULE_DIR/../artifacts}"
mkdir -p "$ARTIFACTS_DIR"
ARTIFACTS_DIR="$(cd "$ARTIFACTS_DIR" && pwd)"   # make absolute before we cd
BUILD_DIR="$ARTIFACTS_DIR/build"     # intermediate files: r1cs, sym, ptau
NAME="age_check"
CIRCUIT="$MODULE_DIR/circuits/$NAME.circom"
PTAU_POWER=14                        # 2^14 = 16384 constraints, enough for this circuit
SNARKJS="npx --no-install snarkjs"

cd "$MODULE_DIR"
mkdir -p "$BUILD_DIR"

if ! command -v circom >/dev/null 2>&1; then
  echo "ERROR: 'circom' is not installed. Install Circom 2.1.x (https://docs.circom.io)" >&2
  echo "       or run the build in Docker: docker compose run --rm circom-builder" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 0. Skip if the artifacts were already built from this exact circuit + tools.
# ---------------------------------------------------------------------------
CIRCOM_VERSION="$(circom --version)"
SNARKJS_VERSION="$(node -p "require('./node_modules/snarkjs/package.json').version")"
CIRCOMLIB_VERSION="$(node -p "require('./node_modules/circomlib/package.json').version")"
FINGERPRINT="$(cat "$CIRCUIT" "$SCRIPT_PATH" | sha256sum | cut -d' ' -f1)"
FINGERPRINT="$(echo "$FINGERPRINT $CIRCOM_VERSION $SNARKJS_VERSION $CIRCOMLIB_VERSION" | sha256sum | cut -d' ' -f1)"
STAMP="$ARTIFACTS_DIR/build-info.json"

if [ "${FORCE_REBUILD:-0}" != "1" ] && [ -f "$STAMP" ] \
   && grep -q "\"fingerprint\": \"$FINGERPRINT\"" "$STAMP" \
   && [ -f "$ARTIFACTS_DIR/$NAME.wasm" ] && [ -f "$ARTIFACTS_DIR/${NAME}_final.zkey" ] \
   && [ -f "$ARTIFACTS_DIR/verification_key.json" ]; then
  echo "==> Artifacts are up to date ($ARTIFACTS_DIR). Set FORCE_REBUILD=1 to rebuild."
  exit 0
fi

# Remove the stamp first, so a build that fails halfway is never mistaken for a good one.
rm -f "$STAMP"

# ---------------------------------------------------------------------------
# 1. Compile: r1cs (constraints), wasm (witness generator), sym (signal names).
#    `-l node_modules` lets the circuit include "circomlib/circuits/...".
# ---------------------------------------------------------------------------
echo "==> [1/5] Compiling $NAME.circom with $CIRCOM_VERSION"
circom "$CIRCUIT" --r1cs --wasm --sym -l node_modules -o "$BUILD_DIR"
$SNARKJS r1cs info "$BUILD_DIR/$NAME.r1cs"

# ---------------------------------------------------------------------------
# 2. Powers of Tau (phase 1), generated locally with ONE contributor.
#    NOT A SECURE CEREMONY: whoever runs this could keep the secret randomness and
#    forge proofs. Fine for a demo. Cached because it does not depend on the circuit.
# ---------------------------------------------------------------------------
PTAU="$BUILD_DIR/pot${PTAU_POWER}_final.ptau"
if [ ! -f "$PTAU" ]; then
  echo "==> [2/5] Powers of Tau 2^$PTAU_POWER (local, NOT secure)"
  $SNARKJS powersoftau new bn128 "$PTAU_POWER" "$BUILD_DIR/pot_0000.ptau"
  $SNARKJS powersoftau contribute "$BUILD_DIR/pot_0000.ptau" "$BUILD_DIR/pot_0001.ptau" \
    --name="demo contribution" -e="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
  $SNARKJS powersoftau prepare phase2 "$BUILD_DIR/pot_0001.ptau" "$PTAU"
  rm -f "$BUILD_DIR/pot_0000.ptau" "$BUILD_DIR/pot_0001.ptau"
else
  echo "==> [2/5] Reusing cached $PTAU"
fi

# ---------------------------------------------------------------------------
# 3. Groth16 circuit-specific setup (phase 2) + one local contribution.
# ---------------------------------------------------------------------------
echo "==> [3/5] Groth16 setup (local, NOT secure)"
$SNARKJS groth16 setup "$BUILD_DIR/$NAME.r1cs" "$PTAU" "$BUILD_DIR/${NAME}_0000.zkey"
$SNARKJS zkey contribute "$BUILD_DIR/${NAME}_0000.zkey" "$BUILD_DIR/${NAME}_final.zkey" \
  --name="demo phase2 contribution" -e="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
rm -f "$BUILD_DIR/${NAME}_0000.zkey"

# ---------------------------------------------------------------------------
# 4. Export the verification key and sanity-check the proving key.
# ---------------------------------------------------------------------------
echo "==> [4/5] Exporting verification key and checking the zkey"
$SNARKJS zkey export verificationkey "$BUILD_DIR/${NAME}_final.zkey" "$BUILD_DIR/verification_key.json"
$SNARKJS zkey verify "$BUILD_DIR/$NAME.r1cs" "$PTAU" "$BUILD_DIR/${NAME}_final.zkey"

# ---------------------------------------------------------------------------
# 5. Publish the three outputs together, then write the stamp last.
# ---------------------------------------------------------------------------
echo "==> [5/5] Writing artifacts to $ARTIFACTS_DIR"
mv -f "$BUILD_DIR/${NAME}_js/$NAME.wasm" "$ARTIFACTS_DIR/$NAME.wasm"
mv -f "$BUILD_DIR/${NAME}_final.zkey" "$ARTIFACTS_DIR/${NAME}_final.zkey"
mv -f "$BUILD_DIR/verification_key.json" "$ARTIFACTS_DIR/verification_key.json"
rm -rf "$BUILD_DIR/${NAME}_js"

cat > "$STAMP" <<EOF
{
  "fingerprint": "$FINGERPRINT",
  "circom": "$CIRCOM_VERSION",
  "snarkjs": "$SNARKJS_VERSION",
  "circomlib": "$CIRCOMLIB_VERSION",
  "builtAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "warning": "Local single-party trusted setup. NOT SECURE. Demo only."
}
EOF

echo "Done: $NAME.wasm, ${NAME}_final.zkey, verification_key.json"
