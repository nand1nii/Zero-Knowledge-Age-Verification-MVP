#!/usr/bin/env bash
# =============================================================================
#  setup.sh — compile the circuit and run a Groth16 trusted setup.
#
#  ############################################################################
#  ##                                                                        ##
#  ##   WARNING: THIS TRUSTED SETUP IS FOR DEVELOPMENT / DEMO ONLY.          ##
#  ##   IT IS *NOT* PRODUCTION-SAFE.                                         ##
#  ##                                                                        ##
#  ##   Groth16 needs a "trusted setup" that produces secret randomness      ##
#  ##   ("toxic waste"). Anyone who knows that randomness can forge proofs   ##
#  ##   of FALSE statements (e.g. "I am over 18" for a 12-year-old) that     ##
#  ##   still verify. Here, a single machine generates all of it, using      ##
#  ##   hard-coded / locally generated entropy, in one process. So whoever  ##
#  ##   ran this script could, in principle, forge proofs.                   ##
#  ##                                                                        ##
#  ##   A real deployment needs EITHER:                                      ##
#  ##     * a proper multi-party ceremony (secure as long as ONE             ##
#  ##       participant destroys their contribution), e.g. reuse the         ##
#  ##       Hermez/Polygon or Perpetual Powers of Tau phase-1 file plus a    ##
#  ##       public multi-party phase-2 for this circuit; OR                  ##
#  ##     * a proving system without a per-circuit trusted setup, such as    ##
#  ##       PLONK/FFLONK with a universal setup, or a transparent system     ##
#  ##       like Halo2 / STARKs.                                             ##
#  ##                                                                        ##
#  ############################################################################
#
#  Outputs (all under build/):
#    age_check.r1cs              constraint system
#    age_check.sym               symbol table (debugging)
#    age_check_js/age_check.wasm witness generator used by the prover
#    pot14_final.ptau            phase-1 powers of tau (2^14 constraints max)
#    age_check_final.zkey        proving key  (prover needs this)
#    verification_key.json       verifying key (verifier needs this)
# =============================================================================
set -euo pipefail

# Always run relative to the project root, wherever this was invoked from.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUILD_DIR="build"
CIRCUIT="circuits/age_check.circom"
NAME="age_check"
# 2^14 = 16,384 constraints. The circuit is ~9.5k constraints (EdDSA dominates),
# so this is the smallest power of two that fits.
POT_POWER=14

SNARKJS="npx --no-install snarkjs"

mkdir -p "$BUILD_DIR"

# -----------------------------------------------------------------------------
# 1. Compile the circuit.
#    Prefer a natively installed `circom` (Rust binary) if one is on PATH;
#    otherwise fall back to the `circom2` npm package, a WebAssembly build of
#    the same Circom 2.x compiler, so `npm install` alone is enough.
#    `-l node_modules` lets the circuit `include "circomlib/circuits/..."`.
# -----------------------------------------------------------------------------
if command -v circom >/dev/null 2>&1 && circom --version 2>/dev/null | grep -q "circom compiler 2"; then
  CIRCOM="circom"
else
  CIRCOM="npx --no-install circom2"
fi
echo "==> [1/5] Compiling $CIRCUIT with: $CIRCOM"
$CIRCOM "$CIRCUIT" --r1cs --wasm --sym -l node_modules -o "$BUILD_DIR"
$SNARKJS r1cs info "$BUILD_DIR/$NAME.r1cs"

# -----------------------------------------------------------------------------
# 2. Phase 1: Powers of Tau (circuit-independent).
#    DEV ONLY: a single local contributor with fixed entropy. In production,
#    download a phase-1 file from a large public ceremony instead.
#    Skipped if already present, because it's the slowest step and doesn't
#    depend on the circuit.
# -----------------------------------------------------------------------------
PTAU_FINAL="$BUILD_DIR/pot${POT_POWER}_final.ptau"
if [ ! -f "$PTAU_FINAL" ]; then
  echo "==> [2/5] Phase 1: powers of tau (2^$POT_POWER) — DEV ONLY, NOT SECURE"
  $SNARKJS powersoftau new bn128 "$POT_POWER" "$BUILD_DIR/pot${POT_POWER}_0000.ptau"
  $SNARKJS powersoftau contribute "$BUILD_DIR/pot${POT_POWER}_0000.ptau" "$BUILD_DIR/pot${POT_POWER}_0001.ptau" \
    --name="dev-only contribution" -e="dev-only entropy: NOT SECRET, NOT SAFE $(date +%s%N)"
  $SNARKJS powersoftau prepare phase2 "$BUILD_DIR/pot${POT_POWER}_0001.ptau" "$PTAU_FINAL"
  rm -f "$BUILD_DIR/pot${POT_POWER}_0000.ptau" "$BUILD_DIR/pot${POT_POWER}_0001.ptau"
else
  echo "==> [2/5] Phase 1: reusing existing $PTAU_FINAL"
fi

# -----------------------------------------------------------------------------
# 3. Phase 2: circuit-specific setup (Groth16 needs one per circuit).
#    Re-run every time because the circuit may have changed.
# -----------------------------------------------------------------------------
echo "==> [3/5] Phase 2: Groth16 circuit-specific setup — DEV ONLY, NOT SECURE"
$SNARKJS groth16 setup "$BUILD_DIR/$NAME.r1cs" "$PTAU_FINAL" "$BUILD_DIR/${NAME}_0000.zkey"
$SNARKJS zkey contribute "$BUILD_DIR/${NAME}_0000.zkey" "$BUILD_DIR/${NAME}_final.zkey" \
  --name="dev-only phase2 contribution" -e="dev-only phase2 entropy: NOT SECRET $(date +%s%N)"
rm -f "$BUILD_DIR/${NAME}_0000.zkey"

# -----------------------------------------------------------------------------
# 4. Export the verification key — the only artifact a verifier needs.
# -----------------------------------------------------------------------------
echo "==> [4/5] Exporting verification key"
$SNARKJS zkey export verificationkey "$BUILD_DIR/${NAME}_final.zkey" "$BUILD_DIR/verification_key.json"

# -----------------------------------------------------------------------------
# 5. Sanity check: the final zkey is consistent with the circuit and ptau.
# -----------------------------------------------------------------------------
echo "==> [5/5] Verifying zkey against circuit + ptau"
$SNARKJS zkey verify "$BUILD_DIR/$NAME.r1cs" "$PTAU_FINAL" "$BUILD_DIR/${NAME}_final.zkey"

cat <<'EOF'

Setup complete.
  Proving key:       build/age_check_final.zkey
  Verification key:  build/verification_key.json
  Witness generator: build/age_check_js/age_check.wasm

REMINDER: these keys come from a single-party, dev-only trusted setup.
Whoever ran this could forge proofs. Do NOT use them for anything real.
EOF
