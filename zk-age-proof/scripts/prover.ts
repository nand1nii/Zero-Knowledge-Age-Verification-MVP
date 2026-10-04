/**
 * prover.ts — The credential holder generates a zero-knowledge proof.
 *
 * Input:  credential.json (PRIVATE), plus the public parameters of this
 *         particular check: current time, minimum age, and a context string.
 * Output: proof.json + public.json — the ONLY things sent to a verifier.
 *
 * If the statement is false (e.g. the holder is under the threshold, or the
 * credential was tampered with), witness generation fails inside snarkjs and
 * NO proof is produced. That's the core guarantee: you can't even construct a
 * proof of a false statement (short of breaking the crypto or the trusted
 * setup), so the verifier never has to "catch" a lie.
 *
 * CLI:
 *   npx ts-node scripts/prover.ts --context "acme-app:2026-09-14" \
 *       [--credential output/credential.json] [--current-timestamp <unix s>] \
 *       [--min-age-seconds 568036800] [--out-dir output]
 */
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { parseArgs } from "util";
import { Credential, DEFAULT_OUTPUT_DIR, PROJECT_ROOT, writeJson } from "./issuer";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require("snarkjs");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { buildPoseidon } = require("circomlibjs");

export const BUILD_DIR = path.join(PROJECT_ROOT, "build");
export const WASM_PATH = path.join(BUILD_DIR, "age_check_js", "age_check.wasm");
export const ZKEY_PATH = path.join(BUILD_DIR, "age_check_final.zkey");

/**
 * "18 years" in seconds, using the average Julian year (365.25 days).
 * Simple and explainable; a production system would do calendar-exact math
 * (birthdays, leap years, time zones) when choosing the threshold.
 */
export const SECONDS_PER_YEAR = 365.25 * 24 * 60 * 60; // 31,557,600
export const MIN_AGE_18_SECONDS = BigInt(18 * SECONDS_PER_YEAR); // 568,036,800

/** Shape of proof.json produced by snarkjs (Groth16 over BN254). */
export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

/** public.json is just an array of decimal strings, in the circuit's public-input order. */
export type PublicSignals = string[];

/**
 * Map an arbitrary context string (e.g. "acme-app:2026-09-14") to a field
 * element for use as `contextHash`.
 *
 * We use SHA-256 here (not Poseidon) because it's computed off-circuit and
 * any verifier can reproduce it with standard tooling. We keep the first 31
 * bytes (248 bits) so the result is always < the BN254 field modulus and can
 * be used as a circuit input without reduction.
 */
export function computeContextHash(contextString: string): bigint {
  const digest = createHash("sha256").update(contextString, "utf8").digest();
  return BigInt("0x" + digest.subarray(0, 31).toString("hex"));
}

/** nullifier = Poseidon(salt, contextHash) — must match Step 4 of the circuit. */
export async function computeNullifier(salt: bigint, contextHash: bigint): Promise<bigint> {
  const poseidon = await buildPoseidon();
  return poseidon.F.toObject(poseidon([salt, contextHash]));
}

export interface ProofRequest {
  currentTimestamp: bigint;
  minAgeSeconds: bigint;
  contextString: string;
}

/**
 * Assemble the complete circuit input: private credential fields plus the
 * public parameters. Key names must match the circuit's `signal input` names.
 * snarkjs accepts decimal strings for field elements.
 */
export async function buildCircuitInput(credential: Credential, req: ProofRequest): Promise<Record<string, string>> {
  const contextHash = computeContextHash(req.contextString);
  const nullifier = await computeNullifier(BigInt(credential.salt), contextHash);
  return {
    // --- private ---
    birthdateTimestamp: credential.birthdateTimestamp,
    salt: credential.salt,
    signatureR8x: credential.signature.R8x,
    signatureR8y: credential.signature.R8y,
    signatureS: credential.signature.S,
    // --- public ---
    currentTimestamp: req.currentTimestamp.toString(),
    minAgeSeconds: req.minAgeSeconds.toString(),
    issuerPubKeyX: credential.issuerPubKey.x,
    issuerPubKeyY: credential.issuerPubKey.y,
    nullifier: nullifier.toString(),
    contextHash: contextHash.toString(),
  };
}

/** Thrown when no valid witness exists, i.e. the statement being proven is false. */
export class ProofGenerationError extends Error {
  constructor(cause: unknown) {
    super(
      "Proof generation FAILED: the circuit's constraints cannot be satisfied with this credential " +
        "(e.g. the holder is under the age threshold, or the credential/signature is invalid). " +
        "No proof exists for a false statement.",
      { cause },
    );
    this.name = "ProofGenerationError";
  }
}

/**
 * Run snarkjs `groth16 fullprove`: compute the witness with the compiled
 * .wasm, then the Groth16 proof with the proving key.
 *
 * Note we deliberately do NOT pre-check the age in JavaScript. The circuit is
 * the single source of truth; if the statement is false, the witness
 * calculator hits a failing constraint and throws.
 */
export async function generateProof(
  credential: Credential,
  req: ProofRequest,
  paths: { wasm: string; zkey: string } = { wasm: WASM_PATH, zkey: ZKEY_PATH },
): Promise<{ proof: Groth16Proof; publicSignals: PublicSignals }> {
  for (const p of [paths.wasm, paths.zkey]) {
    if (!fs.existsSync(p)) throw new Error(`Missing ${p}. Run \`npm run setup\` first.`);
  }
  const input = await buildCircuitInput(credential, req);
  try {
    // No logger passed: snarkjs stays quiet, so private inputs never hit logs.
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, paths.wasm, paths.zkey);
    return { proof, publicSignals };
  } catch (err) {
    throw new ProofGenerationError(err);
  }
}

// -----------------------------------------------------------------------------
// CLI
// -----------------------------------------------------------------------------
async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      credential: { type: "string", default: path.join(DEFAULT_OUTPUT_DIR, "credential.json") },
      "current-timestamp": { type: "string", default: Math.floor(Date.now() / 1000).toString() },
      "min-age-seconds": { type: "string", default: MIN_AGE_18_SECONDS.toString() },
      context: { type: "string" },
      "out-dir": { type: "string", default: DEFAULT_OUTPUT_DIR },
    },
  });
  if (!values.context) {
    console.error('Usage: prover.ts --context "app-name:session" [--credential ...] [--current-timestamp ...] [--min-age-seconds ...] [--out-dir ...]');
    process.exit(2);
  }

  const credential: Credential = JSON.parse(fs.readFileSync(values.credential!, "utf8"));
  const { proof, publicSignals } = await generateProof(credential, {
    currentTimestamp: BigInt(values["current-timestamp"]!),
    minAgeSeconds: BigInt(values["min-age-seconds"]!),
    contextString: values.context,
  });

  writeJson(path.join(values["out-dir"]!, "proof.json"), proof);
  writeJson(path.join(values["out-dir"]!, "public.json"), publicSignals);
  console.log(`Prover: wrote proof.json and public.json to ${values["out-dir"]}`);
}

if (require.main === module) {
  main()
    .then(() => process.exit(0)) // snarkjs keeps worker threads alive; exit explicitly
    .catch((err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exit(1);
    });
}
