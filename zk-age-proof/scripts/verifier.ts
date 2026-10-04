/**
 * verifier.ts — The relying party (website, app, venue) checks a proof.
 *
 * The verifier receives ONLY:
 *   proof.json             — the Groth16 proof (three curve points)
 *   public.json            — the public inputs (timestamps, threshold, issuer key,
 *                            nullifier, context hash)
 *   verification_key.json  — published once by whoever ran the setup
 *
 * It never sees the birthdate, the salt, the signature, or credential.json,
 * and it learns exactly one bit: "this statement is true" (or not).
 *
 * Verification has two layers, and BOTH matter:
 *   1. Cryptographic: does the proof verify against these public inputs?
 *      (snarkjs groth16 verify)
 *   2. Policy: are these the public inputs *I* wanted? A valid proof only says
 *      "some key signed a credential, and its holder is ≥ minAgeSeconds old at
 *      currentTimestamp, scoped to contextHash". The verifier must still check
 *      that the key is a trusted issuer, the threshold is the one it requires,
 *      the timestamp is fresh, the context is its own, and the nullifier
 *      hasn't been used before. Skip these and anyone could self-issue a
 *      credential or replay an old proof.
 *
 * CLI:
 *   npx ts-node scripts/verifier.ts [--proof output/proof.json] [--public output/public.json] \
 *       [--vkey build/verification_key.json] [--issuer-pubkey output/issuer_public_key.json] \
 *       [--context "acme-app:2026-09-14"] [--min-age-seconds 568036800] [--max-skew 300] \
 *       [--nullifier-db output/seen_nullifiers.json]
 */
import * as fs from "fs";
import * as path from "path";
import { parseArgs } from "util";
import { DEFAULT_OUTPUT_DIR, IssuerPublicKey, writeJson } from "./issuer";
import { BUILD_DIR, computeContextHash, Groth16Proof, MIN_AGE_18_SECONDS, PublicSignals } from "./prover";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const snarkjs = require("snarkjs");

export const VKEY_PATH = path.join(BUILD_DIR, "verification_key.json");

/**
 * Names of the public signals, in the exact order snarkjs writes them to
 * public.json. This must match the `component main {public [...]}` list in
 * circuits/age_check.circom (the circuit has no outputs, so nothing precedes them).
 */
export const PUBLIC_SIGNAL_NAMES = [
  "currentTimestamp",
  "minAgeSeconds",
  "issuerPubKeyX",
  "issuerPubKeyY",
  "nullifier",
  "contextHash",
] as const;

export type PublicInputs = Record<(typeof PUBLIC_SIGNAL_NAMES)[number], string>;

export function decodePublicSignals(publicSignals: PublicSignals): PublicInputs {
  if (publicSignals.length !== PUBLIC_SIGNAL_NAMES.length) {
    throw new Error(`Expected ${PUBLIC_SIGNAL_NAMES.length} public signals, got ${publicSignals.length}`);
  }
  return Object.fromEntries(PUBLIC_SIGNAL_NAMES.map((name, i) => [name, publicSignals[i]])) as PublicInputs;
}

/** Layer 1: pure cryptographic check (snarkjs groth16 verify). */
export async function verifyProof(proof: Groth16Proof, publicSignals: PublicSignals, vkey: object): Promise<boolean> {
  try {
    return await snarkjs.groth16.verify(vkey, publicSignals, proof);
  } catch {
    // Malformed proofs (e.g. points not on the curve) throw; treat as invalid.
    return false;
  }
}

/** Layer 2 inputs. Each check is skipped if its field is left undefined. */
export interface VerifierPolicy {
  /** Issuer public keys this verifier accepts. */
  trustedIssuers?: IssuerPublicKey[];
  /** The proof's minAgeSeconds must be at least this. */
  requiredMinAgeSeconds?: bigint;
  /** The proof must be scoped to exactly this context string. */
  expectedContext?: string;
  /** Freshness: |currentTimestamp - now| must be ≤ maxClockSkewSeconds. */
  now?: bigint;
  maxClockSkewSeconds?: bigint;
  /** Nullifiers already accepted in this context (reuse detection). */
  seenNullifiers?: Set<string>;
}

export interface VerificationResult {
  ok: boolean;
  cryptoValid: boolean;
  failures: string[];
  publicInputs: PublicInputs;
}

/** Layers 1 + 2. Returns a structured result; `ok` is the single bit that matters. */
export async function verifyWithPolicy(
  proof: Groth16Proof,
  publicSignals: PublicSignals,
  vkey: object,
  policy: VerifierPolicy = {},
): Promise<VerificationResult> {
  const publicInputs = decodePublicSignals(publicSignals);
  const failures: string[] = [];

  const cryptoValid = await verifyProof(proof, publicSignals, vkey);
  if (!cryptoValid) failures.push("Groth16 proof does not verify against these public inputs");

  if (policy.trustedIssuers) {
    const trusted = policy.trustedIssuers.some(
      (k) => k.x === publicInputs.issuerPubKeyX && k.y === publicInputs.issuerPubKeyY,
    );
    if (!trusted) failures.push("Credential was signed by an issuer this verifier does not trust");
  }
  if (policy.requiredMinAgeSeconds !== undefined && BigInt(publicInputs.minAgeSeconds) < policy.requiredMinAgeSeconds) {
    failures.push(`Proof is for a lower age threshold (${publicInputs.minAgeSeconds}s) than required`);
  }
  if (policy.expectedContext !== undefined && computeContextHash(policy.expectedContext).toString() !== publicInputs.contextHash) {
    failures.push("Proof is scoped to a different context (possible replay from another service)");
  }
  if (policy.now !== undefined && policy.maxClockSkewSeconds !== undefined) {
    const skew = BigInt(publicInputs.currentTimestamp) - policy.now;
    if (skew > policy.maxClockSkewSeconds || -skew > policy.maxClockSkewSeconds) {
      failures.push("Proof timestamp is not fresh (stale proof or wrong clock)");
    }
  }
  if (policy.seenNullifiers?.has(publicInputs.nullifier)) {
    failures.push("Nullifier already used in this context (credential reuse)");
  }

  return { ok: failures.length === 0, cryptoValid, failures, publicInputs };
}

/** Pretty-print exactly what the verifier sees: the public inputs, nothing else. */
export function formatPublicInputs(publicInputs: PublicInputs): string {
  const width = Math.max(...PUBLIC_SIGNAL_NAMES.map((n) => n.length));
  return PUBLIC_SIGNAL_NAMES.map((n) => `  ${n.padEnd(width)} = ${publicInputs[n]}`).join("\n");
}

// -----------------------------------------------------------------------------
// CLI
// -----------------------------------------------------------------------------
async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      proof: { type: "string", default: path.join(DEFAULT_OUTPUT_DIR, "proof.json") },
      public: { type: "string", default: path.join(DEFAULT_OUTPUT_DIR, "public.json") },
      vkey: { type: "string", default: VKEY_PATH },
      "issuer-pubkey": { type: "string" },
      context: { type: "string" },
      "min-age-seconds": { type: "string", default: MIN_AGE_18_SECONDS.toString() },
      "max-skew": { type: "string", default: "300" },
      "nullifier-db": { type: "string" },
    },
  });

  const readJson = (p: string) => JSON.parse(fs.readFileSync(p, "utf8"));
  const proof: Groth16Proof = readJson(values.proof!);
  const publicSignals: PublicSignals = readJson(values.public!);
  const vkey = readJson(values.vkey!);

  const nullifierDb = values["nullifier-db"];
  const seen: string[] = nullifierDb && fs.existsSync(nullifierDb) ? readJson(nullifierDb) : [];

  const result = await verifyWithPolicy(proof, publicSignals, vkey, {
    trustedIssuers: values["issuer-pubkey"] ? [readJson(values["issuer-pubkey"])] : undefined,
    requiredMinAgeSeconds: BigInt(values["min-age-seconds"]!),
    expectedContext: values.context,
    now: BigInt(Math.floor(Date.now() / 1000)),
    maxClockSkewSeconds: BigInt(values["max-skew"]!),
    seenNullifiers: new Set(seen),
  });

  console.log("Verifier received these public inputs (this is ALL it ever sees):");
  console.log(formatPublicInputs(result.publicInputs));
  if (!values["issuer-pubkey"]) console.log("  (warning: no --issuer-pubkey given; issuer trust NOT checked)");
  if (!values.context) console.log("  (warning: no --context given; context binding NOT checked)");

  if (result.ok) {
    if (nullifierDb) writeJson(nullifierDb, [...seen, result.publicInputs.nullifier]);
    console.log("\nResult: PASS — holder is over the age threshold.");
    return 0;
  }
  console.log("\nResult: FAIL");
  for (const f of result.failures) console.log(`  - ${f}`);
  return 1;
}

if (require.main === module) {
  main()
    .then((code) => process.exit(code)) // snarkjs keeps worker threads alive; exit explicitly
    .catch((err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exit(1);
    });
}
