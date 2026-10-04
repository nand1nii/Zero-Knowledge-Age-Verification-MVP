/**
 * issuer.ts — Mock credential issuer.
 *
 * Simulates a trusted authority (a DMV, a university, a bank doing KYC) that
 * has already checked someone's real ID out-of-band and now hands them a
 * *private* digital credential:
 *
 *   commitment = Poseidon(birthdateTimestamp, salt)
 *   signature  = EdDSA-Poseidon-Sign(issuerPrivateKey, commitment)   (BabyJubjub)
 *
 * The holder keeps credential.json to themselves. Later they can prove facts
 * about the birthdate (e.g. "≥ 18") to anyone, without ever showing it again.
 *
 * In production this happens ONCE, by a real authority, with a key kept in an
 * HSM. Here it's a local script with a key in a JSON file — demo only.
 *
 * CLI:
 *   npx ts-node scripts/issuer.ts --birthdate 2000-01-15 \
 *       [--out output/credential.json] [--issuer-key output/issuer_private_key.json]
 */
import { randomBytes } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { parseArgs } from "util";

// circomlibjs ships no TypeScript types; it's the JS twin of circomlib's
// circuits, guaranteeing our off-circuit hashes/signatures match in-circuit.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { buildEddsa, buildPoseidon } = require("circomlibjs");

export const PROJECT_ROOT = path.resolve(__dirname, "..");
export const DEFAULT_OUTPUT_DIR = path.join(PROJECT_ROOT, "output");

/** What the holder stores. All numbers are decimal strings (JSON has no bigint). */
export interface Credential {
  birthdateTimestamp: string;
  salt: string;
  signature: { R8x: string; R8y: string; S: string };
  issuerPubKey: { x: string; y: string };
}

/** The issuer's public key — safe to publish; verifiers use it as a trust anchor. */
export interface IssuerPublicKey {
  x: string;
  y: string;
}

/** The issuer's signing key. SECRET. Only the issuer ever sees this. */
export interface IssuerKeypair {
  privateKey: Buffer; // 32 random bytes
  publicKey: IssuerPublicKey;
}

/** Generate a fresh BabyJubjub EdDSA keypair to act as "the issuer". */
export async function generateIssuerKeypair(): Promise<IssuerKeypair> {
  const eddsa = await buildEddsa();
  const privateKey = randomBytes(32);
  return { privateKey, publicKey: derivePublicKey(eddsa, privateKey) };
}

function derivePublicKey(eddsa: any, privateKey: Buffer): IssuerPublicKey {
  // prv2pub returns a curve point in circomlibjs' internal field encoding;
  // F.toObject converts each coordinate to a plain bigint.
  const pub = eddsa.prv2pub(privateKey);
  return {
    x: eddsa.F.toObject(pub[0]).toString(),
    y: eddsa.F.toObject(pub[1]).toString(),
  };
}

/** Load the issuer key from disk, creating (and saving) a new one if absent. */
export async function loadOrCreateIssuerKeypair(keyPath: string): Promise<IssuerKeypair> {
  if (fs.existsSync(keyPath)) {
    const { privateKey } = JSON.parse(fs.readFileSync(keyPath, "utf8"));
    const eddsa = await buildEddsa();
    const priv = Buffer.from(privateKey, "hex");
    return { privateKey: priv, publicKey: derivePublicKey(eddsa, priv) };
  }
  const keypair = await generateIssuerKeypair();
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  // mode 0o600: a gesture toward "this is secret" — still just a demo file.
  fs.writeFileSync(
    keyPath,
    JSON.stringify({ privateKey: keypair.privateKey.toString("hex"), publicKey: keypair.publicKey }, null, 2),
    { mode: 0o600 },
  );
  return keypair;
}

/**
 * A random salt that is a valid field element.
 *
 * 31 random bytes = 248 bits, which is always below the BN254 scalar field
 * modulus (~2^253.6), so no modular reduction (and no bias) is needed. 248
 * bits is far beyond brute-force range, which is what keeps the commitment
 * (and the nullifier) from leaking the birthdate.
 */
export function randomSalt(): bigint {
  return BigInt("0x" + randomBytes(31).toString("hex"));
}

/**
 * Parse a birthdate given either as an ISO date ("2000-01-15", interpreted
 * as midnight UTC) or as unix seconds ("947894400").
 *
 * Timestamps must be ≥ 0 (born 1970-01-01 or later): the circuit range-checks
 * timestamps as unsigned 64-bit integers. A real system would use an epoch
 * offset to cover earlier birthdates; we keep it simple for the demo.
 */
export function parseBirthdate(input: string): bigint {
  let seconds: number;
  if (/^\d+$/.test(input)) {
    seconds = Number(input);
  } else {
    const ms = Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(input) ? `${input}T00:00:00Z` : input);
    if (Number.isNaN(ms)) throw new Error(`Unrecognized birthdate: "${input}" (use YYYY-MM-DD or unix seconds)`);
    seconds = Math.floor(ms / 1000);
  }
  if (seconds < 0) throw new Error("Birthdates before 1970-01-01 are not supported by this demo circuit.");
  return BigInt(seconds);
}

/**
 * Issue a credential: commit to the birthdate with a fresh salt, sign the
 * commitment, and return everything the holder needs to generate proofs later.
 */
export async function issueCredential(birthdateTimestamp: bigint, issuer: IssuerKeypair): Promise<Credential> {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();

  const salt = randomSalt();

  // Same hash the circuit computes in Step 1. Must match bit-for-bit, which
  // is why we use circomlibjs (the reference JS implementation of circomlib).
  const commitment = poseidon([birthdateTimestamp, salt]);

  // EdDSA over BabyJubjub with Poseidon as the hash — exactly what circomlib's
  // EdDSAPoseidonVerifier checks inside the circuit (Step 2).
  const signature = eddsa.signPoseidon(issuer.privateKey, commitment);

  return {
    birthdateTimestamp: birthdateTimestamp.toString(),
    salt: salt.toString(),
    signature: {
      R8x: eddsa.F.toObject(signature.R8[0]).toString(),
      R8y: eddsa.F.toObject(signature.R8[1]).toString(),
      S: signature.S.toString(),
    },
    issuerPubKey: issuer.publicKey,
  };
}

export function writeJson(filePath: string, data: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n");
}

// -----------------------------------------------------------------------------
// CLI
// -----------------------------------------------------------------------------
async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      birthdate: { type: "string" },
      out: { type: "string", default: path.join(DEFAULT_OUTPUT_DIR, "credential.json") },
      "issuer-key": { type: "string", default: path.join(DEFAULT_OUTPUT_DIR, "issuer_private_key.json") },
    },
  });
  if (!values.birthdate) {
    console.error("Usage: issuer.ts --birthdate YYYY-MM-DD [--out credential.json] [--issuer-key key.json]");
    process.exit(2);
  }

  const issuer = await loadOrCreateIssuerKeypair(values["issuer-key"]!);
  const credential = await issueCredential(parseBirthdate(values.birthdate), issuer);

  writeJson(values.out!, credential);
  // The public key is what a verifier pins as "an issuer I trust".
  const pubKeyPath = path.join(path.dirname(values["issuer-key"]!), "issuer_public_key.json");
  writeJson(pubKeyPath, issuer.publicKey);

  console.log(`Issuer: credential written to ${values.out} (PRIVATE — give only to the holder)`);
  console.log(`Issuer: public key written to ${pubKeyPath} (share with verifiers)`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
