/**
 * End-to-end tests against the real compiled circuit and keys.
 * Requires `npm run setup` to have been run first (build/ must exist).
 */
import * as fs from "fs";
import { Credential, generateIssuerKeypair, issueCredential, IssuerKeypair, parseBirthdate } from "../scripts/issuer";
import {
  computeContextHash,
  computeNullifier,
  generateProof,
  Groth16Proof,
  MIN_AGE_18_SECONDS,
  ProofGenerationError,
  PublicSignals,
  ProofRequest,
} from "../scripts/prover";
import { decodePublicSignals, verifyProof, verifyWithPolicy, VKEY_PATH } from "../scripts/verifier";

// A fixed "now" keeps the tests deterministic: 2026-09-14T00:00:00Z.
const NOW = parseBirthdate("2026-09-14");
const CONTEXT = "acme-app:2026-09-14";
const request = (overrides: Partial<ProofRequest> = {}): ProofRequest => ({
  currentTimestamp: NOW,
  minAgeSeconds: MIN_AGE_18_SECONDS,
  contextString: CONTEXT,
  ...overrides,
});

let vkey: object;
let issuer: IssuerKeypair;
let adultCredential: Credential;
let adultProof: { proof: Groth16Proof; publicSignals: PublicSignals };

beforeAll(async () => {
  // Several tests deliberately feed the circuit invalid witnesses. The circom
  // witness calculator logs each failing constraint ("ERROR: 4 Error in
  // template ...") via console.error; silence just those expected lines.
  const originalError = console.error;
  jest.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    if (typeof args[0] === "string" && args[0].startsWith("ERROR:")) return;
    originalError(...args);
  });

  if (!fs.existsSync(VKEY_PATH)) throw new Error("Build artifacts missing — run `npm run setup` before `npm test`.");
  vkey = JSON.parse(fs.readFileSync(VKEY_PATH, "utf8"));
  issuer = await generateIssuerKeypair();
  adultCredential = await issueCredential(parseBirthdate("2000-01-15"), issuer);
  adultProof = await generateProof(adultCredential, request());
});

afterAll(async () => {
  // snarkjs caches a multi-threaded BN254 curve on globalThis; shut its
  // worker threads down so Jest can exit cleanly.
  await (globalThis as any).curve_bn128?.terminate();
});

describe("valid credential, age >= 18", () => {
  it("generates a proof that verifies", async () => {
    expect(await verifyProof(adultProof.proof, adultProof.publicSignals, vkey)).toBe(true);
  });

  it("passes the verifier's policy checks (trusted issuer, threshold, context, freshness)", async () => {
    const result = await verifyWithPolicy(adultProof.proof, adultProof.publicSignals, vkey, {
      trustedIssuers: [issuer.publicKey],
      requiredMinAgeSeconds: MIN_AGE_18_SECONDS,
      expectedContext: CONTEXT,
      now: NOW,
      maxClockSkewSeconds: 300n,
    });
    expect(result.failures).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("succeeds for someone who turned 18 exactly at the threshold", async () => {
    const credential = await issueCredential(NOW - MIN_AGE_18_SECONDS, issuer);
    const { proof, publicSignals } = await generateProof(credential, request());
    expect(await verifyProof(proof, publicSignals, vkey)).toBe(true);
  });

  it("exposes only public inputs — no birthdate, salt or signature in public.json", () => {
    const publicInputs = decodePublicSignals(adultProof.publicSignals);
    expect(publicInputs).toEqual({
      currentTimestamp: NOW.toString(),
      minAgeSeconds: MIN_AGE_18_SECONDS.toString(),
      issuerPubKeyX: issuer.publicKey.x,
      issuerPubKeyY: issuer.publicKey.y,
      nullifier: expect.any(String),
      contextHash: computeContextHash(CONTEXT).toString(),
    });
    const secrets = [
      adultCredential.birthdateTimestamp,
      adultCredential.salt,
      adultCredential.signature.R8x,
      adultCredential.signature.R8y,
      adultCredential.signature.S,
    ];
    const verifierVisible = JSON.stringify([adultProof.proof, adultProof.publicSignals]);
    for (const secret of secrets) expect(verifierVisible).not.toContain(secret);
  });
});

describe("valid credential, age < 18", () => {
  it("fails at witness/proof generation", async () => {
    const minor = await issueCredential(parseBirthdate("2012-03-10"), issuer);
    await expect(generateProof(minor, request())).rejects.toBeInstanceOf(ProofGenerationError);
  });

  it("fails one second before the 18th birthday", async () => {
    const almost = await issueCredential(NOW - MIN_AGE_18_SECONDS + 1n, issuer);
    await expect(generateProof(almost, request())).rejects.toBeInstanceOf(ProofGenerationError);
  });

  it("cannot be bypassed by asking for a lower threshold the verifier then rejects", async () => {
    // A 14-year-old CAN prove "age >= 10"... but that proof says minAgeSeconds = 10y,
    // and a verifier requiring 18 rejects it.
    const minor = await issueCredential(parseBirthdate("2012-03-10"), issuer);
    const tenYears = MIN_AGE_18_SECONDS / 18n * 10n;
    const { proof, publicSignals } = await generateProof(minor, request({ minAgeSeconds: tenYears }));
    const result = await verifyWithPolicy(proof, publicSignals, vkey, { requiredMinAgeSeconds: MIN_AGE_18_SECONDS });
    expect(result.cryptoValid).toBe(true);
    expect(result.ok).toBe(false);
  });

  it("cannot be bypassed with a birthdate in the future (field wrap-around)", async () => {
    const unborn = await issueCredential(NOW + 1000n, issuer);
    await expect(generateProof(unborn, request())).rejects.toBeInstanceOf(ProofGenerationError);
  });
});

describe("tampered credential", () => {
  it("wrong salt: commitment no longer matches the signature, so the signature check fails", async () => {
    const tampered: Credential = { ...adultCredential, salt: (BigInt(adultCredential.salt) + 1n).toString() };
    const err = await generateProof(tampered, request()).catch((e) => e);
    expect(err).toBeInstanceOf(ProofGenerationError);
    // The witness calculator reports the failing template: the EdDSA verifier's
    // final equality check, not the age comparison.
    expect(String(err.cause)).toMatch(/EdDSAPoseidonVerifier|ForceEqualIfEnabled/);
  });

  it("a minor editing their birthdate to look older fails the signature check", async () => {
    const minor = await issueCredential(parseBirthdate("2012-03-10"), issuer);
    const forged: Credential = { ...minor, birthdateTimestamp: parseBirthdate("1990-01-01").toString() };
    const err = await generateProof(forged, request()).catch((e) => e);
    expect(err).toBeInstanceOf(ProofGenerationError);
    expect(String(err.cause)).toMatch(/EdDSAPoseidonVerifier|ForceEqualIfEnabled/);
  });

  it("a credential presented with a different issuer's public key fails the signature check", async () => {
    const other = await generateIssuerKeypair();
    const swapped: Credential = { ...adultCredential, issuerPubKey: other.publicKey };
    await expect(generateProof(swapped, request())).rejects.toBeInstanceOf(ProofGenerationError);
  });

  it("a self-issued credential yields a valid proof, but the verifier rejects the untrusted issuer", async () => {
    const rogue = await generateIssuerKeypair();
    const selfIssued = await issueCredential(parseBirthdate("2000-01-15"), rogue);
    const { proof, publicSignals } = await generateProof(selfIssued, request());
    const result = await verifyWithPolicy(proof, publicSignals, vkey, { trustedIssuers: [issuer.publicKey] });
    expect(result.cryptoValid).toBe(true);
    expect(result.ok).toBe(false);
    expect(result.failures.join()).toMatch(/issuer/);
  });

  it("editing any public input after proving makes verification fail", async () => {
    const { proof, publicSignals } = adultProof;
    for (let i = 0; i < publicSignals.length; i++) {
      const edited = [...publicSignals];
      edited[i] = (BigInt(edited[i]) + 1n).toString();
      expect(await verifyProof(proof, edited, vkey)).toBe(false);
    }
  });
});

describe("nullifier", () => {
  it("is deterministic for the same (salt, contextHash) pair", async () => {
    const salt = BigInt(adultCredential.salt);
    const ctx = computeContextHash(CONTEXT);
    expect(await computeNullifier(salt, ctx)).toEqual(await computeNullifier(salt, ctx));
  });

  it("is different across different contexts (proofs are unlinkable across services)", async () => {
    const salt = BigInt(adultCredential.salt);
    const a = await computeNullifier(salt, computeContextHash("acme-app:2026-09-14"));
    const b = await computeNullifier(salt, computeContextHash("other-site:2026-09-14"));
    expect(a).not.toEqual(b);
  });

  it("is different for different credentials in the same context", async () => {
    const other = await issueCredential(parseBirthdate("2000-01-15"), issuer);
    const ctx = computeContextHash(CONTEXT);
    expect(await computeNullifier(BigInt(other.salt), ctx)).not.toEqual(
      await computeNullifier(BigInt(adultCredential.salt), ctx),
    );
  });

  it("is enforced by the circuit: same credential + context gives the same public nullifier; new context gives a new one", async () => {
    const again = await generateProof(adultCredential, request({ currentTimestamp: NOW + 60n }));
    const elsewhere = await generateProof(adultCredential, request({ contextString: "other-site:2026-09-14" }));
    const nullifierOf = (ps: PublicSignals) => decodePublicSignals(ps).nullifier;

    expect(nullifierOf(again.publicSignals)).toEqual(nullifierOf(adultProof.publicSignals));
    expect(nullifierOf(elsewhere.publicSignals)).not.toEqual(nullifierOf(adultProof.publicSignals));
  });

  it("lets a verifier detect reuse of the same credential in the same context", async () => {
    const seen = new Set([decodePublicSignals(adultProof.publicSignals).nullifier]);
    const result = await verifyWithPolicy(adultProof.proof, adultProof.publicSignals, vkey, { seenNullifiers: seen });
    expect(result.ok).toBe(false);
    expect(result.failures.join()).toMatch(/Nullifier already used/);
  });
});
