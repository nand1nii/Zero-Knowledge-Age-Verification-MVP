/**
 * run_demo.ts — Narrated end-to-end flow: issuer → prover → verifier.
 *
 * Runs two scenarios:
 *   1. An adult (born 2000-01-15): proof generation and verification succeed.
 *   2. A minor  (born 2012-03-10): proof generation FAILS outright — there is
 *      no proof for the verifier to reject, because none can be constructed.
 *
 * Optionally pass `--birthdate YYYY-MM-DD` to run a single custom scenario.
 *
 * The three roles exchange data only through files, as they would across a
 * network, so it's easy to see what crosses each trust boundary:
 *   issuer   → holder:   credential.json          (PRIVATE)
 *   holder   → verifier: proof.json, public.json  (no personal data)
 */
import * as fs from "fs";
import * as path from "path";
import { parseArgs } from "util";
import { DEFAULT_OUTPUT_DIR, generateIssuerKeypair, issueCredential, parseBirthdate, writeJson } from "../scripts/issuer";
import { generateProof, MIN_AGE_18_SECONDS, ProofGenerationError, SECONDS_PER_YEAR } from "../scripts/prover";
import { formatPublicInputs, VKEY_PATH, verifyWithPolicy } from "../scripts/verifier";

const CONTEXT = "acme-app:2026-09-14";

const banner = (s: string) => console.log(`\n${"=".repeat(78)}\n${s}\n${"=".repeat(78)}`);
const step = (n: number, s: string) => console.log(`\n[${n}] ${s}`);
const readJson = (p: string) => JSON.parse(fs.readFileSync(p, "utf8"));

/** Returns true if the scenario behaved as expected for its true age. */
async function runScenario(label: string, birthdateIso: string, issuerKeypair: Awaited<ReturnType<typeof generateIssuerKeypair>>): Promise<boolean> {
  const dir = path.join(DEFAULT_OUTPUT_DIR, "demo", label);
  const now = BigInt(Math.floor(Date.now() / 1000));
  const birthdate = parseBirthdate(birthdateIso);
  // Ground truth, computed here ONLY to label the demo's expected outcome.
  // The prover does not use it — the circuit decides.
  const actuallyAdult = now - birthdate >= MIN_AGE_18_SECONDS;
  const approxAge = (Number(now - birthdate) / SECONDS_PER_YEAR).toFixed(1);

  banner(`SCENARIO: ${label} (born ${birthdateIso}, ~${approxAge} years old)`);

  // --- 1. Issuer -----------------------------------------------------------
  step(1, `Issuer signs a credential for a user born on ${birthdateIso}.`);
  const credential = await issueCredential(birthdate, issuerKeypair);
  writeJson(path.join(dir, "credential.json"), credential);
  console.log("    The issuer commits to the birthdate with a random salt, signs the");
  console.log("    commitment with EdDSA-Poseidon, and hands credential.json to the user.");
  console.log(`    -> ${path.relative(process.cwd(), path.join(dir, "credential.json"))} (PRIVATE: stays on the user's device)`);

  // --- 2. Prover -----------------------------------------------------------
  step(2, "User generates a ZK proof that they are over 18 — without revealing their birthdate.");
  console.log(`    Public parameters: minAge = 18 years (${MIN_AGE_18_SECONDS}s), context = "${CONTEXT}"`);
  let proofResult;
  try {
    const t0 = Date.now();
    proofResult = await generateProof(credential, {
      currentTimestamp: now,
      minAgeSeconds: MIN_AGE_18_SECONDS,
      contextString: CONTEXT,
    });
    console.log(`    Proof generated in ${((Date.now() - t0) / 1000).toFixed(1)}s.`);
  } catch (err) {
    if (!(err instanceof ProofGenerationError)) throw err;
    console.log("    (The \"ERROR ... line: N\" above, if shown, is snarkjs's witness calculator");
    console.log("     reporting which circuit constraint could not be satisfied.)");
    console.log(`    ✗ ${err.message}`);
    console.log("    The user is under 18, so the circuit's `age >= minAge` constraint can't be");
    console.log("    satisfied. Nothing is sent to the verifier — there is nothing to send.");
    return !actuallyAdult;
  }
  writeJson(path.join(dir, "proof.json"), proofResult.proof);
  writeJson(path.join(dir, "public.json"), proofResult.publicSignals);
  console.log(`    -> proof.json + public.json sent to the verifier.`);

  // --- 3. Verifier ---------------------------------------------------------
  // The verifier reads ONLY proof.json, public.json, the verification key and
  // the issuer's published public key — never credential.json.
  step(3, "Verifier checks the proof.");
  const proof = readJson(path.join(dir, "proof.json"));
  const publicSignals = readJson(path.join(dir, "public.json"));
  const vkey = readJson(VKEY_PATH);
  const seenNullifiers = new Set<string>();
  const policy = {
    trustedIssuers: [issuerKeypair.publicKey],
    requiredMinAgeSeconds: MIN_AGE_18_SECONDS,
    expectedContext: CONTEXT,
    now: BigInt(Math.floor(Date.now() / 1000)),
    maxClockSkewSeconds: 300n,
    seenNullifiers,
  };
  const result = await verifyWithPolicy(proof, publicSignals, vkey, policy);
  console.log(`    Result: ${result.ok ? "PASS ✓ — user is over 18" : "FAIL ✗"}`);
  for (const f of result.failures) console.log(`      - ${f}`);

  // --- 4. Show what the verifier actually saw ------------------------------
  step(4, "Everything the verifier received — public.json — contains no personal data:");
  console.log(JSON.stringify(publicSignals, null, 2).replace(/^/gm, "    "));
  console.log("    Decoded:");
  console.log(formatPublicInputs(result.publicInputs).replace(/^/gm, "  "));
  const leaked = [credential.birthdateTimestamp, credential.salt, credential.signature.S].some((secret) =>
    publicSignals.includes(secret),
  );
  console.log(`    Birthdate, salt or signature present in public.json? ${leaked ? "YES (BUG!)" : "No."}`);

  // --- Bonus: nullifier reuse detection ------------------------------------
  if (result.ok) {
    seenNullifiers.add(result.publicInputs.nullifier);
    const replay = await verifyWithPolicy(proof, publicSignals, vkey, policy);
    console.log("\n    Bonus: the same proof submitted again to the same service:");
    console.log(`    Result: ${replay.ok ? "PASS" : "FAIL ✗"} — ${replay.failures.join("; ")}`);
  }

  return result.ok === actuallyAdult && !leaked;
}

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { birthdate: { type: "string" } } });

  if (!fs.existsSync(VKEY_PATH)) {
    console.error("Missing build artifacts. Run `npm run setup` first.");
    process.exit(1);
  }

  // One issuer for the whole demo, like one DMV issuing to many people.
  const issuer = await generateIssuerKeypair();
  writeJson(path.join(DEFAULT_OUTPUT_DIR, "demo", "issuer_public_key.json"), issuer.publicKey);

  const scenarios: Array<[string, string]> = values.birthdate
    ? [["custom", values.birthdate]]
    : [
        ["adult", "2000-01-15"],
        ["minor", "2012-03-10"],
      ];

  let allAsExpected = true;
  for (const [label, birthdate] of scenarios) {
    allAsExpected = (await runScenario(label, birthdate, issuer)) && allAsExpected;
  }

  banner(allAsExpected ? "Demo finished: every scenario behaved as expected." : "Demo finished: UNEXPECTED RESULT (see above).");
  process.exit(allAsExpected ? 0 : 1); // snarkjs keeps worker threads alive; exit explicitly
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
