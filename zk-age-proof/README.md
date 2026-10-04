# zk-age-proof

A command-line demo of zero-knowledge age verification.

> ⚠️ **This is an unaudited proof of concept for teaching.** Do not use it with real
> identity documents or in any production system without a full security review.
> See [Security caveats](#security-caveats) below.

- An **issuer** (think: DMV, university) signs a private credential that contains a
  birthdate.
- A **prover** (the credential holder) builds a zk-SNARK proof of the statement
  *"I hold an issuer-signed credential, and its birthdate makes me at least 18."*
- A **verifier** checks the proof. It learns **true/false and nothing else**: no
  birthdate, no name, and no identifier that could link this proof to the same
  person's proofs at other services.

Stack: **Circom 2** circuit · **Groth16** via **snarkjs** · **EdDSA-Poseidon** signatures
over **BabyJubjub** (circomlib) · **Node.js + TypeScript** · **Jest**.

---

## Architecture

```
 ┌──────────────┐  credential.json (PRIVATE)   ┌──────────────┐   proof.json + public.json   ┌──────────────┐
 │    Issuer    │ ───────────────────────────▶ │    Prover    │ ───────────────────────────▶ │   Verifier   │
 │ scripts/     │   birthdate, salt,           │ scripts/     │   no birthdate, no salt,     │ scripts/     │
 │  issuer.ts   │   EdDSA sig, issuer pubkey   │  prover.ts   │   no signature               │  verifier.ts │
 └──────────────┘                              └──────────────┘                              └──────────────┘
        │ issuer_public_key.json (public trust anchor)                                              ▲
        └───────────────────────────────────────────────────────────────────────────────────────────┘
                                 verification_key.json (public, from setup.sh) ───────────────────▶ │
```

| Role | Knows | Produces |
|---|---|---|
| Issuer | the real birthdate (it checked an ID out-of-band), its own signing key | `credential.json` = `{ birthdateTimestamp, salt, signature: {R8x, R8y, S}, issuerPubKey }` |
| Prover | `credential.json` | `proof.json`, `public.json` |
| Verifier | `proof.json`, `public.json`, `verification_key.json`, a list of trusted issuer public keys | PASS / FAIL |

### The circuit (`circuits/age_check.circom`)

| | Signals |
|---|---|
| **Private** | `birthdateTimestamp`, `salt`, `signatureR8x`, `signatureR8y`, `signatureS` |
| **Public** (in `public.json` order) | `currentTimestamp`, `minAgeSeconds`, `issuerPubKeyX`, `issuerPubKeyY`, `nullifier`, `contextHash` |

The constraints, in order. Each is a circomlib template, and none of the cryptography is
hand-written:

0. **Range checks** (`Num2Bits(64)`): the timestamps, the threshold and the computed age
   must all be 64-bit unsigned integers. Circom signals are field elements, so without
   this a birthdate "in the future" could wrap around and look enormous.
1. **Commitment**: `commitment = Poseidon(birthdateTimestamp, salt)`.
2. **Signature**: `EdDSAPoseidonVerifier` checks the issuer's signature over
   `commitment` against `(issuerPubKeyX, issuerPubKeyY)`. This ties the birthdate to the
   issuer. Changing the birthdate or the salt breaks it.
3. **Age**: `GreaterEqThan(64)` checks `currentTimestamp − birthdateTimestamp ≥ minAgeSeconds`,
   and its output is forced to be `1`.
4. **Nullifier**: `nullifier === Poseidon(salt, contextHash)`.
5. There is no output signal. If a proof exists, every constraint above was satisfied.

**Why an underage user can't produce a proof at all.** The constraints are checked
while the witness is computed. If the user is under 18, no assignment of the signals
satisfies step 3, so `snarkjs groth16 fullprove` throws before any proof exists. The
verifier never sees a "false" proof because one can't be built. Producing one would
require breaking the cryptography or knowing the trusted-setup secrets (see caveats).

### Nullifiers and contexts

The prover hashes a context string such as `"acme-app:2026-09-14"` to
`contextHash = SHA-256(context)[0..31 bytes]`. The circuit then forces
`nullifier = Poseidon(salt, contextHash)`.

- **Same credential, same context → same nullifier.** A service can store the nullifiers
  it has seen and reject a second use, for example one credential opening ten accounts.
  The demo shows this.
- **Same credential, different context → nullifiers that look unrelated.** Two services
  comparing their logs can't tell that the same person proved their age to both.
- The salt is secret, so a nullifier can't be traced back to a credential or a birthdate.

### What the verifier must check (beyond the proof)

A valid Groth16 proof means: *some* key signed *some* credential whose holder is at
least `minAgeSeconds` old at `currentTimestamp`, scoped to `contextHash`. The values in
that sentence are all public inputs, so the verifier has to check that they are the
values it wants. `verifyWithPolicy()` in `scripts/verifier.ts` does this:

| Check | Without it… |
|---|---|
| `issuerPubKey` is a trusted issuer | anyone could issue themselves a credential |
| `minAgeSeconds` ≥ the required threshold | a 14-year-old could prove "≥ 10" |
| `contextHash` = hash of *this* service's context | a proof made for another service could be replayed here |
| `currentTimestamp` is within ±`maxSkew` of now | old proofs could be replayed, or a fake date used |
| `nullifier` not seen before | one credential could be reused without limit |

---

## Project layout

```
zk-age-proof/
├── circuits/age_check.circom   # the ZK statement (heavily commented)
├── scripts/
│   ├── issuer.ts               # mock issuer: keypair, salt, commitment, signature
│   ├── prover.ts               # builds circuit input, runs groth16 fullprove
│   ├── verifier.ts             # groth16 verify + policy checks; prints PASS/FAIL
│   └── setup.sh                # compile circuit + DEV-ONLY trusted setup
├── test/age_check.test.ts      # Jest end-to-end tests against the real circuit
├── demo/run_demo.ts            # narrated issuer → prover → verifier flow
├── package.json
├── tsconfig.json
└── README.md
```

Generated, git-ignored directories:

- `build/` holds the r1cs, the wasm witness generator, the ptau, the zkey and
  `verification_key.json`.
- `output/` holds credentials, proofs and the issuer key. ⚠️ It contains private data.

---

## Running it

**Prerequisites:** Node.js ≥ 18.3 and npm. You don't need a native Circom install:
`setup.sh` uses `circom` if it's on your `PATH` and otherwise falls back to the
[`circom2`](https://www.npmjs.com/package/circom2) npm package, a WebAssembly build of
the same Circom 2.x compiler.

```bash
cd zk-age-proof
npm install
npm run setup     # compile circuit + dev trusted setup (~4-5 min the first time; ptau is cached)
npm run demo      # narrated flow: an adult succeeds, a minor fails at proof generation
npm test          # Jest suite (~40 s)
```

The circuit is about 9.4k constraints, so the 2^14 Powers of Tau is enough. Each proof
takes about 2 s.

Run the demo with your own birthdate. Dates are `YYYY-MM-DD`, read as midnight UTC:

```bash
npm run demo -- --birthdate 2010-05-05   # under 18: proof generation fails
```

### Using the three roles by hand

```bash
# 1. Issuer: creates output/issuer_private_key.json (secret) on first run,
#    plus output/issuer_public_key.json (public) and output/credential.json (private).
npm run issue -- --birthdate 2000-01-15

# 2. Prover: writes output/proof.json and output/public.json.
#    --current-timestamp defaults to now; --min-age-seconds defaults to 18 years.
npm run prove -- --context "acme-app:2026-09-14"

# 3. Verifier: reads only proof.json, public.json, verification_key.json and the trusted issuer key.
npm run verify -- --issuer-pubkey output/issuer_public_key.json \
                  --context "acme-app:2026-09-14" \
                  --nullifier-db output/seen_nullifiers.json
# Run the verify command a second time: the nullifier was recorded, so it now FAILs as reuse.
```

The verifier exits with `0` on PASS and `1` on FAIL. The underage case looks like this:

```bash
npm run issue -- --birthdate 2012-03-10 --out output/minor.json
npm run prove -- --credential output/minor.json --context "acme-app:2026-09-14" --out-dir output/minor
# → "Proof generation FAILED ... No proof exists for a false statement." (exit 1, no proof.json written)
```

### What the tests cover

`test/age_check.test.ts` runs against the real compiled circuit and keys:

- Valid credential with age ≥ 18 → the proof generates and verifies. This also covers
  the exact 18th birthday and the full policy checks.
- Valid credential with age < 18 → witness/proof generation fails. This also covers one
  second before the 18th birthday and a birthdate in the future.
- Tampered credentials:
  - A wrong salt fails in `EdDSAPoseidonVerifier`.
  - A minor who edits their birthdate fails the signature check.
  - A swapped issuer key fails the signature check.
  - A self-issued credential proves fine but is rejected as an untrusted issuer.
  - Editing any public input after proving makes verification fail.
- Nullifiers:
  - The same `(salt, contextHash)` always gives the same nullifier.
  - Different contexts give different nullifiers.
  - Different credentials give different nullifiers.
  - The circuit enforces the nullifier.
  - Reuse is detected.
- Neither `proof.json` nor `public.json` contains the birthdate, the salt or the
  signature.

---

## Security caveats

This repository is a **proof of concept**. It is **unaudited** and **not suitable for
real identity documents** without further security review. Its known limitations:

- **The trusted setup is dev-only.** `setup.sh` runs a single-party Powers of Tau and
  phase-2 ceremony on one machine. Whoever ran it could, in principle, have kept the
  "toxic waste" and could forge proofs of false statements that still verify. A real
  deployment needs one of:
  - a multi-party ceremony, which is secure if at least one participant is honest;
  - a universal-setup system such as PLONK;
  - a transparent system with no trusted setup, such as Halo2 or STARKs.
- **No Sybil resistance.** Nullifiers only stop reuse *within one context*. Nothing
  here stops one person from obtaining several credentials, or stops several people
  from sharing one.
- **No biometric or device binding.** Whoever holds `credential.json` can generate
  proofs. An adult can hand their credential to a minor, and the system can't tell.
  Real systems bind credentials to a device secure element or to the holder's key, or
  add liveness checks.
- **No revocation.** A credential can't be revoked once issued, and it never expires.
- **Issuer trust is out of scope.** The verifier pins issuer public keys by hand. There
  is no PKI, no key rotation and no HSM, and the issuer's private key sits in a
  plaintext JSON file.
- **The prover chooses `currentTimestamp`.** The verifier has to enforce freshness
  (`--max-skew`). Otherwise a minor could claim it is some date years in the future.
- **The age math is simplified.** "18 years" means 18 × 365.25 days in seconds, and
  birthdates are midnight UTC, so results near a birthday may be off by about a day.
  Birthdates before 1970-01-01 aren't supported because timestamps are unsigned in the
  circuit.
- **Nothing beyond the statement is hidden.** The public inputs include the issuer key
  and the exact `currentTimestamp`, so the verifier learns which issuer you use and
  when you proved.
- **The context hash is a plain SHA-256.** It's truncated to 248 bits to fit the field.
  That's fine for a demo. A real scheme should specify domain separation.
- **The code is not audited.** It relies on circomlib and snarkjs, which are widely used.
  The circuit, the glue code and the threat model have not been reviewed.

## Dependency licensing note

`circomlib` is licensed under GPL-3.0, and the circuit includes its templates. Review
the license implications before reusing this code in another project.
