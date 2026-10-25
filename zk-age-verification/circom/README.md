# circom/ — Module 3: the ZK circuit (owner C)

The "math rulebook". `circuits/age_check.circom` only produces a valid proof if:

1. a trusted issuer signed `Poseidon([ID_Number, dob])` (EdDSA on BabyJubJub), and
2. `dob <= currentDate` and `currentDate - dob >= ageThreshold`.

The proof reveals nothing unique to the user: the circuit has **no public outputs**.

| | Signals |
|---|---|
| Private inputs | `dob`, `ID_Number`, `signatureR8x`, `signatureR8y`, `signatureS` |
| Public inputs (this order) | `challenge`, `currentDate`, `issuerPubKeyX`, `issuerPubKeyY`, `ageThreshold`, `verifierId` |
| Public outputs | none |

The public order is fixed by `PUBLIC_SIGNALS` in [`../shared/constants.js`](../shared/constants.js).
`test/signal-order.test.js` checks the source, the compiled `.sym` file and the
verification key all agree with it.

Size: about 4,600 constraints (EdDSA is most of it), so a `2^14` Powers of Tau is enough.

## Files

```
circuits/age_check.circom   the circuit (commented line by line)
scripts/build.sh            compile -> Powers of Tau -> Groth16 setup -> export vkey
test/helpers.js             test-only signing helper (own copy, not the issuer's code)
test/age_check.test.js      positive + negative circuit tests
test/signal-order.test.js   public-signal order vs shared/constants.js
Dockerfile                  one-shot builder image (not a server)
```

## Run it alone

Needs Node 20+ and Circom 2.1.x on your `PATH` (or use Docker, below).

```bash
cd circom
npm install
npm run build   # ~5 min the first time (Powers of Tau), ~30 s after; skipped if nothing changed
npm test        # runs build first (a no-op if up to date), then the tests (~10 s)
```

With Docker only (no local Circom):

```bash
# from the repo root (zk-age-verification/)
docker compose run --rm circom-builder              # build into the artifacts volume
docker compose run --rm circom-builder npm test     # run the circuit tests in the container
```

## Outputs (the module's interface)

`build.sh` writes **only** to `$ARTIFACTS_DIR` (default `../artifacts`, in Docker the
`artifacts` volume). It never copies files into other modules.

| File | Used by |
|---|---|
| `age_check.wasm` | wallet (witness generation in the browser) |
| `age_check_final.zkey` | wallet (proving key) |
| `verification_key.json` | verifier |
| `build/age_check.r1cs`, `build/age_check.sym`, `build/pot14_final.ptau` | this module only (tests, cache) |
| `build-info.json` | fingerprint used to skip unchanged rebuilds |

`FORCE_REBUILD=1 npm run build` forces a fresh setup. Every rebuild creates **new keys**,
so the wallet and verifier must use the same build (they share one volume, so they do).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `ARTIFACTS_DIR` | `../artifacts` | where outputs are written / read by tests |
| `FORCE_REBUILD` | `0` | `1` rebuilds even if the circuit is unchanged |

## What the tests check

- A valid adult proves and verifies; public signals come out in constants order.
- The proof and public signals contain no `dob`, `ID_Number`, signature or message hash.
- Exactly 18 today passes (`20261025 - 20081025 = 180000`); 18 tomorrow fails (`179999`).
- Rejected (no proof can be built): underage, future DOB, tampered `S` or `R8`, edited
  `dob`, edited `ID_Number`, a completely forged signature (`enabled` sanity), a
  credential from another issuer checked against the trusted key.
- Range checks: `dob = p - 1`, `dob = p - 180000` (which would wrap to a passing
  difference), a negative `ageThreshold` and an oversized `currentDate` are all rejected.
- Proofs that are mathematically valid but have the wrong public values (self-made
  issuer, `ageThreshold = 0`, wrong `challenge`, wrong `verifierId`) are caught by the
  server-side compare. Editing any public signal after proving breaks verification.

We also checked the tests are meaningful by compiling two broken copies of the circuit:
without the `dob` range check, the `p - 180000` attack produces a witness; with
`enabled <== 0`, the forged signature produces a witness. The real circuit rejects both.

## Security notes

- **The trusted setup is generated locally and is NOT a secure ceremony.** Whoever ran
  `build.sh` could keep the randomness and forge proofs. Fine for a demo only.
- The keep-alive lines (`challenge * challenge`, `verifierId * verifierId`) do **not**
  provide replay protection. Groth16 binds every public input anyway; replay protection
  comes from the verifier server checking the challenge.
- Versions are pinned: Circom 2.1.9, circomlib 2.0.5, snarkjs 0.7.6, circomlibjs 0.1.7.
- `circomlib` is GPL-3.0; the circuit includes its templates.

## What this module expects from others

Nothing at build time. At test time it imports only `../shared/constants.js`.
