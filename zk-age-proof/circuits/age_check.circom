pragma circom 2.1.6;

// =============================================================================
//  age_check.circom — "I hold an issuer-signed credential whose birthdate makes
//  me at least `minAgeSeconds` old at `currentTimestamp`" — proven without
//  revealing the birthdate, the salt, or the signature.
//
//  Everything below is built from circomlib's audited templates. We do NOT
//  implement any cryptographic primitive by hand.
//
//  Reminder on how a circuit "asserts" things: there is no if/else or return
//  value. Every `===` / `<==` is a polynomial constraint. A Groth16 proof can
//  only be produced for a witness (an assignment of all signals) that satisfies
//  EVERY constraint. So "the proof exists" == "every check below passed".
// =============================================================================

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

template AgeCheck() {
    // -------------------------------------------------------------------------
    // Private inputs — known only to the prover (the credential holder).
    // These never leave the prover's machine; the proof reveals nothing about
    // them beyond the truth of the statement.
    // -------------------------------------------------------------------------
    signal input birthdateTimestamp; // unix seconds (must be >= 0, i.e. 1970+)
    signal input salt;               // random field element chosen by the issuer
    signal input signatureR8x;       // EdDSA signature (R8 point, x coordinate)
    signal input signatureR8y;       // EdDSA signature (R8 point, y coordinate)
    signal input signatureS;         // EdDSA signature scalar

    // -------------------------------------------------------------------------
    // Public inputs — visible to the verifier, part of public.json.
    // -------------------------------------------------------------------------
    signal input currentTimestamp;   // "now", as claimed by the prover; the verifier must check it is fresh
    signal input minAgeSeconds;      // the age threshold the verifier asked for (e.g. 18 years)
    signal input issuerPubKeyX;      // issuer's BabyJubjub public key; the verifier must check it is a trusted issuer
    signal input issuerPubKeyY;
    signal input nullifier;          // Poseidon(salt, contextHash): stable per (credential, context)
    signal input contextHash;        // which app / service / session this proof is scoped to

    // -------------------------------------------------------------------------
    // Step 0: range checks.
    //
    // WHY: circom signals are elements of a ~254-bit prime field, not integers.
    // Subtraction "wraps around" modulo p, and circomlib's comparators
    // (LessThan / GreaterEqThan) are only sound when their inputs are known to
    // fit in `n` bits. Without these checks a malicious prover could pick a
    // birthdate in the "future" so that `currentTimestamp - birthdateTimestamp`
    // wraps to an enormous field element and confuses the comparison.
    //
    // Num2Bits(64) constrains its input to be representable in 64 bits, i.e.
    // to be an integer in [0, 2^64). That's plenty for unix-second timestamps.
    // -------------------------------------------------------------------------
    component birthdateBits = Num2Bits(64);
    birthdateBits.in <== birthdateTimestamp;

    component currentBits = Num2Bits(64);
    currentBits.in <== currentTimestamp;

    component minAgeBits = Num2Bits(64);
    minAgeBits.in <== minAgeSeconds;

    // -------------------------------------------------------------------------
    // Step 1: commitment = Poseidon(birthdateTimestamp, salt)
    //
    // WHY: the issuer doesn't sign the raw birthdate; it signs a *hiding
    // commitment* to it. Poseidon is a SNARK-friendly hash (cheap in
    // constraints, unlike SHA-256). The random salt prevents brute-forcing the
    // commitment: there are only ~36,500 plausible birthdates, so an unsalted
    // hash of a birthdate would effectively be public.
    // -------------------------------------------------------------------------
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== birthdateTimestamp;
    commitmentHasher.inputs[1] <== salt;
    signal commitment <== commitmentHasher.out;

    // -------------------------------------------------------------------------
    // Step 2: verify the issuer's EdDSA signature over the commitment.
    //
    // WHY: this binds the birthdate to a trusted authority. Without it, the
    // prover could simply invent any birthdate they like. Because the
    // commitment is recomputed *inside* the circuit from the private
    // birthdate/salt, the birthdate used in Step 3 is exactly the one the
    // issuer signed — changing it (or the salt) changes the commitment and
    // the signature check fails.
    //
    // EdDSAPoseidonVerifier is circomlib's verifier for EdDSA over the
    // BabyJubjub curve with Poseidon as the challenge hash. `enabled = 1`
    // means "always enforce" (the template supports conditional verification,
    // which we don't need).
    //
    // NOTE: this only proves *some* key signed the commitment. It is the
    // verifier's job to check that (issuerPubKeyX, issuerPubKeyY) — a public
    // input — belongs to an issuer it trusts. See scripts/verifier.ts.
    // -------------------------------------------------------------------------
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== issuerPubKeyX;
    sigVerifier.Ay <== issuerPubKeyY;
    sigVerifier.R8x <== signatureR8x;
    sigVerifier.R8y <== signatureR8y;
    sigVerifier.S <== signatureS;
    sigVerifier.M <== commitment;

    // -------------------------------------------------------------------------
    // Step 3: assert (currentTimestamp - birthdateTimestamp) >= minAgeSeconds
    //
    // WHY: this is the actual statement being proven. We first range-check the
    // difference itself to 64 bits: if birthdate > currentTimestamp the field
    // subtraction would wrap to a ~254-bit number and this Num2Bits fails —
    // so "born in the future" can't masquerade as "very old".
    //
    // GreaterEqThan(64) outputs 1 iff in[0] >= in[1] (both 64-bit). We then
    // force that output to be 1. If the user is underage, no valid witness
    // exists, so witness generation fails and NO proof can be produced at all
    // — the verifier never even sees a "false" proof.
    // -------------------------------------------------------------------------
    signal ageSeconds <== currentTimestamp - birthdateTimestamp;

    component ageBits = Num2Bits(64);
    ageBits.in <== ageSeconds;

    component isOldEnough = GreaterEqThan(64);
    isOldEnough.in[0] <== ageSeconds;
    isOldEnough.in[1] <== minAgeSeconds;
    isOldEnough.out === 1;

    // -------------------------------------------------------------------------
    // Step 4: nullifier === Poseidon(salt, contextHash)
    //
    // WHY: the salt is secret and unique per credential, so this value is:
    //   * deterministic — the same credential used in the same context always
    //     yields the same nullifier, letting a verifier detect reuse (e.g. one
    //     credential creating many accounts on the same service);
    //   * unlinkable across contexts — a different contextHash gives an
    //     unrelated-looking nullifier, so two services comparing notes can't
    //     tell that the same person proved their age to both;
    //   * non-identifying — without the salt, it can't be traced back to the
    //     credential or the birthdate.
    // Constraining it here prevents the prover from submitting a random
    // nullifier to evade reuse detection.
    // -------------------------------------------------------------------------
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== salt;
    nullifierHasher.inputs[1] <== contextHash;
    nullifier === nullifierHasher.out;

    // Step 5: no output signal. A proof that satisfies all the constraints
    // above *is* the assertion "the statement is true".
}

// Declare which inputs are public. Everything not listed here is private.
// The order here is the order the values appear in public.json.
component main {public [
    currentTimestamp,
    minAgeSeconds,
    issuerPubKeyX,
    issuerPubKeyY,
    nullifier,
    contextHash
]} = AgeCheck();
