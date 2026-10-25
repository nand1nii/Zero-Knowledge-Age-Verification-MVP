// circom/circuits/age_check.circom
// Proves "a trusted issuer signed my (ID_Number, dob), and dob makes me at least
// ageThreshold old on currentDate" without revealing dob, ID_Number or the signature.
pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// Reminder: a circuit has no if/else or return. Every `===` / `<==` is a constraint,
// and a proof can only be made from inputs that satisfy ALL of them.
// So "a valid proof exists" means "every check below passed".
template AgeCheck() {
    // ---- Private inputs (never revealed) ------------------------------------
    signal input dob;           // date of birth as YYYYMMDD, e.g. 20080315
    signal input ID_Number;     // 128-bit random number chosen by the issuer
    signal input signatureR8x;  // EdDSA signature: point R8 (x)
    signal input signatureR8y;  // EdDSA signature: point R8 (y)
    signal input signatureS;    // EdDSA signature: scalar S

    // ---- Public inputs ------------------------------------------------------
    // Declared in EXACTLY the order of PUBLIC_SIGNALS in shared/constants.js.
    // The verifier server must check every one of them against its own value.
    signal input challenge;     // random nonce from the verifier
    signal input currentDate;   // today as YYYYMMDD (verifier's clock)
    signal input issuerPubKeyX; // trusted issuer public key
    signal input issuerPubKeyY;
    signal input ageThreshold;  // 180000 = "18 years, 0 months, 0 days"
    signal input verifierId;    // identifies the website the proof is for

    // There are deliberately NO output signals. Anything unique to the user in the
    // proof (dob, ID_Number, signature, or a hash of them) would let the issuer and
    // the verifier compare notes and recognise the user (unlinkability).

    // ---- 1. Hash the signed message -----------------------------------------
    // Same input order as the issuer's JS: Poseidon([ID_Number, dob]).
    component hasher = Poseidon(2);
    hasher.inputs[0] <== ID_Number;
    hasher.inputs[1] <== dob;

    // ---- 2. Check the issuer's signature on that hash -----------------------
    // enabled = 1 is essential: with enabled = 0 circomlib skips every check and
    // anyone could prove anything. circom/test checks a forged signature fails.
    component sigCheck = EdDSAPoseidonVerifier();
    sigCheck.enabled <== 1;
    sigCheck.Ax <== issuerPubKeyX;
    sigCheck.Ay <== issuerPubKeyY;
    sigCheck.R8x <== signatureR8x;
    sigCheck.R8y <== signatureR8y;
    sigCheck.S <== signatureS;
    sigCheck.M <== hasher.out;

    // ---- 3. Range checks, then the age comparison ---------------------------
    // Circuit arithmetic is modulo a huge prime p. A "negative" number such as
    // (currentDate - dob) with dob > currentDate wraps around to a gigantic positive
    // number and could wrongly pass ">=". circomlib's comparators are also only
    // correct when their inputs fit in n bits. So first force all three dates /
    // thresholds to be small (< 2^32; YYYYMMDD values are about 2 * 10^7).
    component dobBits = Num2Bits(32);
    dobBits.in <== dob;
    component currentDateBits = Num2Bits(32);
    currentDateBits.in <== currentDate;
    component thresholdBits = Num2Bits(32);
    thresholdBits.in <== ageThreshold;

    // dob <= currentDate (no birthdays in the future). This also guarantees that
    // currentDate - dob below is between 0 and 2^32, so it cannot wrap around.
    component notInFuture = LessEqThan(32);
    notInFuture.in[0] <== dob;
    notInFuture.in[1] <== currentDate;
    notInFuture.out === 1;

    // (currentDate - dob) >= ageThreshold. See README "Age arithmetic" for why
    // subtracting YYYYMMDD integers works.
    component oldEnough = GreaterEqThan(32);
    oldEnough.in[0] <== currentDate - dob;
    oldEnough.in[1] <== ageThreshold;
    oldEnough.out === 1;

    // ---- 4. Keep-alive constraints ------------------------------------------
    // Groth16 already binds EVERY public input into the proof, so these lines are
    // NOT what prevents replay (the verifier server checking the challenge does).
    // They only make sure the compiler never treats these inputs as unused.
    signal challengeSq <== challenge * challenge;
    signal verifierIdSq <== verifierId * verifierId;
}

// Only the inputs listed here are public; all others are private.
// Keep this list in the same order as the declarations above and shared/constants.js.
component main {public [
    challenge,
    currentDate,
    issuerPubKeyX,
    issuerPubKeyY,
    ageThreshold,
    verifierId
]} = AgeCheck();
