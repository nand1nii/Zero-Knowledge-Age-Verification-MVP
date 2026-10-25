// verifier/src/verify.js
// Checks a submitted proof: every public signal must equal the server's own expected value
// (compared as decimal strings, never JS numbers), then snarkjs.groth16.verify must pass.

const crypto = require('crypto');
const C = require('../../shared/constants');

const DECIMAL = /^(0|[1-9][0-9]{0,77})$/; // canonical decimal string, at most 78 digits

function isDecimal(value) {
  return typeof value === 'string' && DECIMAL.test(value);
}

// verifierId = first 31 bytes of SHA-256(origin), as a decimal string (rule in shared/constants.js).
// The wallet recomputes this from returnOrigin, so a proof is tied to the site that receives it.
function verifierIdForOrigin(origin) {
  const digest = crypto.createHash('sha256').update(origin, 'utf8').digest();
  return BigInt('0x' + digest.subarray(0, C.VERIFIER_ID_BYTES).toString('hex')).toString();
}

// Today as "YYYYMMDD" from the server clock, in UTC.
function todayYYYYMMDD(date = new Date()) {
  return date.toISOString().slice(0, 10).replace(/-/g, '');
}

// expected = { challenge, currentDate, issuerPubKeyX, issuerPubKeyY, ageThreshold, verifierId }
// Returns null when every public signal matches, otherwise the reason it does not.
function checkPublicSignals(publicSignals, expected) {
  // Count first (so indexing below is safe). snarkjs does NOT check the count itself: it
  // would happily verify with a signal missing from the end if that signal was 0.
  if (!Array.isArray(publicSignals) || publicSignals.length !== C.NUM_PUBLIC_SIGNALS) {
    return `publicSignals must contain exactly ${C.NUM_PUBLIC_SIGNALS} values`;
  }
  for (const [index, name] of C.PUBLIC_SIGNALS.entries()) {
    const value = publicSignals[index];
    if (!isDecimal(value)) return `${name} is not a decimal string`;
    if (value !== String(expected[name])) return `${name} does not match`;
  }
  return null;
}

// Groth16 proof as produced by snarkjs: pi_a, pi_c = 3 numbers, pi_b = 3 pairs of numbers.
function isProofShape(proof) {
  const isPoint = (p, size) => Array.isArray(p) && p.length === size;
  return (
    proof !== null &&
    typeof proof === 'object' &&
    isPoint(proof.pi_a, 3) && proof.pi_a.every(isDecimal) &&
    isPoint(proof.pi_c, 3) && proof.pi_c.every(isDecimal) &&
    isPoint(proof.pi_b, 3) && proof.pi_b.every((pair) => isPoint(pair, 2) && pair.every(isDecimal))
  );
}

// Steps 3-5 of the verification (the challenge was already consumed by the caller).
// deps = { vkey, groth16Verify } so tests can swap in a fake verifier.
async function verifySubmission(body, expected, { vkey, groth16Verify }) {
  const { proof, publicSignals } = body || {};

  const mismatch = checkPublicSignals(publicSignals, expected);
  if (mismatch) return { ok: false, reason: mismatch };
  if (!isProofShape(proof)) return { ok: false, reason: 'proof is malformed' };

  let valid = false;
  try {
    valid = await groth16Verify(vkey, publicSignals, proof);
  } catch (err) {
    valid = false;
  }
  return valid ? { ok: true } : { ok: false, reason: 'the proof is not valid' };
}

module.exports = {
  isDecimal,
  verifierIdForOrigin,
  todayYYYYMMDD,
  checkPublicSignals,
  isProofShape,
  verifySubmission,
};
