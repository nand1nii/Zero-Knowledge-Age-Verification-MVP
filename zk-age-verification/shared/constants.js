// shared/constants.js
// THE CONTRACT between all modules: origins, the age threshold, and the ORDER of the
// circuit's public signals. Constants only: no crypto, no helpers, no business logic.
// Works in Node (`require`) and in the browser (`<script>` sets `window.ZK_CONSTANTS`).

(function (root, factory) {
  const constants = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = constants; // Node.js
  } else {
    root.ZK_CONSTANTS = constants; // browser
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const PORTS = Object.freeze({ ISSUER: 3001, WALLET: 3002, VERIFIER: 3003 });

  // The public inputs of circom/circuits/age_check.circom, in EXACTLY the order the
  // circuit declares them. snarkjs puts them in `publicSignals` in this order, so the
  // wallet, the verifier and the circuit tests all index publicSignals with this list.
  // If you change the circuit, change this list too (the circuit tests check they match).
  const PUBLIC_SIGNALS = Object.freeze([
    'challenge',
    'currentDate',
    'issuerPubKeyX',
    'issuerPubKeyY',
    'ageThreshold',
    'verifierId',
  ]);

  // The private inputs (never leave the wallet). Order does not matter for these.
  const PRIVATE_INPUTS = Object.freeze([
    'dob',
    'ID_Number',
    'signatureR8x',
    'signatureR8y',
    'signatureS',
  ]);

  return Object.freeze({
    PORTS,
    ISSUER_ORIGIN: 'http://localhost:' + PORTS.ISSUER,
    WALLET_ORIGIN: 'http://localhost:' + PORTS.WALLET,
    VERIFIER_ORIGIN: 'http://localhost:' + PORTS.VERIFIER,

    // "18 years, 0 months, 0 days" in YYYYMMDD arithmetic (NOT a number of days).
    // A decimal string because public signals are always compared as strings.
    AGE_THRESHOLD: '180000',

    PUBLIC_SIGNALS,
    NUM_PUBLIC_SIGNALS: PUBLIC_SIGNALS.length, // 6
    PRIVATE_INPUTS,

    // Verifier challenge: 31 random bytes (always smaller than the ~254-bit field),
    // valid for 2 minutes and usable once.
    CHALLENGE_BYTES: 31,
    CHALLENGE_TTL_MS: 2 * 60 * 1000,

    // verifierId = the first VERIFIER_ID_BYTES bytes of SHA-256(UTF-8 origin string),
    // read as a big-endian unsigned integer and written as a decimal string.
    // The verifier computes it for its own origin; the wallet recomputes it from
    // `returnOrigin` and refuses to prove if they differ (see client/README.md).
    VERIFIER_ID_HASH: 'SHA-256',
    VERIFIER_ID_BYTES: 31,

    // Credential embedding: a PNG tEXt chunk with this keyword whose text is the
    // base64-encoded credential JSON (format: shared/credential.schema.json).
    PNG_CHUNK_KEYWORD: 'zkcred',
    CREDENTIAL_VERSION: 1,

    // File names written by the circuit builder into the `artifacts` volume.
    ARTIFACTS: Object.freeze({
      WASM: 'age_check.wasm',
      ZKEY: 'age_check_final.zkey',
      VKEY: 'verification_key.json',
    }),

    // File written by issuer/src/keygen.js into shared/generated/.
    ISSUER_PUBKEY_FILE: 'issuer-pubkey.json',
  });
});
