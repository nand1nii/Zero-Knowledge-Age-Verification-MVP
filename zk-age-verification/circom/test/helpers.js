// circom/test/helpers.js
// Test-only helpers: a tiny EdDSA "issuer" (our own copy, nothing imported from issuer/),
// proof generation / verification, and a minimal copy of the verifier's public-signal check.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const snarkjs = require('snarkjs');
const { buildEddsa } = require('circomlibjs');
const C = require('../../shared/constants');

const ARTIFACTS_DIR = process.env.ARTIFACTS_DIR || path.join(__dirname, '..', '..', 'artifacts');
const PATHS = {
  wasm: path.join(ARTIFACTS_DIR, C.ARTIFACTS.WASM),
  zkey: path.join(ARTIFACTS_DIR, C.ARTIFACTS.ZKEY),
  vkey: path.join(ARTIFACTS_DIR, C.ARTIFACTS.VKEY),
  sym: path.join(ARTIFACTS_DIR, 'build', 'age_check.sym'),
  circuit: path.join(__dirname, '..', 'circuits', 'age_check.circom'),
};

// BN254 scalar field prime: all circuit arithmetic happens modulo this number.
const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let eddsaPromise;
function getEddsa() {
  if (!eddsaPromise) eddsaPromise = buildEddsa();
  return eddsaPromise;
}

function randomDecimal(bytes) {
  return BigInt('0x' + crypto.randomBytes(bytes).toString('hex')).toString();
}

// A test issuer with a fresh random private key.
// circomlibjs returns points in Montgomery form: F.toObject() converts them to normal numbers.
async function makeIssuer() {
  const eddsa = await getEddsa();
  const F = eddsa.F;
  const privateKey = crypto.randomBytes(32);
  const pub = eddsa.prv2pub(privateKey);
  return {
    pubKey: { x: F.toObject(pub[0]).toString(), y: F.toObject(pub[1]).toString() },
    // Signs Poseidon([ID_Number, dob]), the same message the real issuer signs.
    sign(ID_Number, dob) {
      const msg = eddsa.poseidon([BigInt(ID_Number), BigInt(dob)]);
      const sig = eddsa.signPoseidon(privateKey, msg);
      return {
        R8x: F.toObject(sig.R8[0]).toString(),
        R8y: F.toObject(sig.R8[1]).toString(),
        S: sig.S.toString(),
      };
    },
  };
}

// The message hash, as a decimal string (used to check it never appears in a proof).
async function messageHash(ID_Number, dob) {
  const eddsa = await getEddsa();
  return eddsa.F.toObject(eddsa.poseidon([BigInt(ID_Number), BigInt(dob)])).toString();
}

// A credential like the one the issuer embeds in the PNG (only the fields the circuit uses).
function makeCredential(issuer, dob) {
  const ID_Number = randomDecimal(16); // 128-bit, like the real issuer
  return { dob: String(dob), ID_Number, issuerPubKey: issuer.pubKey, signature: issuer.sign(ID_Number, dob) };
}

// The verifier's request: all public values. "Today" is fixed so the tests are stable.
function makeRequest(issuer, overrides = {}) {
  return {
    challenge: randomDecimal(C.CHALLENGE_BYTES),
    currentDate: '20261025',
    issuerPubKeyX: issuer.pubKey.x,
    issuerPubKeyY: issuer.pubKey.y,
    ageThreshold: C.AGE_THRESHOLD,
    verifierId: randomDecimal(C.VERIFIER_ID_BYTES),
    ...overrides,
  };
}

function circuitInput(credential, request) {
  const input = {
    dob: credential.dob,
    ID_Number: credential.ID_Number,
    signatureR8x: credential.signature.R8x,
    signatureR8y: credential.signature.R8y,
    signatureS: credential.signature.S,
  };
  for (const name of C.PUBLIC_SIGNALS) input[name] = request[name];
  return input;
}

function prove(input) {
  return snarkjs.groth16.fullProve(input, PATHS.wasm, PATHS.zkey);
}

let vkey;
function verifyProof(publicSignals, proof) {
  if (!vkey) vkey = JSON.parse(fs.readFileSync(PATHS.vkey, 'utf8'));
  return snarkjs.groth16.verify(vkey, publicSignals, proof);
}

// Minimal copy of the comparison the real verifier does (verifier/src/verify.js).
// Returns the name of the first public signal that does not match, or null if all match.
function serverSideCheck(publicSignals, expected) {
  if (!Array.isArray(publicSignals) || publicSignals.length !== C.NUM_PUBLIC_SIGNALS) return 'length';
  for (const [i, name] of C.PUBLIC_SIGNALS.entries()) {
    if (publicSignals[i] !== String(expected[name])) return name;
  }
  return null;
}

// snarkjs keeps worker threads alive; stop them so `node --test` can exit.
async function terminateCurve() {
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
}

module.exports = {
  PATHS,
  FIELD_P,
  makeIssuer,
  messageHash,
  makeCredential,
  makeRequest,
  circuitInput,
  prove,
  verifyProof,
  serverSideCheck,
  terminateCurve,
};
