// issuer/src/credential.js
// Creates signed credentials: picks a random 128-bit ID_Number and signs
// Poseidon([ID_Number, dob]) with the issuer's EdDSA (BabyJubJub) private key.

const crypto = require('crypto');
const { buildEddsa } = require('circomlibjs');
const C = require('../../shared/constants');

// buildEddsa() is slow (it builds WebAssembly), so do it once and reuse it.
let eddsaPromise;
function getEddsa() {
  if (!eddsaPromise) eddsaPromise = buildEddsa();
  return eddsaPromise;
}

// The private key is 32 bytes written as 64 hex characters (env var ISSUER_PRIVATE_KEY).
function parsePrivateKey(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex.trim())) {
    throw new Error('ISSUER_PRIVATE_KEY must be 64 hex characters (32 bytes). Run `npm run keygen` to create one.');
  }
  return Buffer.from(hex.trim(), 'hex');
}

// circomlibjs gives points in its internal "Montgomery" form. F.toObject() converts them
// to normal numbers; forgetting this is the number one cause of "signature invalid" bugs.
async function publicKeyFromPrivate(privateKey) {
  const eddsa = await getEddsa();
  const pub = eddsa.prv2pub(privateKey);
  return { x: eddsa.F.toObject(pub[0]).toString(), y: eddsa.F.toObject(pub[1]).toString() };
}

// 128-bit cryptographically secure random integer, as a BigInt.
function generateIdNumber() {
  return BigInt('0x' + crypto.randomBytes(16).toString('hex'));
}

// fields = { name, address, contact, dob } (already validated; dob is "YYYYMMDD").
// Returns the credential JSON object. All big numbers are decimal strings.
async function createCredential(fields, privateKey) {
  const eddsa = await getEddsa();
  const F = eddsa.F;

  const idNumber = generateIdNumber();
  // Same input order as the circuit: Poseidon([ID_Number, dob]).
  const message = eddsa.poseidon([idNumber, BigInt(fields.dob)]);
  const sig = eddsa.signPoseidon(privateKey, message);

  const credential = {
    version: C.CREDENTIAL_VERSION,
    name: fields.name,
    address: fields.address,
    ...(fields.contact ? { contact: fields.contact } : {}),
    dob: fields.dob,
    ID_Number: idNumber.toString(),
    issuerPubKey: await publicKeyFromPrivate(privateKey),
    signature: {
      R8x: F.toObject(sig.R8[0]).toString(),
      R8y: F.toObject(sig.R8[1]).toString(),
      S: sig.S.toString(),
    },
  };

  // Self-check: never hand out a credential whose signature does not verify.
  if (!(await verifyCredentialSignature(credential))) {
    throw new Error('Internal error: freshly signed credential does not verify');
  }
  return credential;
}

// Checks the EdDSA signature in a credential (decimal strings -> field elements).
async function verifyCredentialSignature(credential) {
  const eddsa = await getEddsa();
  const F = eddsa.F;
  const message = eddsa.poseidon([BigInt(credential.ID_Number), BigInt(credential.dob)]);
  const signature = {
    R8: [F.e(BigInt(credential.signature.R8x)), F.e(BigInt(credential.signature.R8y))],
    S: BigInt(credential.signature.S),
  };
  const pubKey = [F.e(BigInt(credential.issuerPubKey.x)), F.e(BigInt(credential.issuerPubKey.y))];
  return eddsa.verifyPoseidon(message, signature, pubKey);
}

module.exports = {
  parsePrivateKey,
  publicKeyFromPrivate,
  generateIdNumber,
  createCredential,
  verifyCredentialSignature,
};
