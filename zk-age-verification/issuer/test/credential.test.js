// issuer/test/credential.test.js
// Credential creation: the format matches shared/credential.schema.json, big numbers are
// decimal strings, ID_Number is 128-bit, and the EdDSA signature verifies.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const Ajv2020 = require('ajv/dist/2020');
const schema = require('../../shared/credential.schema.json');
const {
  createCredential,
  verifyCredentialSignature,
  publicKeyFromPrivate,
  parsePrivateKey,
  generateIdNumber,
} = require('../src/credential');
const { TEST_KEY, TEST_KEY_HEX } = require('./helpers');

const validateSchema = new Ajv2020({ allErrors: true }).compile(schema);
const fields = { name: 'José नमस्ते', address: '1 Main St', contact: '', dob: '20000115' };

describe('credential', () => {
  it('matches the shared credential schema', async () => {
    const credential = await createCredential(fields, TEST_KEY);
    assert.ok(validateSchema(credential), JSON.stringify(validateSchema.errors));
    assert.equal(credential.version, 1);
    assert.equal('contact' in credential, false); // empty contact is left out
  });

  it('stores every big number as a decimal string', async () => {
    const c = await createCredential(fields, TEST_KEY);
    for (const value of [c.ID_Number, c.issuerPubKey.x, c.issuerPubKey.y, c.signature.R8x, c.signature.R8y, c.signature.S]) {
      assert.equal(typeof value, 'string');
      assert.match(value, /^(0|[1-9][0-9]*)$/);
    }
  });

  it('has a valid signature over Poseidon([ID_Number, dob])', async () => {
    const credential = await createCredential(fields, TEST_KEY);
    assert.equal(await verifyCredentialSignature(credential), true);
  });

  it('signature fails if dob or ID_Number is changed', async () => {
    const credential = await createCredential(fields, TEST_KEY);
    assert.equal(await verifyCredentialSignature({ ...credential, dob: '19990115' }), false);
    const otherId = (BigInt(credential.ID_Number) + 1n).toString();
    assert.equal(await verifyCredentialSignature({ ...credential, ID_Number: otherId }), false);
  });

  it('embeds the issuer public key in normal (non-Montgomery) form', async () => {
    const credential = await createCredential(fields, TEST_KEY);
    assert.deepEqual(credential.issuerPubKey, await publicKeyFromPrivate(TEST_KEY));
  });

  it('ID_Number is a fresh 128-bit random BigInt each time', () => {
    const a = generateIdNumber();
    const b = generateIdNumber();
    assert.equal(typeof a, 'bigint');
    assert.notEqual(a, b);
    assert.ok(a < 2n ** 128n);
  });

  it('parsePrivateKey only accepts 64 hex characters', () => {
    assert.deepEqual(parsePrivateKey(TEST_KEY_HEX), TEST_KEY);
    for (const bad of [undefined, '', 'abc', TEST_KEY_HEX + '00', 'z'.repeat(64)]) {
      assert.throws(() => parsePrivateKey(bad), /64 hex/);
    }
  });
});
