// issuer/test/keygen.test.js
// keygen writes the public key derived from ISSUER_PRIVATE_KEY, and creates a new private
// key (printed once) when none is set.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { publicKeyFromPrivate, parsePrivateKey } = require('../src/credential');
const { TEST_KEY, TEST_KEY_HEX } = require('./helpers');

const KEYGEN = path.join(__dirname, '..', 'src', 'keygen.js');

function runKeygen(env) {
  const outFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'keygen-')), 'issuer-pubkey.json');
  const cleanEnv = { ...process.env, ISSUER_PUBKEY_PATH: outFile };
  delete cleanEnv.ISSUER_PRIVATE_KEY;
  const stdout = execFileSync(process.execPath, [KEYGEN], { env: { ...cleanEnv, ...env }, encoding: 'utf8' });
  return { stdout, pubKey: JSON.parse(fs.readFileSync(outFile, 'utf8')) };
}

describe('keygen', () => {
  it('writes the public key that matches ISSUER_PRIVATE_KEY', async () => {
    const { pubKey } = runKeygen({ ISSUER_PRIVATE_KEY: TEST_KEY_HEX });
    assert.deepEqual(pubKey, await publicKeyFromPrivate(TEST_KEY));
    assert.match(pubKey.x, /^[0-9]+$/);
  });

  it('creates and prints a new private key when none is set', async () => {
    const { stdout, pubKey } = runKeygen({});
    const printed = /ISSUER_PRIVATE_KEY=([0-9a-f]{64})/.exec(stdout);
    assert.ok(printed, stdout);
    assert.deepEqual(pubKey, await publicKeyFromPrivate(parsePrivateKey(printed[1])));
  });
});
