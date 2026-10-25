// verifier/test/verify.test.js
// Unit tests for the proof checks: public signals compared as exact decimal strings in
// constants order, exact count, proof shape, and the verifierId / date helpers.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const C = require('../../shared/constants');
const { verifierIdForOrigin, todayYYYYMMDD, checkPublicSignals, isProofShape, verifySubmission } = require('../src/verify');
const { GOOD_PROOF, FAKE_VKEY } = require('./helpers');

const expected = {
  challenge: '123456789012345678901234567890',
  currentDate: '20261025',
  issuerPubKeyX: '111',
  issuerPubKeyY: '222',
  ageThreshold: '180000',
  verifierId: '333',
};
const signals = () => C.PUBLIC_SIGNALS.map((name) => expected[name]);

describe('verifierIdForOrigin', () => {
  it('is the first 31 bytes of SHA-256(origin) as a decimal string', () => {
    const hex = crypto.createHash('sha256').update('http://localhost:3003').digest('hex').slice(0, 62);
    assert.equal(verifierIdForOrigin('http://localhost:3003'), BigInt('0x' + hex).toString());
  });

  it('differs between sites and fits in 248 bits', () => {
    const a = verifierIdForOrigin('http://localhost:3003');
    assert.notEqual(a, verifierIdForOrigin('http://localhost:3004'));
    assert.ok(BigInt(a) < 2n ** 248n);
  });
});

describe('todayYYYYMMDD', () => {
  it('uses the UTC date', () => {
    assert.equal(todayYYYYMMDD(new Date(Date.UTC(2026, 9, 25, 23, 59))), '20261025');
    assert.equal(todayYYYYMMDD(new Date(Date.UTC(2026, 0, 5, 0, 0))), '20260105');
  });
});

describe('checkPublicSignals', () => {
  it('accepts signals that all match, in constants order', () => {
    assert.equal(checkPublicSignals(signals(), expected), null);
  });

  for (const name of C.PUBLIC_SIGNALS) {
    it(`rejects a wrong ${name}`, () => {
      const bad = signals();
      bad[C.PUBLIC_SIGNALS.indexOf(name)] = '999';
      assert.match(checkPublicSignals(bad, expected), new RegExp(`${name} does not match`));
    });
  }

  it('rejects ageThreshold 0 (the "prove age >= 0" trick)', () => {
    const bad = signals();
    bad[C.PUBLIC_SIGNALS.indexOf('ageThreshold')] = '0';
    assert.match(checkPublicSignals(bad, expected), /ageThreshold/);
  });

  it('requires exactly 6 signals', () => {
    assert.match(checkPublicSignals(signals().slice(0, 5), expected), /exactly 6/);
    assert.match(checkPublicSignals([...signals(), '0'], expected), /exactly 6/);
    assert.match(checkPublicSignals('not an array', expected), /exactly 6/);
    assert.match(checkPublicSignals(undefined, expected), /exactly 6/);
  });

  it('compares canonical decimal strings, never JS numbers or other spellings', () => {
    const at = C.PUBLIC_SIGNALS.indexOf('ageThreshold');
    for (const spelling of [180000, '0180000', '0x2bf20', '180000.0', ' 180000', '+180000', '1.8e5']) {
      const bad = signals();
      bad[at] = spelling;
      assert.notEqual(checkPublicSignals(bad, expected), null, `accepted ${JSON.stringify(spelling)}`);
    }
  });
});

describe('isProofShape', () => {
  it('accepts a snarkjs-shaped proof', () => {
    assert.equal(isProofShape(GOOD_PROOF), true);
  });

  it('rejects malformed proofs', () => {
    for (const bad of [null, 'x', {}, { ...GOOD_PROOF, pi_a: ['1', '2'] }, { ...GOOD_PROOF, pi_b: [['1'], ['2'], ['3']] }, { ...GOOD_PROOF, pi_c: [1, 2, 3] }]) {
      assert.equal(isProofShape(bad), false, JSON.stringify(bad));
    }
  });
});

describe('verifySubmission', () => {
  const deps = (result) => {
    const calls = [];
    return { calls, vkey: FAKE_VKEY, groth16Verify: async (...args) => { calls.push(args); if (result instanceof Error) throw result; return result; } };
  };

  it('accepts when signals match and groth16 verifies', async () => {
    const d = deps(true);
    assert.deepEqual(await verifySubmission({ proof: GOOD_PROOF, publicSignals: signals() }, expected, d), { ok: true });
    assert.equal(d.calls.length, 1);
    assert.deepEqual(d.calls[0][1], signals());
  });

  it('never calls groth16 when a public signal is wrong', async () => {
    const d = deps(true);
    const bad = signals();
    bad[0] = '1';
    const result = await verifySubmission({ proof: GOOD_PROOF, publicSignals: bad }, expected, d);
    assert.equal(result.ok, false);
    assert.equal(d.calls.length, 0);
  });

  it('rejects when groth16 says no or throws', async () => {
    assert.equal((await verifySubmission({ proof: GOOD_PROOF, publicSignals: signals() }, expected, deps(false))).ok, false);
    assert.equal((await verifySubmission({ proof: GOOD_PROOF, publicSignals: signals() }, expected, deps(new Error('boom')))).ok, false);
  });

  it('rejects a missing body', async () => {
    assert.equal((await verifySubmission(undefined, expected, deps(true))).ok, false);
  });
});
