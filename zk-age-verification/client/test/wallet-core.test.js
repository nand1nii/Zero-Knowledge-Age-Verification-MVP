// client/test/wallet-core.test.js
// The wallet's decisions: exact-match origin allowlist (wrong returnOrigin is refused),
// request parsing, verifierId binding, privacy sanity checks, and the circuit input.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const C = require('../../shared/constants');
const W = require('../public/wallet-core');

const ALLOWLIST = ['http://localhost:3003'];
const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);

// Independent Node implementation of the verifierId rule (shared/constants.js).
function nodeVerifierId(origin) {
  const hex = crypto.createHash('sha256').update(origin).digest('hex').slice(0, 2 * C.VERIFIER_ID_BYTES);
  return BigInt('0x' + hex).toString();
}

const goodParams = {
  challenge: '123456789',
  currentDate: '20261025',
  ageThreshold: '180000',
  issuerPubKeyX: '111',
  issuerPubKeyY: '222',
  verifierId: nodeVerifierId('http://localhost:3003'),
  returnOrigin: 'http://localhost:3003',
};

const credential = {
  version: 1,
  name: 'Ada',
  address: 'x',
  dob: '20000115',
  ID_Number: '987654321',
  issuerPubKey: { x: '111', y: '222' },
  signature: { R8x: '1', R8y: '2', S: '3' },
};

describe('origin allowlist (wrong returnOrigin is refused)', () => {
  it('accepts an exact match', () => {
    assert.equal(W.isAllowedOrigin('http://localhost:3003', ALLOWLIST), true);
  });

  for (const bad of [
    'http://localhost:3004',
    'http://localhost:30030',
    'http://localhost:3003/',
    'http://localhost:3003/path',
    'http://localhost:3003.evil.example',
    'http://localhost:3003@evil.example',
    'http://LOCALHOST:3003',
    'https://localhost:3003',
    'http://127.0.0.1:3003',
    'javascript:alert(1)',
    'null',
    '*',
    '',
    undefined,
  ]) {
    it(`refuses ${JSON.stringify(bad)}`, () => {
      assert.equal(W.isAllowedOrigin(bad, ALLOWLIST), false);
    });
  }
});

describe('parseRequest', () => {
  it('reads all public values and the return origin (URLSearchParams too)', () => {
    assert.deepEqual(W.parseRequest(goodParams), goodParams);
    assert.deepEqual(W.parseRequest(new URLSearchParams(goodParams)), goodParams);
  });

  for (const name of [...C.PUBLIC_SIGNALS, 'returnOrigin']) {
    it(`rejects a missing ${name}`, () => {
      const params = { ...goodParams };
      delete params[name];
      assert.throws(() => W.parseRequest(params), W.WalletError);
    });
  }

  it('rejects numbers that are not plain decimal strings', () => {
    for (const bad of ['0x10', '-1', '1e5', '01', ' 1', '1.0']) {
      assert.throws(() => W.parseRequest({ ...goodParams, challenge: bad }), W.WalletError, bad);
    }
  });

  it('rejects a currentDate that is not YYYYMMDD', () => {
    assert.throws(() => W.parseRequest({ ...goodParams, currentDate: '2026105' }), /invalid date/);
  });
});

describe('verifierIdForOrigin', () => {
  it('matches the SHA-256 rule from shared/constants.js (computed independently)', async () => {
    for (const origin of ['http://localhost:3003', 'https://example.org']) {
      assert.equal(await W.verifierIdForOrigin(origin), nodeVerifierId(origin));
    }
  });
});

describe('checkRequestIsReasonable (privacy checks)', () => {
  it('accepts 18+ and 21+ for today', () => {
    W.checkRequestIsReasonable(goodParams, NOW);
    W.checkRequestIsReasonable({ ...goodParams, ageThreshold: '210000' }, NOW);
  });

  it('refuses odd thresholds that could narrow down a birthday', () => {
    for (const t of ['0', '180001', '175000', '9999', '1210000']) {
      assert.throws(() => W.checkRequestIsReasonable({ ...goodParams, ageThreshold: t }, NOW), /unusual age/, t);
    }
  });

  it('accepts today +/- 1 day (time zones), refuses other dates', () => {
    for (const d of ['20261024', '20261025', '20261026']) W.checkRequestIsReasonable({ ...goodParams, currentDate: d }, NOW);
    for (const d of ['20261023', '20261027', '20361025']) {
      assert.throws(() => W.checkRequestIsReasonable({ ...goodParams, currentDate: d }, NOW), /date/, d);
    }
  });

  it('requiredAge turns 180000 into 18', () => {
    assert.equal(W.requiredAge(goodParams), 18);
  });
});

describe('credential checks', () => {
  it('accepts a well-formed credential and refuses broken ones', () => {
    assert.equal(W.checkCredential(credential), credential);
    for (const bad of [null, {}, { ...credential, version: 2 }, { ...credential, dob: 20000115 }, { ...credential, signature: { R8x: '1', R8y: '2' } }, { ...credential, ID_Number: 42 }]) {
      assert.throws(() => W.checkCredential(bad), W.WalletError);
    }
  });

  it('detects a card from a different issuer', () => {
    assert.equal(W.isFromRequestedIssuer(credential, goodParams), true);
    assert.equal(W.isFromRequestedIssuer({ ...credential, issuerPubKey: { x: '111', y: '999' } }, goodParams), false);
  });

  it('applies the same age rule as the circuit (exact 18th birthday passes)', () => {
    assert.equal(W.meetsAgeRequirement({ ...credential, dob: '20081025' }, goodParams), true);
    assert.equal(W.meetsAgeRequirement({ ...credential, dob: '20081026' }, goodParams), false);
    assert.equal(W.meetsAgeRequirement({ ...credential, dob: '20270101' }, goodParams), false);
  });
});

describe('buildCircuitInput', () => {
  it('has exactly the circuit inputs: private from the card, public from the request', () => {
    const input = W.buildCircuitInput(credential, goodParams);
    assert.deepEqual(Object.keys(input).sort(), [...C.PRIVATE_INPUTS, ...C.PUBLIC_SIGNALS].sort());
    assert.equal(input.dob, credential.dob);
    assert.equal(input.signatureS, credential.signature.S);
    for (const name of C.PUBLIC_SIGNALS) assert.equal(input[name], goodParams[name]);
    assert.equal('returnOrigin' in input, false);
  });
});
