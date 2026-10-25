// verifier/test/session.test.js
// Challenge lifecycle: random 31-byte decimal values, stored in the session, expiring after
// the TTL, and removed on first use even when that use fails.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const C = require('../../shared/constants');
const { newChallengeValue, issueChallenge, consumeChallenge } = require('../src/session');

describe('challenges', () => {
  it('are random decimal strings below 2^248 (31 bytes)', () => {
    const a = newChallengeValue();
    const b = newChallengeValue();
    assert.match(a, /^(0|[1-9][0-9]*)$/);
    assert.notEqual(a, b);
    assert.ok(BigInt(a) < 2n ** 248n);
  });

  it('default lifetime is 2 minutes', () => {
    assert.equal(C.CHALLENGE_TTL_MS, 120000);
  });

  it('can be consumed once', () => {
    const session = {};
    const issued = issueChallenge(session, { nowMs: 0, ttlMs: 1000, currentDate: '20261025' });
    assert.deepEqual(consumeChallenge(session, 500), { challenge: issued });
    assert.match(consumeChallenge(session, 500).error, /No active challenge/);
  });

  it('expire after the TTL, and an expired challenge is removed too', () => {
    const session = {};
    issueChallenge(session, { nowMs: 0, ttlMs: 1000, currentDate: '20261025' });
    assert.match(consumeChallenge(session, 1001).error, /expired/);
    assert.equal(session.challenge, undefined);
  });

  it('a new challenge replaces the old one', () => {
    const session = {};
    const first = issueChallenge(session, { nowMs: 0, ttlMs: 1000, currentDate: '20261025' });
    const second = issueChallenge(session, { nowMs: 0, ttlMs: 1000, currentDate: '20261025' });
    assert.notEqual(first.value, second.value);
    assert.equal(consumeChallenge(session, 1).challenge.value, second.value);
  });
});
