// verifier/test/server.test.js
// HTTP-level tests with a fake groth16 verifier (no other module needed): challenge contents,
// the ordered /verify checks, single use, expiry, races, the protected page and rate limits.

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const C = require('../../shared/constants');
const { verifierIdForOrigin } = require('../src/verify');
const { ISSUER, GOOD_PROOF, startVerifier, client, honestSignals } = require('./helpers');

describe('verifier server', () => {
  let v;
  let browser;

  beforeEach(async () => {
    v = await startVerifier();
    browser = client(v.url);
  });
  afterEach(() => v.close());

  async function getChallenge(who = browser) {
    const res = await who.post('/challenge', {});
    assert.equal(res.status, 200);
    return res.json();
  }

  async function submit(publicSignals, proof = GOOD_PROOF, who = browser) {
    const res = await who.post('/verify', { proof, publicSignals });
    return { status: res.status, body: await res.json() };
  }

  describe('pages and headers', () => {
    it('serves the landing page with a strict CSP and no COOP header (would break the popup)', async () => {
      const res = await browser.get('/');
      assert.equal(res.status, 200);
      assert.match(await res.text(), /Verify Age with ZK/);
      assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
      assert.equal(res.headers.get('cross-origin-opener-policy'), null);
    });

    it('serves the shared constants to the page', async () => {
      const res = await browser.get('/shared/constants.js');
      assert.equal(res.status, 200);
      assert.match(await res.text(), /PUBLIC_SIGNALS/);
    });

    it('the success page is not reachable without verification, not even as a static file', async () => {
      const res = await browser.get('/success');
      assert.equal(res.status, 303);
      assert.equal(res.headers.get('location'), '/?error=not-verified');
      for (const path of ['/success.html', '/protected/success.html', '/%73uccess.html', '/../protected/success.html']) {
        const r = await browser.get(path);
        assert.notEqual(r.status, 200, path);
        assert.doesNotMatch(await r.text(), /secret password/, path);
      }
    });
  });

  describe('POST /challenge', () => {
    it('returns a fresh challenge and the server\'s own public parameters', async () => {
      const a = await getChallenge();
      const b = await getChallenge();
      assert.notEqual(a.challenge, b.challenge);
      assert.match(a.challenge, /^[1-9][0-9]*$/);
      assert.deepEqual({ ...a, challenge: 'x' }, {
        challenge: 'x',
        currentDate: '20261025',
        ageThreshold: '180000',
        issuerPubKeyX: ISSUER.x,
        issuerPubKeyY: ISSUER.y,
        verifierId: verifierIdForOrigin(C.VERIFIER_ORIGIN),
        returnOrigin: C.VERIFIER_ORIGIN,
      });
    });

    it('sets an httpOnly, SameSite=Lax session cookie', async () => {
      const res = await browser.post('/challenge', {});
      const cookie = res.headers.get('set-cookie');
      assert.match(cookie, /^zkverifier\.sid=/);
      assert.match(cookie, /HttpOnly/);
      assert.match(cookie, /SameSite=Lax/);
    });
  });

  describe('POST /verify', () => {
    it('accepts an honest proof, rotates the session id and unlocks /success', async () => {
      const request = await getChallenge();
      const cookieBefore = browser.cookie;
      const { status, body } = await submit(honestSignals(request));
      assert.equal(status, 200, JSON.stringify(body));
      assert.deepEqual(body, { ok: true, redirect: '/success' });
      assert.notEqual(browser.cookie, cookieBefore);
      assert.equal(v.calls.length, 1);

      const page = await browser.get('/success');
      assert.equal(page.status, 200);
      assert.match(await page.text(), /secret password/);
    });

    it('rejects when there is no challenge', async () => {
      const { status, body } = await submit(['1', '2', '3', '4', '5', '6']);
      assert.equal(status, 400);
      assert.match(body.error, /No active challenge/);
    });

    it('rejects replaying the same proof (challenge is single use)', async () => {
      const request = await getChallenge();
      assert.equal((await submit(honestSignals(request))).status, 200);
      const replay = await submit(honestSignals(request));
      assert.equal(replay.status, 400);
      assert.match(replay.body.error, /No active challenge/);
    });

    it('rejects an old proof against a new challenge', async () => {
      const old = await getChallenge();
      await getChallenge(); // replaces the old one
      const { status, body } = await submit(honestSignals(old));
      assert.equal(status, 400);
      assert.match(body.error, /challenge does not match/);
    });

    it('consumes the challenge even when verification fails', async () => {
      const request = await getChallenge();
      const wrong = honestSignals(request);
      wrong[C.PUBLIC_SIGNALS.indexOf('ageThreshold')] = '0';
      assert.equal((await submit(wrong)).status, 400);
      const retry = await submit(honestSignals(request));
      assert.equal(retry.status, 400);
      assert.match(retry.body.error, /No active challenge/);
    });

    it('rejects an expired challenge (older than 2 minutes)', async () => {
      const request = await getChallenge();
      v.clock.now += C.CHALLENGE_TTL_MS + 1;
      const { status, body } = await submit(honestSignals(request));
      assert.equal(status, 400);
      assert.match(body.error, /expired/);
    });

    it('accepts a proof just before the 2 minutes are up', async () => {
      const request = await getChallenge();
      v.clock.now += C.CHALLENGE_TTL_MS;
      assert.equal((await submit(honestSignals(request))).status, 200);
    });

    it('checks currentDate against the date issued with the challenge (no midnight surprise)', async () => {
      v.clock.now = Date.UTC(2026, 9, 25, 23, 59, 30); // challenge issued just before midnight
      const request = await getChallenge();
      assert.equal(request.currentDate, '20261025');
      v.clock.now = Date.UTC(2026, 9, 26, 0, 0, 30); // proof arrives just after midnight
      assert.equal((await submit(honestSignals(request))).status, 200);
    });

    for (const name of C.PUBLIC_SIGNALS) {
      it(`rejects a proof with the wrong ${name}, without running groth16`, async () => {
        const request = await getChallenge();
        const wrong = honestSignals(request);
        wrong[C.PUBLIC_SIGNALS.indexOf(name)] = '12345';
        const { status, body } = await submit(wrong);
        assert.equal(status, 400);
        assert.match(body.error, new RegExp(name));
        assert.equal(v.calls.length, 0);
      });
    }

    it('rejects the wrong number of public signals', async () => {
      const request = await getChallenge();
      const { status, body } = await submit(honestSignals(request).slice(0, 5));
      assert.equal(status, 400);
      assert.match(body.error, /exactly 6/);
    });

    it('rejects when the Groth16 check fails', async () => {
      const request = await getChallenge();
      const badProof = { ...GOOD_PROOF, pi_a: ['0', '2', '1'] };
      const { status, body } = await submit(honestSignals(request), badProof);
      assert.equal(status, 400);
      assert.match(body.error, /not valid/);
    });

    it('two parallel submissions in one session: only one wins', async () => {
      // Both requests read the session before either saves it, so the session alone
      // cannot stop this; the server's used-challenge list must.
      const slow = await startVerifier({ verifyDelayMs: 100 });
      const who = client(slow.url);
      try {
        const request = await getChallenge(who);
        const results = await Promise.all([submit(honestSignals(request), GOOD_PROOF, who), submit(honestSignals(request), GOOD_PROOF, who)]);
        assert.deepEqual(results.map((r) => r.status).sort(), [200, 400]);
        assert.match(results.find((r) => r.status === 400).body.error, /already used/);
      } finally {
        await slow.close();
      }
    });

    it('a different browser cannot use my challenge', async () => {
      const request = await getChallenge();
      const attacker = client(v.url);
      await getChallenge(attacker);
      const { status } = await submit(honestSignals(request), GOOD_PROOF, attacker);
      assert.equal(status, 400);
    });

    it('rejects bad JSON and oversized bodies with 4xx', async () => {
      await getChallenge();
      assert.equal((await browser.post('/verify', '{not json')).status, 400);
      await getChallenge();
      assert.equal((await browser.post('/verify', JSON.stringify({ pad: 'x'.repeat(20000) }))).status, 413);
    });

    it('"Start over" ends the verified session', async () => {
      const request = await getChallenge();
      await submit(honestSignals(request));
      assert.equal((await browser.get('/success')).status, 200);
      await browser.post('/logout', {});
      assert.equal((await browser.get('/success')).status, 303);
    });
  });

  describe('rate limiting', () => {
    it('limits /challenge and /verify per client', async () => {
      const limited = await startVerifier({ rateLimitPerMinute: 3 });
      const who = client(limited.url);
      try {
        const statuses = [];
        for (let i = 0; i < 4; i++) statuses.push((await who.post('/challenge', {})).status);
        assert.deepEqual(statuses, [200, 200, 200, 429]);
      } finally {
        await limited.close();
      }
    });
  });
});
