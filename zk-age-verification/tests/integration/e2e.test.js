// tests/integration/e2e.test.js
// Cross-module test without a browser: a card from the REAL issuer, read and proven with the
// wallet's own code, must be accepted by the REAL verifier. Plus replay, expiry and misuse.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const snarkjs = require('snarkjs');
const C = require('../../shared/constants');
const PngParse = require('../../client/public/png-parse');
const Wallet = require('../../client/public/wallet-core');
const stack = require('./stack');

// A tiny cookie-keeping HTTP client, like one browser tab on the verifier site.
function browserSession(baseUrl) {
  let cookie = null;
  return async function request(method, path, body) {
    const res = await fetch(baseUrl + path, {
      method,
      redirect: 'manual',
      headers: { ...(cookie ? { cookie } : {}), ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    return res;
  };
}

describe('issuer -> wallet -> verifier (real servers, real proofs)', () => {
  let s;
  let artifacts;

  before(async () => {
    s = await stack.start();
    // Download the proving files from the wallet server, exactly like the browser does.
    const download = async (name) => new Uint8Array(await (await fetch(`${s.wallet}/artifacts/${name}`)).arrayBuffer());
    artifacts = { wasm: { type: 'mem', data: await download(C.ARTIFACTS.WASM) }, zkey: { type: 'mem', data: await download(C.ARTIFACTS.ZKEY) } };
  });

  after(async () => {
    if (s) await s.stop();
    if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
  });

  async function issueCard(dob, name = 'Ada Lovelace') {
    const form = new FormData();
    form.append('name', name);
    form.append('dob', dob);
    form.append('address', '12 Analytical Way');
    const res = await fetch(`${s.issuer}/issue`, { method: 'POST', body: form });
    assert.equal(res.status, 200, await res.clone().text());
    return new Uint8Array(await res.arrayBuffer());
  }

  async function getChallenge(request, baseUrl = s.verifier) {
    const res = await request('POST', '/challenge', {});
    assert.equal(res.status, 200, `challenge from ${baseUrl}`);
    return res.json();
  }

  // What the wallet does after the user approves (minus the DOM).
  async function walletProve(cardBytes, challengeResponse, overrides = {}) {
    const credential = Wallet.checkCredential(PngParse.extractCredential(cardBytes));
    const request = Wallet.parseRequest({ ...challengeResponse, ...overrides });
    return snarkjs.groth16.fullProve(Wallet.buildCircuitInput(credential, request), artifacts.wasm, artifacts.zkey);
  }

  it('a card from the real Issuer produces a proof the real Verifier accepts', async () => {
    const card = await issueCard('2000-01-15');
    const request = browserSession(s.verifier);
    const challenge = await getChallenge(request);

    // The wallet's checks pass for a genuine request.
    const parsed = Wallet.parseRequest(challenge);
    assert.equal(Wallet.isAllowedOrigin(parsed.returnOrigin, [C.VERIFIER_ORIGIN]), true);
    assert.equal(await Wallet.verifierIdForOrigin(parsed.returnOrigin), parsed.verifierId);

    const { proof, publicSignals } = await walletProve(card, challenge);
    const verify = await request('POST', '/verify', { proof, publicSignals });
    assert.equal(verify.status, 200, await verify.clone().text());

    const page = await request('GET', '/success');
    assert.equal(page.status, 200);
    assert.match(await page.text(), /secret password/);
  });

  it('the proof reveals nothing from the card', async () => {
    const card = await issueCard('2000-01-15', 'Zebediah Uniquename');
    const credential = PngParse.extractCredential(card);
    const challenge = await getChallenge(browserSession(s.verifier));
    const sent = JSON.stringify(await walletProve(card, challenge));
    for (const secret of ['Zebediah', credential.ID_Number, credential.signature.R8x, credential.signature.S, credential.address]) {
      assert.equal(sent.includes(secret), false, `proof message contains ${secret}`);
    }
  });

  it('reusing the same challenge fails (replay)', async () => {
    const card = await issueCard('2000-01-15');
    const request = browserSession(s.verifier);
    const message = await walletProve(card, await getChallenge(request));
    assert.equal((await request('POST', '/verify', message)).status, 200);

    const replay = await request('POST', '/verify', message);
    assert.equal(replay.status, 400);
    assert.match((await replay.json()).error, /No active challenge/);
  });

  it('an old proof is rejected under a new challenge', async () => {
    const card = await issueCard('2000-01-15');
    const request = browserSession(s.verifier);
    const oldMessage = await walletProve(card, await getChallenge(request));
    await getChallenge(request); // a new verification attempt
    const res = await request('POST', '/verify', oldMessage);
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /challenge does not match/);
  });

  it('an expired challenge fails', { timeout: 60000 }, async (t) => {
    if (!s.spawned) return t.skip('needs a short-lived verifier, only available when this test starts the servers');
    const shortLived = await s.startVerifier(3013, { CHALLENGE_TTL_MS: '1500' });
    const card = await issueCard('2000-01-15');
    const request = browserSession(shortLived);
    const message = await walletProve(card, await getChallenge(request, shortLived));
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const res = await request('POST', '/verify', message);
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /expired/);
  });

  it('an underage card cannot produce a proof, and lowering the threshold is caught', async () => {
    const card = await issueCard('2015-06-01');
    const request = browserSession(s.verifier);
    const challenge = await getChallenge(request);
    await assert.rejects(walletProve(card, challenge), /Assert Failed/);

    // A cheating wallet proves "age >= 0" instead: a valid proof, but the verifier refuses it.
    const cheat = await walletProve(card, challenge, { ageThreshold: '0' });
    const res = await request('POST', '/verify', cheat);
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /ageThreshold/);
  });

  it('a proof made for another website is rejected (verifierId)', async () => {
    const card = await issueCard('2000-01-15');
    const request = browserSession(s.verifier);
    const challenge = await getChallenge(request);
    const otherSite = await Wallet.verifierIdForOrigin('https://other-site.example');
    const message = await walletProve(card, challenge, { verifierId: otherSite });
    const res = await request('POST', '/verify', message);
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /verifierId/);
  });

  it('a different browser session cannot use someone else\'s proof', async () => {
    const card = await issueCard('2000-01-15');
    const victim = browserSession(s.verifier);
    const message = await walletProve(card, await getChallenge(victim));
    const attacker = browserSession(s.verifier);
    await getChallenge(attacker);
    assert.equal((await attacker('POST', '/verify', message)).status, 400);
  });
});
