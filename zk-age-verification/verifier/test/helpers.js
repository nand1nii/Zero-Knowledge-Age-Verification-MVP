// verifier/test/helpers.js
// Test fixtures: a fake issuer key and vkey, a fake groth16 verifier, a controllable clock,
// and a tiny HTTP client that keeps the session cookie (like a browser would).

const { createApp } = require('../src/server');

const ISSUER = { x: '1111111111111111111111', y: '2222222222222222222222' };
const FAKE_VKEY = { protocol: 'groth16', curve: 'bn128', nPublic: 6 };
const START = Date.UTC(2026, 9, 25, 12, 0, 0); // 25 Oct 2026, noon UTC

// A syntactically valid Groth16 proof. The fake verifier accepts it unless pi_a[0] is "0".
const GOOD_PROOF = {
  pi_a: ['1', '2', '1'],
  pi_b: [['1', '2'], ['3', '4'], ['1', '0']],
  pi_c: ['5', '6', '1'],
  protocol: 'groth16',
  curve: 'bn128',
};

// verifyDelayMs makes the fake verifier as slow as a real one (real Groth16 takes a few ms),
// which opens the window for race conditions between parallel requests.
async function startVerifier({ verifyDelayMs = 0, ...overrides } = {}) {
  const clock = { now: START };
  const calls = [];
  const groth16Verify = async (vkey, publicSignals, proof) => {
    calls.push({ vkey, publicSignals, proof });
    if (verifyDelayMs) await new Promise((resolve) => setTimeout(resolve, verifyDelayMs));
    return proof.pi_a[0] !== '0';
  };
  const app = createApp({
    vkey: FAKE_VKEY,
    issuerPubKey: ISSUER,
    sessionSecret: 'test-secret',
    clock: () => new Date(clock.now),
    groth16Verify,
    ...overrides,
  });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  return { url, clock, calls, close: () => new Promise((r) => server.close(r)) };
}

// Minimal cookie-keeping client (one cookie: the session).
function client(baseUrl) {
  let cookie = null;
  async function request(method, path, body) {
    const headers = {};
    if (cookie) headers.cookie = cookie;
    if (body !== undefined) headers['content-type'] = 'application/json';
    const res = await fetch(baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
      redirect: 'manual',
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    return res;
  }
  return {
    get: (path) => request('GET', path),
    post: (path, body) => request('POST', path, body),
    get cookie() { return cookie; },
    set cookie(value) { cookie = value; },
  };
}

// The publicSignals an honest wallet would send for this challenge response.
function honestSignals(challengeResponse) {
  const r = challengeResponse;
  return [r.challenge, r.currentDate, r.issuerPubKeyX, r.issuerPubKeyY, r.ageThreshold, r.verifierId];
}

module.exports = { ISSUER, FAKE_VKEY, START, GOOD_PROOF, startVerifier, client, honestSignals };
