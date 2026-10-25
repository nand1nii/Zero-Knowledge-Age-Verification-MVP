// client/test/server.test.js
// The wallet's static server: strict CSP, the allowlist config, and ONLY the wasm and zkey
// served from the artifacts folder with the right MIME types (fake artifacts, no circom needed).

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createApp, parseAllowlist } = require('../src/server');

describe('wallet server', () => {
  let server;
  let url;

  before(async () => {
    const artifactsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'artifacts-'));
    fs.writeFileSync(path.join(artifactsDir, 'age_check.wasm'), 'fake wasm');
    fs.writeFileSync(path.join(artifactsDir, 'age_check_final.zkey'), 'fake zkey');
    fs.writeFileSync(path.join(artifactsDir, 'verification_key.json'), '{}');
    fs.writeFileSync(path.join(artifactsDir, 'build-info.json'), '{}');
    const app = createApp({ allowedVerifierOrigins: ['http://localhost:3003'], artifactsDir });
    server = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    url = `http://127.0.0.1:${server.address().port}`;
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it('serves the wallet page with a strict CSP and no COOP header', async () => {
    const res = await fetch(`${url}/`);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /src="\/wallet\.js"/);
    const csp = res.headers.get('content-security-policy');
    assert.match(csp, /script-src 'self' 'wasm-unsafe-eval';/);
    assert.match(csp, /connect-src 'self';/);
    assert.match(csp, /worker-src 'none';/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(res.headers.get('cross-origin-opener-policy'), null);
  });

  it('serves the allowlist from the environment as /config.json', async () => {
    const res = await fetch(`${url}/config.json`);
    assert.deepEqual(await res.json(), { allowedVerifierOrigins: ['http://localhost:3003'] });
  });

  it('serves the wasm as application/wasm and the zkey as binary, same-origin only', async () => {
    const wasm = await fetch(`${url}/artifacts/age_check.wasm`);
    assert.equal(wasm.status, 200);
    assert.equal(wasm.headers.get('content-type'), 'application/wasm');
    assert.equal(wasm.headers.get('access-control-allow-origin'), null);
    assert.equal(await wasm.text(), 'fake wasm');

    const zkey = await fetch(`${url}/artifacts/age_check_final.zkey`);
    assert.equal(zkey.status, 200);
    assert.equal(zkey.headers.get('content-type'), 'application/octet-stream');
  });

  it('does not serve any other file from the artifacts folder', async () => {
    for (const p of ['/artifacts/verification_key.json', '/artifacts/build-info.json', '/artifacts/', '/artifacts/../package.json', '/artifacts/%2e%2e/package.json']) {
      const res = await fetch(`${url}${p}`);
      assert.equal(res.status, 404, p);
    }
  });

  it('serves snarkjs and the shared constants for the page', async () => {
    const snarkjs = await fetch(`${url}/snarkjs.min.js`);
    assert.equal(snarkjs.status, 200);
    assert.match(snarkjs.headers.get('content-type'), /javascript/);
    assert.match(await (await fetch(`${url}/shared/constants.js`)).text(), /PUBLIC_SIGNALS/);
  });

  it('says clearly when the artifacts are missing', async () => {
    const app = createApp({ allowedVerifierOrigins: [], artifactsDir: path.join(os.tmpdir(), 'does-not-exist') });
    const s = await new Promise((resolve) => {
      const x = app.listen(0, '127.0.0.1', () => resolve(x));
    });
    try {
      const res = await fetch(`http://127.0.0.1:${s.address().port}/artifacts/age_check.wasm`);
      assert.equal(res.status, 404);
      assert.match(await res.text(), /not built/);
    } finally {
      s.close();
    }
  });
});

describe('parseAllowlist (ALLOWED_VERIFIER_ORIGINS)', () => {
  it('defaults to the verifier origin and splits on commas', () => {
    assert.deepEqual(parseAllowlist(undefined), ['http://localhost:3003']);
    assert.deepEqual(parseAllowlist('http://localhost:3003, https://example.org'), ['http://localhost:3003', 'https://example.org']);
  });

  it('refuses entries that are not plain origins', () => {
    for (const bad of ['http://localhost:3003/', 'localhost:3003', 'http://localhost:3003/x', '*']) {
      assert.throws(() => parseAllowlist(bad), /plain origin/, bad);
    }
  });
});
