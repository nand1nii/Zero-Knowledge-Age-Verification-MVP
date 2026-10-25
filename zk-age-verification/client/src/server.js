// client/src/server.js
// The ZK wallet's web server (port 3002). It only serves static files and headers: the wallet
// page, shared constants, snarkjs, and the circuit wasm/zkey. All proving happens in the browser.

const path = require('path');
const express = require('express');
const C = require('../../shared/constants');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const SHARED_CONSTANTS = path.join(__dirname, '..', '..', 'shared', 'constants.js');
// snarkjs's prebuilt browser bundle (no bundler needed); the version is pinned in package.json.
const SNARKJS_BROWSER = path.join(__dirname, '..', 'node_modules', 'snarkjs', 'build', 'snarkjs.min.js');

// Only these two files from the artifacts volume are served (never the whole folder).
const ARTIFACT_FILES = [
  { route: '/artifacts/' + C.ARTIFACTS.WASM, file: C.ARTIFACTS.WASM, type: 'application/wasm' },
  { route: '/artifacts/' + C.ARTIFACTS.ZKEY, file: C.ARTIFACTS.ZKEY, type: 'application/octet-stream' },
];

function securityHeaders(req, res, next) {
  // Scripts only from this origin; 'wasm-unsafe-eval' lets snarkjs compile WebAssembly.
  // connect-src 'self' means page scripts cannot send your credential anywhere else.
  // Deliberately NO Cross-Origin-Opener-Policy: it would null window.opener, and the
  // wallet could not postMessage the proof back to the website.
  res.set({
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob: data:; " +
      "connect-src 'self'; worker-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', // the URL holds the challenge; do not leak it
    'Cross-Origin-Resource-Policy': 'same-origin', // other sites cannot embed our files
  });
  next();
}

// "http://localhost:3003,https://example.org" -> ['http://localhost:3003', 'https://example.org']
function parseAllowlist(value) {
  const list = String(value || C.VERIFIER_ORIGIN).split(',').map((s) => s.trim()).filter(Boolean);
  for (const origin of list) {
    let canonical = null;
    try { canonical = new URL(origin).origin; } catch (err) { /* invalid URL */ }
    if (canonical !== origin) {
      throw new Error(`ALLOWED_VERIFIER_ORIGINS: "${origin}" must be a plain origin like http://localhost:3003`);
    }
  }
  return list;
}

function createApp({ allowedVerifierOrigins, artifactsDir }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(securityHeaders);

  // The page reads the allowlist from here (it comes from an env var on the server).
  app.get('/config.json', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ allowedVerifierOrigins });
  });
  app.get('/shared/constants.js', (req, res) => res.sendFile(SHARED_CONSTANTS));
  app.get('/snarkjs.min.js', (req, res) => res.sendFile(SNARKJS_BROWSER));

  // Same-origin downloads, so no CORS headers are needed (or wanted).
  for (const { route, file, type } of ARTIFACT_FILES) {
    app.get(route, (req, res) => {
      res.type(type);
      res.set('Cache-Control', 'no-cache'); // revalidate: a circuit rebuild makes new keys
      res.sendFile(path.join(artifactsDir, file), (err) => {
        if (err && !res.headersSent) res.status(404).type('text').send('Circuit artifacts not built yet.');
      });
    });
  }

  app.use(express.static(PUBLIC_DIR));
  return app;
}

if (require.main === module) {
  const allowedVerifierOrigins = parseAllowlist(process.env.ALLOWED_VERIFIER_ORIGINS);
  const artifactsDir = process.env.ARTIFACTS_DIR || path.join(__dirname, '..', '..', 'artifacts');
  const port = Number(process.env.PORT || C.PORTS.WALLET);
  const host = process.env.HOST || '127.0.0.1';
  createApp({ allowedVerifierOrigins, artifactsDir }).listen(port, host, () => {
    console.log(`[wallet] listening on http://${host}:${port} (open ${C.WALLET_ORIGIN})`);
    console.log(`[wallet] approved verifier origins: ${allowedVerifierOrigins.join(', ')}`);
  });
}

module.exports = { createApp, parseAllowlist };
