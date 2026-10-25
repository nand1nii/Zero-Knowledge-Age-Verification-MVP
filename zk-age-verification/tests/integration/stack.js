// tests/integration/stack.js
// Starts the REAL issuer, wallet and verifier servers as child processes on their normal ports
// (or uses an already running stack, e.g. docker compose, with USE_RUNNING_STACK=1).

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, execFileSync } = require('child_process');
const C = require('../../shared/constants');

const ROOT = path.join(__dirname, '..', '..');
// Test-only issuer key. Never use it for anything else.
const TEST_ISSUER_KEY = '5be1c9c41b7a3bd6a59b2d2a2f7a1d6c0c9e4b1f7d3a2e6c8b9f0a1d2c3e4f50';

const useRunningStack = process.env.USE_RUNNING_STACK === '1';

async function isUp(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(1000) });
    return res.status < 500;
  } catch (err) {
    return false;
  }
}

async function waitUntilUp(url, child, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child && child.exitCode !== null) throw new Error(`${url}: server exited early.\n${child.output}`);
    if (await isUp(url)) return;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`${url} did not start in time.\n${child ? child.output : ''}`);
}

function startServer(script, env) {
  const child = spawn(process.execPath, [path.join(ROOT, script)], {
    env: { ...process.env, HOST: '127.0.0.1', ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.output = '';
  child.stdout.on('data', (d) => { child.output += d; });
  child.stderr.on('data', (d) => { child.output += d; });
  return child;
}

async function stopServer(child) {
  if (child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  await exited;
}

// Returns { issuer, wallet, verifier, startVerifier(port, env), stop() }.
// Node code talks to 127.0.0.1; browsers must use the localhost origins from constants.
async function start() {
  const local = (port) => `http://127.0.0.1:${port}`;
  const urls = { issuer: local(C.PORTS.ISSUER), wallet: local(C.PORTS.WALLET), verifier: local(C.PORTS.VERIFIER) };

  if (useRunningStack) {
    for (const url of Object.values(urls)) await waitUntilUp(url, null, 5000);
    return { ...urls, spawned: false, startVerifier: null, stop: async () => {} };
  }

  for (const url of Object.values(urls)) {
    if (await isUp(url)) {
      throw new Error(`${url} is already in use. Stop it (e.g. docker compose down), or run with USE_RUNNING_STACK=1 to test it.`);
    }
  }

  // Our own issuer key + public key file, so the real shared/generated is left alone.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zk-integration-'));
  const pubKeyPath = path.join(tmp, C.ISSUER_PUBKEY_FILE);
  execFileSync(process.execPath, [path.join(ROOT, 'issuer/src/keygen.js')], {
    env: { ...process.env, ISSUER_PRIVATE_KEY: TEST_ISSUER_KEY, ISSUER_PUBKEY_PATH: pubKeyPath },
  });

  const children = [
    startServer('issuer/src/server.js', { ISSUER_PRIVATE_KEY: TEST_ISSUER_KEY }),
    startServer('client/src/server.js', {}),
    startServer('verifier/src/server.js', { ISSUER_PUBKEY_PATH: pubKeyPath, SESSION_SECRET: 'integration-test' }),
  ];
  await Promise.all(Object.values(urls).map((url, i) => waitUntilUp(url, children[i])));

  return {
    ...urls,
    spawned: true,
    // An extra verifier (e.g. with a short challenge lifetime) on another port.
    async startVerifier(port, env) {
      const child = startServer('verifier/src/server.js', {
        ISSUER_PUBKEY_PATH: pubKeyPath,
        SESSION_SECRET: 'integration-test',
        PORT: String(port),
        ...env,
      });
      children.push(child);
      await waitUntilUp(local(port), child);
      return local(port);
    },
    async stop() {
      await Promise.all(children.map(stopServer));
    },
  };
}

module.exports = { start, useRunningStack };
