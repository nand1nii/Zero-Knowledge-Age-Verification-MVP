// verifier/src/server.js
// Age-locked website on port 3003. POST /challenge starts a verification, POST /verify checks
// the proof in a fixed order, and /success shows the hidden content to verified sessions only.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { rateLimit } = require('express-rate-limit');
const snarkjs = require('snarkjs');
const C = require('../../shared/constants');
const { sessionMiddleware, issueChallenge, consumeChallenge } = require('./session');
const { verifierIdForOrigin, todayYYYYMMDD, verifySubmission, isDecimal } = require('./verify');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
// The success page lives OUTSIDE public/: express.static would serve anything in public/
// to anyone, so this page is only sent by the /success route after the session check.
const SUCCESS_PAGE = path.join(__dirname, '..', 'protected', 'success.html');
const SHARED_CONSTANTS = path.join(__dirname, '..', '..', 'shared', 'constants.js');

function securityHeaders(req, res, next) {
  // Deliberately NO Cross-Origin-Opener-Policy: "same-origin" would cut this page's link
  // to the wallet popup, and the wallet could no longer postMessage the proof back.
  res.set({
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
      "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  next();
}

function limiter(perMinute) {
  return rateLimit({
    windowMs: 60 * 1000,
    limit: perMinute,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, error: 'Too many requests. Please wait a minute.' },
  });
}

// Remembers challenge values that were already used, until they expire. Two requests that
// share one session could otherwise both read the challenge before either saves the session.
function createUsedChallenges() {
  const used = new Map(); // challenge value -> expiresAt
  return {
    // Returns false if the value was already used. Synchronous, so no request can slip in between.
    markUsed(value, expiresAt, nowMs) {
      for (const [v, exp] of used) if (exp < nowMs) used.delete(v);
      if (used.has(value)) return false;
      used.set(value, expiresAt);
      return true;
    },
  };
}

// options: vkey, issuerPubKey {x, y}, sessionSecret, and for tests: origin, challengeTtlMs,
// rateLimitPerMinute, clock (returns a Date), groth16Verify (fake verifier).
function createApp(options) {
  const {
    vkey,
    issuerPubKey,
    sessionSecret,
    origin = C.VERIFIER_ORIGIN,
    challengeTtlMs = C.CHALLENGE_TTL_MS,
    rateLimitPerMinute = 30,
    clock = () => new Date(),
    groth16Verify = snarkjs.groth16.verify,
  } = options;
  const verifierId = verifierIdForOrigin(origin);
  const usedChallenges = createUsedChallenges();

  const app = express();
  app.disable('x-powered-by');
  app.use(securityHeaders);
  app.use(sessionMiddleware(sessionSecret));
  app.use(express.static(PUBLIC_DIR));
  app.get('/shared/constants.js', (req, res) => res.sendFile(SHARED_CONSTANTS));

  // Start of a verification: a fresh single-use challenge plus all public parameters.
  app.post('/challenge', limiter(rateLimitPerMinute), (req, res) => {
    const now = clock();
    const challenge = issueChallenge(req.session, {
      nowMs: now.getTime(),
      ttlMs: challengeTtlMs,
      currentDate: todayYYYYMMDD(now),
    });
    res.set('Cache-Control', 'no-store');
    res.json({
      challenge: challenge.value,
      currentDate: challenge.currentDate,
      ageThreshold: C.AGE_THRESHOLD,
      issuerPubKeyX: issuerPubKey.x,
      issuerPubKeyY: issuerPubKey.y,
      verifierId,
      returnOrigin: origin,
    });
  });

  app.post('/verify', limiter(rateLimitPerMinute), express.json({ limit: '16kb' }), async (req, res, next) => {
    try {
      // Steps 1 + 2: a fresh challenge must exist, and it is consumed right now.
      const nowMs = clock().getTime();
      const { challenge, error } = consumeChallenge(req.session, nowMs);
      if (error) return res.status(400).json({ ok: false, error });
      if (!usedChallenges.markUsed(challenge.value, challenge.expiresAt, nowMs)) {
        return res.status(400).json({ ok: false, error: 'This challenge was already used.' });
      }

      // Steps 3-5: every public signal must equal OUR value, then the proof must verify.
      const expected = {
        challenge: challenge.value,
        currentDate: challenge.currentDate, // the date we handed out with this challenge
        issuerPubKeyX: issuerPubKey.x,
        issuerPubKeyY: issuerPubKey.y,
        ageThreshold: C.AGE_THRESHOLD, // without this check a client could prove "age >= 0"
        verifierId,
      };
      const result = await verifySubmission(req.body, expected, { vkey, groth16Verify });
      if (!result.ok) return res.status(400).json({ ok: false, error: `Verification failed: ${result.reason}.` });

      // Step 6: success. Switch to a new session id (stops session fixation) and mark it verified.
      req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.verified = true;
        res.json({ ok: true, redirect: '/success' });
      });
    } catch (err) {
      next(err);
    }
  });

  // The hidden content: only for sessions that passed /verify.
  app.get('/success', (req, res) => {
    if (req.session.verified !== true) return res.redirect(303, '/?error=not-verified');
    res.set('Cache-Control', 'no-store');
    res.sendFile(SUCCESS_PAGE);
  });

  app.post('/logout', (req, res, next) => {
    req.session.destroy((err) => {
      if (err) return next(err);
      res.clearCookie('zkverifier.sid');
      res.json({ ok: true });
    });
  });

  // Bad JSON / too large -> 4xx with a short message. Anything else -> 500, details only in the log.
  app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    if (err.status >= 400 && err.status < 500) return res.status(err.status).json({ ok: false, error: 'Bad request.' });
    console.error('[verifier] error:', err);
    res.status(500).json({ ok: false, error: 'Server error.' });
  });

  return app;
}

function readJson(file, hint) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    console.error(`[verifier] cannot read ${file}: ${err.message}\n           ${hint}`);
    process.exit(1);
  }
}

if (require.main === module) {
  const artifactsDir = process.env.ARTIFACTS_DIR || path.join(__dirname, '..', '..', 'artifacts');
  const vkey = readJson(path.join(artifactsDir, C.ARTIFACTS.VKEY), 'Build the circuit first (circom module).');
  if (vkey.nPublic !== C.NUM_PUBLIC_SIGNALS) {
    console.error(`[verifier] verification key has ${vkey.nPublic} public signals, expected ${C.NUM_PUBLIC_SIGNALS}`);
    process.exit(1);
  }

  const pubKeyFile =
    process.env.ISSUER_PUBKEY_PATH || path.join(__dirname, '..', '..', 'shared', 'generated', C.ISSUER_PUBKEY_FILE);
  const issuerPubKey = readJson(pubKeyFile, 'Run the issuer keygen first (issuer module).');
  if (!isDecimal(issuerPubKey.x) || !isDecimal(issuerPubKey.y)) {
    console.error(`[verifier] ${pubKeyFile} must contain { "x": "<decimal>", "y": "<decimal>" }`);
    process.exit(1);
  }

  let sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    sessionSecret = crypto.randomBytes(32).toString('hex');
    console.warn('[verifier] SESSION_SECRET not set: using a random secret (sessions reset on restart).');
  }

  const challengeTtlMs = process.env.CHALLENGE_TTL_MS ? Number(process.env.CHALLENGE_TTL_MS) : C.CHALLENGE_TTL_MS;
  if (!Number.isInteger(challengeTtlMs) || challengeTtlMs <= 0) {
    console.error('[verifier] CHALLENGE_TTL_MS must be a positive whole number of milliseconds');
    process.exit(1);
  }

  const port = Number(process.env.PORT || C.PORTS.VERIFIER);
  const host = process.env.HOST || '127.0.0.1';
  createApp({ vkey, issuerPubKey, sessionSecret, challengeTtlMs }).listen(port, host, () => {
    console.log(`[verifier] listening on http://${host}:${port} (open ${C.VERIFIER_ORIGIN})`);
  });
}

module.exports = { createApp };
