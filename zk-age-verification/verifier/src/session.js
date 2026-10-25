// verifier/src/session.js
// Session cookie settings, and the challenge lifecycle: each challenge is random, stored
// in the server session, expires after 2 minutes and can be used only once.

const crypto = require('crypto');
const session = require('express-session');
const C = require('../../shared/constants');

function sessionMiddleware(secret) {
  return session({
    name: 'zkverifier.sid',
    secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // page scripts cannot read the cookie
      sameSite: 'lax', // not sent on cross-site POSTs
      secure: false, // localhost demo without HTTPS (see README limitations)
      maxAge: 30 * 60 * 1000,
    },
  });
}

// 31 random bytes, always smaller than the circuit's field size. Kept as a decimal string.
function newChallengeValue() {
  return BigInt('0x' + crypto.randomBytes(C.CHALLENGE_BYTES).toString('hex')).toString();
}

// Stores a new challenge in the session (replacing any older one) and returns it.
// currentDate is remembered too, so the proof is checked against the date we handed out.
function issueChallenge(sess, { nowMs, ttlMs, currentDate }) {
  const challenge = { value: newChallengeValue(), currentDate, expiresAt: nowMs + ttlMs };
  sess.challenge = challenge;
  return challenge;
}

// Takes the challenge OUT of the session (single use, even if later checks fail).
// Returns { challenge } or { error }.
function consumeChallenge(sess, nowMs) {
  const challenge = sess.challenge;
  delete sess.challenge;
  if (!challenge) return { error: 'No active challenge. Please start the verification again.' };
  if (nowMs > challenge.expiresAt) return { error: 'The challenge expired. Please start the verification again.' };
  return { challenge };
}

module.exports = { sessionMiddleware, newChallengeValue, issueChallenge, consumeChallenge };
