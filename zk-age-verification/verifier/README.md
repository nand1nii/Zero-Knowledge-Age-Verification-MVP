# verifier/ — Module 4: the age-locked website, port 3003 (owner D)

A website that asks for proof of age, checks it carefully, and only then shows the hidden
content.

## Server logic

**`POST /challenge`** (rate limited) creates `crypto.randomBytes(31)` as a decimal
string. It stores it in the session with a **2-minute expiry**, replacing any older one,
and returns the public parameters:

```json
{ "challenge": "…", "currentDate": "20261025", "ageThreshold": "180000",
  "issuerPubKeyX": "…", "issuerPubKeyY": "…", "verifierId": "…", "returnOrigin": "http://localhost:3003" }
```

`currentDate` comes from the server clock (UTC). `issuerPubKeyX/Y` come from
`shared/generated/issuer-pubkey.json`. `verifierId` is the first 31 bytes of
`SHA-256("http://localhost:3003")` (rule in `shared/constants.js`).

**`POST /verify`** with `{ proof, publicSignals }` (rate limited, JSON only, max 16 kB).
It rejects on the first failure, in this order:

1. A challenge exists in the session and has not expired.
2. It is **consumed immediately** (deleted from the session), even if later steps fail.
   It is also recorded in an in-memory "used" list until it expires. Two parallel
   requests from one session could otherwise both read it before either saves the
   session. A test shows this race is real without the list.
3. `publicSignals` is an array of **exactly 6** values. (This is checked first so indexing
   is safe. snarkjs does not check the count itself.)
4. **Every** public signal equals the server's own value, compared as canonical decimal
   strings, never JS Numbers: `challenge`, `currentDate`, `issuerPubKeyX`,
   `issuerPubKeyY`, `ageThreshold == "180000"` (without this a client could prove
   "age >= 0"), and `verifierId`.
5. The proof has the Groth16 shape, and `snarkjs.groth16.verify(vkey, publicSignals, proof)`
   returns true.
6. Success: `req.session.regenerate()` (a new session id, which prevents session
   fixation), then `verified = true`.

**`GET /success`** sends the hidden page only if `session.verified === true`; otherwise it
redirects to `/`. **`POST /logout`** ("Start over") destroys the session.

### Small deviations from the spec (please review)

- **`currentDate` is compared with the date the server issued with the challenge**, not
  the date at verify time. Otherwise a challenge fetched at 23:59:30 would fail at
  00:00:30. The issued date is at most 2 minutes old and never later than today, so this
  can only make the check stricter.
- **The success page is in `protected/`, not `public/`.** `express.static` serves
  everything in `public/` to anyone, so `success.html` there could be fetched without
  verifying. (A blocklist route would be bypassable, e.g. with `/%73uccess.html`.) The
  tests try those paths.
- `SESSION_SECRET` is optional: if it is unset, a random secret is generated at start
  (sessions then reset on restart). This is safer than a fixed default.

## Browser side (`public/landing.js`)

The "Verify Age with ZK" click opens the popup **immediately**, so pop-up blockers allow
it. It then fetches `/challenge` and points the popup at the wallet URL. The
`message` listener **only accepts `event.origin === "http://localhost:3002"`** *and*
`event.source === popup`; everything else is ignored. It then POSTs the proof to
`/verify` and goes to `/success`.

## Security settings

- `express-session`: cookie `zkverifier.sid`, `httpOnly`, `sameSite: "lax"`, secret from
  `SESSION_SECRET`.
- `express-rate-limit`: 30 requests/minute per client on `/challenge` and on `/verify`.
- CSP `default-src 'self'; script-src 'self'; …; frame-ancestors 'none'`, `nosniff`,
  `no-referrer`.
- **No `Cross-Origin-Opener-Policy`**: `same-origin` would break the link to the wallet
  popup.

## Files

```
src/server.js          routes, headers, rate limits, startup checks
src/session.js         cookie settings, challenge issue / consume / expiry
src/verify.js          verifierId, date, public-signal comparison, proof shape, groth16 call
public/                landing page (index.html, landing.js), success.js, style.css
protected/success.html the age-locked content (only sent by GET /success)
test/                  node:test suites with a fake groth16 verifier
```

## Run it alone

```bash
cd verifier
npm install
npm test     # 50 tests, ~2 s: no artifacts, no issuer, no wallet needed (groth16 is faked)
npm start    # needs ../artifacts/verification_key.json and ../shared/generated/issuer-pubkey.json
```

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `SESSION_SECRET` | random at start | signs the session cookie |
| `ARTIFACTS_DIR` | `../artifacts` | where `verification_key.json` is (read-only volume in Docker) |
| `ISSUER_PUBKEY_PATH` | `../shared/generated/issuer-pubkey.json` | the trusted issuer key |
| `CHALLENGE_TTL_MS` | `120000` (2 min) | challenge lifetime; only changed by the integration test |
| `PORT` / `HOST` | `3003` / `127.0.0.1` | listen address (`0.0.0.0` in Docker) |

## What the tests check

- `verify.test.js`: `verifierId` rule, UTC date, every signal mismatch, `ageThreshold = 0`,
  exact count, and rejection of numbers and other spellings (`180000` as a number,
  `0180000`, `0x2bf20`, `1.8e5`, …). Also proof shape, and that groth16 is never called
  when a signal is wrong.
- `session.test.js`: challenges are random, below 2^248, single use, expire, and a newer
  one replaces an older one.
- `server.test.js`: challenge contents and cookie flags. Honest proof → `/success`
  unlocked and session id rotated. Rejected: no challenge, replay, an old proof under a
  new challenge, a consumed-on-failure challenge, expired (2 min + 1 ms), each wrong
  signal, the wrong count, and a bad proof. Also: the midnight case, two parallel
  submissions (only one wins), another browser's challenge, bad JSON / 413, `/success`
  unreachable (including `/success.html` and `/%73uccess.html`), logout, and rate
  limiting (429).

Real proofs from the real issuer and wallet are tested in `../tests/integration/`.

## Interfaces with other modules

- **Reads** `verification_key.json` (circuit builder volume) and
  `shared/generated/issuer-pubkey.json` (issuer keygen).
- **Sends** the public request to the wallet as popup URL parameters.
- **Receives** `{ proof, publicSignals }` from the wallet via `postMessage`.
- **Imports** only `../shared/constants.js` (also served to the page at `/shared/constants.js`).
