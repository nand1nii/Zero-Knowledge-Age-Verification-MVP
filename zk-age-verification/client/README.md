# client/ — Module 2: the ZK wallet, port 3002 (owner B)

A popup that a website opens. The user drops in their ID card PNG, and the wallet makes
the zero-knowledge proof **in the browser** and sends back only the proof. Private data
never leaves the user's machine. The server in `src/server.js` only serves static files and
security headers; it never sees the card.

## Flow

1. The verifier opens `http://localhost:3002/?challenge=…&currentDate=…&ageThreshold=…&issuerPubKeyX=…&issuerPubKeyY=…&verifierId=…&returnOrigin=…`.
   All of these values are public.
2. **The request is checked before anything is shown.** If any check fails, the wallet
   shows "Request refused" and stops.
   - Every value is a plain decimal string, and `currentDate` is `YYYYMMDD`.
   - `returnOrigin` must **exactly** match an entry in `ALLOWED_VERIFIER_ORIGINS`.
   - The page must have been opened by a website (`window.opener`).
   - `verifierId` must equal `SHA-256(returnOrigin)` truncated to 31 bytes (*addition, see
     below*).
   - The threshold must be a whole number of years, and `currentDate` must be today ±1 day
     by this computer's clock (*addition, see below*).
3. The user drops the PNG. `png-parse.js` (about 30 lines) finds the `zkcred` tEXt chunk,
   base64-decodes it and parses the JSON.
4. **Sanity checks:** the credential has the expected shape; its `issuerPubKey` equals
   the requested `issuerPubKeyX/Y` ("This ID is from a different issuer…"); and it meets
   the age rule (a clear message instead of a cryptic proving error).
5. **Consent screen:** "`http://localhost:3003` wants proof that you are at least 18. Your
   birthdate will NOT be shared." with Approve / Cancel, plus an optional "Remember my
   card" checkbox (*Demo only, stored unencrypted*).
6. `snarkjs.groth16.fullProve()` runs in the page, using `/artifacts/age_check.wasm` and
   `/artifacts/age_check_final.zkey`. It shows a spinner and a timer, takes about 2 s, and
   times out after 60 s.
7. `window.opener.postMessage({ proof, publicSignals }, returnOrigin)`, **never `"*"`**.
   The browser only delivers it if the opener is still on `returnOrigin`.

## Additions beyond the spec (please review)

- **`verifierId` is bound to `returnOrigin`.** Without this, one approved site could open
  the wallet with *another* site's challenge and `verifierId`. The consent screen would
  name the first site, but the proof would work at the second site (a relay attack). The
  spec suggested "for example a Poseidon hash" for `verifierId`. We use truncated SHA-256
  instead, because the wallet can compute it with the browser's built-in WebCrypto.
  Poseidon in the browser would need circomlibjs plus a bundler.
- **Privacy sanity checks.** A site could ask odd questions such as "at least 18 years and
  3 days on 2031-02-14" to narrow down your birthday. So the wallet only accepts
  whole-year thresholds (1 to 120 years) and a `currentDate` within one day of the user's
  own clock.

## Security headers

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
  img-src 'self' blob: data:; connect-src 'self'; worker-src 'none'; object-src 'none';
  base-uri 'none'; frame-ancestors 'none'; form-action 'none'
Referrer-Policy: no-referrer          (the URL contains the challenge)
X-Content-Type-Options: nosniff
Cross-Origin-Resource-Policy: same-origin
```

- `connect-src 'self'`: even injected script could not upload the credential to another server.
- **snarkjs runs single-threaded** (`{ singleThread: true }`). Its multi-threaded mode
  creates `blob:` Web Workers, which this CSP blocks; we tested that it then hangs. The
  single-threaded proof takes about 2 s, so we kept the strict policy instead of
  allowing `worker-src blob:`.
- **No `Cross-Origin-Opener-Policy`** on purpose: `same-origin` would set `window.opener`
  to null, and the proof could not be sent back.
- The `.wasm` is served as `application/wasm` and the `.zkey` as
  `application/octet-stream`. Both are same-origin downloads, so **no CORS headers** are
  needed, and none are sent. Only these two files are served from the artifacts folder.
- snarkjs is the prebuilt browser file `node_modules/snarkjs/build/snarkjs.min.js`
  (pinned 0.7.6), served from this origin at `/snarkjs.min.js`. No bundler and no CDN.

## Files

```
src/server.js          static files + headers + /config.json + the two artifact routes
public/index.html      the popup UI (no inline scripts)
public/wallet.js       DOM glue: steps, drag & drop, consent, proving, postMessage
public/wallet-core.js  all decisions, no DOM (unit-tested in Node)
public/png-parse.js    PNG chunk reader (unit-tested in Node)
public/style.css
```

`png-parse.js` and `wallet-core.js` are small UMD scripts. In the browser they set
`window.PngParse` / `window.WalletCore`, and Node tests `require()` them.

## Run it alone

```bash
cd client
npm install
npm start      # http://localhost:3002 (needs ../artifacts for real proofs)
npm test       # 49 tests, ~1 s, no other module needed (artifacts are faked)
```

Opening `http://localhost:3002` directly shows "Request refused", because it needs to be
opened by a verifier.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `ALLOWED_VERIFIER_ORIGINS` | `http://localhost:3003` | comma-separated list of exact origins the wallet will answer |
| `ARTIFACTS_DIR` | `../artifacts` | folder with `age_check.wasm` and `age_check_final.zkey` (read-only volume in Docker) |
| `PORT` / `HOST` | `3002` / `127.0.0.1` | listen address (`0.0.0.0` in Docker) |

## Interfaces with other modules

- **Reads** the ID card PNG (format: `shared/credential.schema.json`), dropped in by the user.
- **Reads** `age_check.wasm` + `age_check_final.zkey` from the circuit builder's volume.
- **Receives** the public request from the verifier as URL parameters.
- **Sends** `{ proof, publicSignals }` to the verifier window via `postMessage`, with the
  exact target origin.
- **Imports** only `../shared/constants.js` (also served to the page at `/shared/constants.js`).

## What the tests check

- `wallet-core.test.js`: the allowlist is exact-match only. Refused: trailing slash, extra
  port digit, `localhost:3003.evil.example`, `user@host`, upper case, https, `127.0.0.1`,
  `javascript:`, `null`, `*`. Also covered: request parsing, `verifierId` matches an
  independent Node implementation, the threshold/date privacy checks, credential shape,
  wrong issuer, the age boundary, and that the circuit input has exactly the circuit's
  signals.
- `png-parse.test.js`: checked against PNGs built with an independent library. Unicode
  survives; other or look-alike chunks are ignored; non-PNG, truncated and bad-base64
  files are rejected.
- `server.test.js`: CSP (including `worker-src 'none'`, no COOP), allowlist config,
  wasm/zkey MIME types without CORS headers, no other artifact files (including path
  traversal), and a clear 404 when artifacts are missing.

The browser flow (popup, consent, proof, postMessage, refusals) is tested in
`../tests/integration/browser.test.js`.
