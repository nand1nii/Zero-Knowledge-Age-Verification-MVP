# shared/ — the contract between modules

This folder is the **only** code that more than one module may import. Keep it tiny:
constants and the credential format only. No crypto, no Express, no helpers.
If two modules need the same small function, copy it (about 10 lines is fine) rather than
adding it here.

| File | What it is | Who uses it |
|---|---|---|
| `constants.js` | origins and ports, `AGE_THRESHOLD`, **the ordered list of public signals**, challenge size and lifetime, `verifierId` rule, PNG chunk keyword, artifact file names | everyone |
| `credential.schema.json` | JSON Schema of the credential hidden in the ID card PNG | issuer (writes, tests validate against it), wallet (reads) |
| `generated/issuer-pubkey.json` | issuer public key `{ "x": "...", "y": "..." }`, written by `issuer/src/keygen.js` (gitignored) | verifier |

`constants.js` is a small UMD file: `require('../../shared/constants')` in Node, and
`<script src="/shared/constants.js">` in the browser (it sets `window.ZK_CONSTANTS`).
The wallet and verifier servers serve this one file to their pages.

## Rules that must never drift

- **`PUBLIC_SIGNALS` order** must match the circuit's public inputs exactly.
  `circom/test/signal-order.test.js` fails if it doesn't.
- **All big numbers are decimal strings** (`ID_Number`, keys, signature parts, challenge,
  `verifierId`). JavaScript numbers lose precision above 2^53.
- **`AGE_THRESHOLD` is `"180000"`**: "18 years, 0 months, 0 days" in `YYYYMMDD`
  arithmetic, not a number of days.
- **`verifierId`** = the first 31 bytes of `SHA-256(origin)` as a big-endian integer,
  written in decimal. The verifier computes it for its own origin, and the wallet
  recomputes it from `returnOrigin`. Both implement this in about 5 lines each.

## Credential embedding

The issuer stores `base64(JSON.stringify(credential))` in a PNG `tEXt` chunk with keyword
`zkcred`. Base64 is used because `tEXt` only allows Latin-1, which would corrupt names
like "José" or Hindi text.
