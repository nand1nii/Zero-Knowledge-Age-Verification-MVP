# issuer/ — Module 1: mock government, port 3001 (owner A)

A web form that creates a signed credential and prints it onto an ID card PNG.

1. **Validate** the form: Name (max 60 characters), Date of Birth (a real calendar date,
   not in the future, at most 120 years ago), Address (max 120), Contact Info (optional,
   max 100), Photo (optional; PNG/JPEG only, max 2 MB, max 16 megapixels; decoded and
   re-encoded to a clean 300x380 JPEG with no metadata). Control characters and bidi
   override characters are rejected.
2. Convert the DOB to a `YYYYMMDD` integer string, e.g. `"20080315"`.
3. Generate `ID_Number` = 128 random bits (`crypto.randomBytes(16)`) as a BigInt.
4. Sign `Poseidon([ID_Number, dob])` with EdDSA (`eddsa.signPoseidon`). Every value from
   circomlibjs goes through `F.toObject()` (Montgomery form fix), and the new signature is
   verified before the card is returned.
5. Render the card with Puppeteer (headless Chromium) to a PNG.
6. Embed `base64(JSON)` as a PNG `tEXt` chunk with keyword `zkcred`.
7. Return the PNG as a download (`id_card.png`).

## Files

```
src/server.js       Express app: GET / (form), POST /issue
src/validate.js     form + photo validation
src/credential.js   ID_Number, Poseidon hash, EdDSA signing, signature check
src/render-card.js  card HTML template + locked-down Puppeteer rendering
src/png-embed.js    put the credential into / get it out of the PNG
src/keygen.js       writes the issuer public key to shared/generated/issuer-pubkey.json
public/             the form (index.html, issuer.js, style.css)
test/               node:test suites (see below)
```

## Card renderer safety

A user could type HTML into the Name field. Without protection, Chromium would render it,
and an `<iframe src="file:///etc/passwd">` could read server files into the card image.
There are four independent layers, each with its own test:

1. Every user string is **HTML-escaped** before it goes into the template.
2. **JavaScript is disabled** in the page.
3. **All network requests except `data:` URLs are aborted.** The page itself is loaded
   as a `data:` URL, and the photo is embedded as one.
4. The template has a strict **CSP** (`default-src 'none'; img-src data:; style-src 'unsafe-inline'`).

Each page also gets a fresh, isolated browser context. We checked the tests are meaningful
by removing the escaping or the request blocking or re-enabling JS: the matching test
then fails.

## Run it alone

Needs Node 22.12+. Puppeteer downloads its own Chrome during `npm install`, unless you
already have Chromium and set `CHROMIUM_PATH`.

```bash
cd issuer
npm install
npm run keygen                                      # no key set: creates one and prints it
export ISSUER_PRIVATE_KEY=<the 64 hex chars it printed>
npm run keygen                                      # writes ../shared/generated/issuer-pubkey.json
npm start                                           # http://localhost:3001
npm test                                            # 50 tests, ~15 s, no other module needed
```

If you run as root on Linux (some CI machines), Chromium's sandbox will not start. Then set
`CHROMIUM_NO_SANDBOX=1`. The Docker image does this.

With Docker only: `docker compose run --rm issuer npm test` (from the repo root).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `ISSUER_PRIVATE_KEY` | none (required by the server) | 64 hex chars. The demo value in `.env.example` is **DEMO ONLY, never reuse** |
| `PORT` | `3001` | listen port |
| `HOST` | `127.0.0.1` | listen address (`0.0.0.0` in Docker) |
| `CHROMIUM_PATH` | Puppeteer's own Chrome | path to a Chromium binary (`/usr/bin/chromium` in Docker) |
| `CHROMIUM_NO_SANDBOX` | unset | `1` adds `--no-sandbox` (needed in Docker or as root) |
| `ISSUER_PUBKEY_PATH` | `../shared/generated/issuer-pubkey.json` | where `keygen` writes the public key |

## What the tests check

- `validate.test.js`: 30 Feb / non-leap 29 Feb / month 13 rejected, future rejected, the
  120-year boundary, text limits counted in characters (not bytes), José and Hindi kept,
  control and bidi characters rejected, PNG/JPEG re-encoded, GIF/WebP/SVG/fake PNG/over
  2 MB/decompression bomb rejected.
- `credential.test.js`: the output matches `shared/credential.schema.json`, all big
  numbers are decimal strings, and the signature verifies and breaks if `dob` or
  `ID_Number` changes. The public key is in normal (non-Montgomery) form, and
  `ID_Number` is 128-bit.
- `png-embed.test.js`: the round trip works with non-Latin text, the data is a base64
  `zkcred` chunk before IEND, the PNG is still valid, and only one credential is stored.
- `render-card.test.js`: `<script>`, `<iframe src="file:///etc/passwd">`, `<img onerror>`
  and attribute-breaking input in Name/Address appear as **plain text** in the rendered
  DOM, with no injected elements. JS is off, network requests are blocked (tested against
  a server on this machine), and local files are not readable.
- `server.test.js`: POST /issue returns a PNG. Extracting the credential gives
  schema-valid JSON with a valid signature. Bad dates, names and photos get a 400.
- `keygen.test.js`: the written public key matches the private key, and a key is created
  when none is set.

## Interfaces with other modules

- **Produces:** `id_card.png` (format: `shared/credential.schema.json`). The user carries
  it to the wallet.
- **Produces:** `shared/generated/issuer-pubkey.json` (via `keygen`), read by the verifier.
- **Imports:** only `../shared/constants.js` (and the schema in tests).

Note: only `ID_Number` and `dob` are signed. Name, address, contact and the photo are
unsigned display data, and the circuit ignores them.
