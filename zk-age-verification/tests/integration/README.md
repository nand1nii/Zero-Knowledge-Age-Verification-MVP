# tests/integration/ — end-to-end tests across modules

The only place where tests may use more than one module. They start the **real**
issuer, wallet and verifier servers as child processes on their normal ports
(3001-3003) and use real circuit artifacts and real Groth16 proofs.

| File | What it checks |
|---|---|
| `e2e.test.js` | No browser. A card from the real issuer is read with the wallet's own `png-parse.js` / `wallet-core.js`, proven with snarkjs using the wasm/zkey **downloaded from the wallet server**, and accepted by the real verifier (`/success` unlocks). Also: the proof contains nothing from the card. Replay fails. An old proof fails under a new challenge. An **expired challenge** fails (a second verifier with a 1.5 s lifetime). An underage card cannot prove, and "threshold 0" is refused. A proof for another site (`verifierId`) is refused, and so is another session's proof. |
| `browser.test.js` | Headless Chromium via Puppeteer. Fill in the issuer form and download `id_card.png`; click "Verify Age with ZK"; upload the card into the wallet popup; check the consent text; approve; land on `/success`. Also: "Remember my card" / "Forget"; an underage card and a screenshot are refused. The wallet refuses a **returnOrigin not on its allowlist**, a `verifierId` for another site, and being opened without a website. The verifier page ignores proofs posted from other origins. No page logs an error or a CSP violation. |

## Before you run them

1. Build the circuit: `cd ../../circom && npm install && npm run build` (writes `../artifacts`).
2. `npm install` in `issuer/`, `client/`, `verifier/` and here.
3. Chromium: Puppeteer downloads one on `npm install`. Or set `CHROMIUM_PATH` to an
   existing Chromium. As root on Linux, also set `CHROMIUM_NO_SANDBOX=1`.
4. Ports 3001-3003 must be free (stop `docker compose` first), plus 3013 for the
   short-lived verifier.

```bash
npm test               # both files, one after the other (~30 s)
npm run test:node      # e2e.test.js only
npm run test:browser   # browser.test.js only
```

The tests use their own throwaway issuer key and a temporary public-key file. They
never touch `shared/generated/`.

## Testing the Docker stack instead

With `docker compose up` running, run the same tests against it:

```bash
USE_RUNNING_STACK=1 npm test
```

Only the expiry test is skipped then, because it needs a verifier with a short challenge
lifetime.
