// issuer/src/keygen.js
// One-time key setup: derives the issuer public key from ISSUER_PRIVATE_KEY and writes it to
// shared/generated/issuer-pubkey.json for the verifier. If no key is set, it creates one.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const C = require('../../shared/constants');
const { parsePrivateKey, publicKeyFromPrivate } = require('./credential');

const DEFAULT_OUT = path.join(__dirname, '..', '..', 'shared', 'generated', C.ISSUER_PUBKEY_FILE);

async function main() {
  let hex = process.env.ISSUER_PRIVATE_KEY;
  if (!hex) {
    hex = crypto.randomBytes(32).toString('hex');
    console.log('No ISSUER_PRIVATE_KEY was set, so a new private key was created.');
    console.log('Put this line in your .env file (keep it secret) and start the issuer with it:');
    console.log(`ISSUER_PRIVATE_KEY=${hex}`);
  }

  const pubKey = await publicKeyFromPrivate(parsePrivateKey(hex));
  const outFile = process.env.ISSUER_PUBKEY_PATH || DEFAULT_OUT;
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(pubKey, null, 2) + '\n');
  console.log(`[keygen] wrote issuer public key to ${outFile}`);
}

main().catch((err) => {
  console.error('[keygen] failed:', err.message);
  process.exit(1);
});
