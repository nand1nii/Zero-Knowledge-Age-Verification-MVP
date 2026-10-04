# Zero-Knowledge Age Verification MVP

A command-line demo of zero-knowledge age verification. It proves "I am at least 18"
without revealing the birthdate. It uses Circom 2, Groth16 via snarkjs, EdDSA-Poseidon
signatures from circomlib, and TypeScript.

The code, setup instructions and security caveats are in
[`zk-age-proof/`](zk-age-proof/README.md).

```bash
cd zk-age-proof
npm install && npm run setup && npm run demo && npm test
```

> Proof of concept only. It is unaudited, and its trusted setup is for development use.
> Do not use it with real identity documents.
