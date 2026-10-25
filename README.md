# Zero-Knowledge Age Verification MVP

Prove "I am at least 18" without revealing your birthdate, using Circom 2, Groth16 (snarkjs)
and EdDSA-Poseidon signatures. This repository holds two independent demos:

| Folder | What it is |
|---|---|
| [`zk-age-verification/`](zk-age-verification/README.md) | **The web demo.** A mock government issues an ID card PNG with a hidden signed credential. A website asks "are you 18+?", and a wallet popup proves it in the browser. Four isolated modules (issuer, wallet, circuit, verifier) run with one `docker compose up --build`. |
| [`zk-age-proof/`](zk-age-proof/README.md) | The earlier command-line demo (TypeScript): issuer → prover → verifier scripts with nullifiers. |

```bash
cd zk-age-verification
docker compose up --build      # then open http://localhost:3001
```

> These are proofs of concept for teaching. They are unaudited, their trusted setups are for
> development use, and they must not be used with real identity documents.
