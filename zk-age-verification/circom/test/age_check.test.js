// circom/test/age_check.test.js
// Runs the REAL compiled circuit and keys: a valid adult credential must prove and verify;
// underage, future, tampered, forged, wrong-issuer and wraparound inputs must be rejected.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const C = require('../../shared/constants');
const h = require('./helpers');

// circom's witness generator throws this when any constraint is not satisfied,
// so no proof can be produced at all.
const NO_PROOF = /Assert Failed/;

describe('age_check circuit', () => {
  let issuer;
  let otherIssuer;
  let adult; // born 2000-01-15, 26 years old on 2026-10-25

  before(async () => {
    issuer = await h.makeIssuer();
    otherIssuer = await h.makeIssuer();
    adult = h.makeCredential(issuer, '20000115');
  });

  after(h.terminateCurve);

  describe('valid credentials', () => {
    it('an adult credential proves and verifies, with public signals in constants order', async () => {
      const request = h.makeRequest(issuer);
      const { proof, publicSignals } = await h.prove(h.circuitInput(adult, request));

      assert.equal(await h.verifyProof(publicSignals, proof), true);
      assert.deepEqual(publicSignals, C.PUBLIC_SIGNALS.map((name) => request[name]));
      assert.equal(h.serverSideCheck(publicSignals, request), null);
    });

    it('the proof reveals nothing unique to the user (unlinkability)', async () => {
      const request = h.makeRequest(issuer);
      const { proof, publicSignals } = await h.prove(h.circuitInput(adult, request));
      const hash = await h.messageHash(adult.ID_Number, adult.dob);
      const secrets = [adult.dob, adult.ID_Number, hash, ...Object.values(adult.signature)];

      for (const secret of secrets) {
        assert.equal(publicSignals.includes(secret), false, `public signals contain ${secret}`);
      }
      const proofJson = JSON.stringify(proof);
      for (const secret of [adult.ID_Number, hash, ...Object.values(adult.signature)]) {
        assert.equal(proofJson.includes(secret), false, `proof contains ${secret}`);
      }
    });

    it('turning 18 today passes: 20261025 - 20081025 = 180000', async () => {
      const cred = h.makeCredential(issuer, '20081025');
      const request = h.makeRequest(issuer);
      const { proof, publicSignals } = await h.prove(h.circuitInput(cred, request));
      assert.equal(await h.verifyProof(publicSignals, proof), true);
    });
  });

  describe('age and date checks', () => {
    it('rejects someone who turns 18 tomorrow: 20261025 - 20081026 = 179999', async () => {
      const cred = h.makeCredential(issuer, '20081026');
      await assert.rejects(h.prove(h.circuitInput(cred, h.makeRequest(issuer))), NO_PROOF);
    });

    it('rejects a clearly underage credential', async () => {
      const cred = h.makeCredential(issuer, '20150601');
      await assert.rejects(h.prove(h.circuitInput(cred, h.makeRequest(issuer))), NO_PROOF);
    });

    it('rejects a date of birth in the future', async () => {
      const cred = h.makeCredential(issuer, '20270101');
      await assert.rejects(h.prove(h.circuitInput(cred, h.makeRequest(issuer))), NO_PROOF);
    });
  });

  describe('range checks stop the "negative age" wraparound trick', () => {
    // Even if the issuer signed a huge "dob", (currentDate - dob) mod p must not
    // become a giant number that passes ">=".
    it('rejects a huge field-element dob (p - 1, i.e. "-1"), even with a valid signature', async () => {
      const cred = h.makeCredential(issuer, (h.FIELD_P - 1n).toString());
      await assert.rejects(h.prove(h.circuitInput(cred, h.makeRequest(issuer))), NO_PROOF);
    });

    it('rejects dob = p - 180000 ("-180000"), which would wrap to a small passing difference', async () => {
      // Without range checks: currentDate - dob = 20261025 + 180000 (mod p) = 20441025,
      // a small number that is >= 180000, so GreaterEqThan alone would accept it.
      // (Note: values >= p are NOT an attack, they are just the same field element.)
      const dob = (h.FIELD_P - 180000n).toString();
      const cred = h.makeCredential(issuer, dob);
      await assert.rejects(h.prove(h.circuitInput(cred, h.makeRequest(issuer))), NO_PROOF);
    });

    it('rejects a negative ageThreshold (p - 1)', async () => {
      const minor = h.makeCredential(issuer, '20150601');
      const request = h.makeRequest(issuer, { ageThreshold: (h.FIELD_P - 1n).toString() });
      await assert.rejects(h.prove(h.circuitInput(minor, request)), NO_PROOF);
    });

    it('rejects a currentDate that does not fit in 32 bits', async () => {
      const request = h.makeRequest(issuer, { currentDate: (2n ** 32n + 20261025n).toString() });
      await assert.rejects(h.prove(h.circuitInput(adult, request)), NO_PROOF);
    });
  });

  describe('signature checks', () => {
    it('rejects a tampered signature (S changed by 1)', async () => {
      const cred = { ...adult, signature: { ...adult.signature, S: (BigInt(adult.signature.S) + 1n).toString() } };
      await assert.rejects(h.prove(h.circuitInput(cred, h.makeRequest(issuer))), NO_PROOF);
    });

    it('rejects a tampered R8 point', async () => {
      const cred = { ...adult, signature: { ...adult.signature, R8x: adult.signature.R8y } };
      await assert.rejects(h.prove(h.circuitInput(cred, h.makeRequest(issuer))), NO_PROOF);
    });

    it('rejects a minor who edits their dob (the signature no longer matches)', async () => {
      const minor = h.makeCredential(issuer, '20150601');
      const edited = { ...minor, dob: '20000101' };
      await assert.rejects(h.prove(h.circuitInput(edited, h.makeRequest(issuer))), NO_PROOF);
    });

    it('rejects a changed ID_Number (the signature no longer matches)', async () => {
      const edited = { ...adult, ID_Number: (BigInt(adult.ID_Number) + 1n).toString() };
      await assert.rejects(h.prove(h.circuitInput(edited, h.makeRequest(issuer))), NO_PROOF);
    });

    it('enabled-flag sanity: a completely forged signature cannot produce a proof', async () => {
      // If EdDSAPoseidonVerifier.enabled were 0, this would PASS. It must fail.
      const forged = {
        dob: '19900101',
        ID_Number: '42',
        signature: { R8x: '1', R8y: '2', S: '3' },
      };
      await assert.rejects(h.prove(h.circuitInput(forged, h.makeRequest(issuer))), NO_PROOF);
      assert.match(require('fs').readFileSync(h.PATHS.circuit, 'utf8'), /sigCheck\.enabled\s*<==\s*1\s*;/);
    });

    it('wrong issuer key: a credential from another issuer fails against the trusted key', async () => {
      const foreign = h.makeCredential(otherIssuer, '20000115');
      await assert.rejects(h.prove(h.circuitInput(foreign, h.makeRequest(issuer))), NO_PROOF);
    });

    it('wrong issuer key: a self-made issuer proves fine, but the server-side compare rejects it', async () => {
      const selfIssued = h.makeCredential(otherIssuer, '20000115');
      const expected = h.makeRequest(issuer);
      const attackerRequest = { ...expected, issuerPubKeyX: otherIssuer.pubKey.x, issuerPubKeyY: otherIssuer.pubKey.y };
      const { proof, publicSignals } = await h.prove(h.circuitInput(selfIssued, attackerRequest));

      assert.equal(await h.verifyProof(publicSignals, proof), true); // math is fine...
      assert.equal(h.serverSideCheck(publicSignals, expected), 'issuerPubKeyX'); // ...policy is not
    });
  });

  describe('public inputs are bound to the proof', () => {
    let minorProof; // a minor proving with ageThreshold = 0

    it('a modified ageThreshold (0) proves, but the server-side compare rejects it', async () => {
      const minor = h.makeCredential(issuer, '20150601');
      const expected = h.makeRequest(issuer);
      minorProof = await h.prove(h.circuitInput(minor, { ...expected, ageThreshold: '0' }));

      assert.equal(await h.verifyProof(minorProof.publicSignals, minorProof.proof), true);
      assert.equal(h.serverSideCheck(minorProof.publicSignals, expected), 'ageThreshold');
    });

    it('editing ageThreshold in publicSignals after proving breaks verification', async () => {
      const edited = [...minorProof.publicSignals];
      edited[C.PUBLIC_SIGNALS.indexOf('ageThreshold')] = C.AGE_THRESHOLD;
      assert.equal(await h.verifyProof(edited, minorProof.proof), false);
    });

    it('a wrong challenge or verifierId is caught by the server-side compare', async () => {
      const request = h.makeRequest(issuer);
      const { publicSignals } = await h.prove(h.circuitInput(adult, request));

      const otherChallenge = { ...request, challenge: h.makeRequest(issuer).challenge };
      assert.equal(h.serverSideCheck(publicSignals, otherChallenge), 'challenge');

      const otherSite = { ...request, verifierId: h.makeRequest(issuer).verifierId };
      assert.equal(h.serverSideCheck(publicSignals, otherSite), 'verifierId');
    });

    it('editing any public signal after proving breaks verification', async () => {
      const request = h.makeRequest(issuer);
      const { proof, publicSignals } = await h.prove(h.circuitInput(adult, request));

      for (let i = 0; i < publicSignals.length; i++) {
        const edited = [...publicSignals];
        edited[i] = (BigInt(edited[i]) + 1n).toString();
        assert.equal(await h.verifyProof(edited, proof), false, `editing ${C.PUBLIC_SIGNALS[i]} still verified`);
      }
    });
  });
});
