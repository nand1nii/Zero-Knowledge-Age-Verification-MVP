// client/public/wallet-core.js
// The wallet's decision logic, with no DOM: read the request, check the origin allowlist and
// verifierId, sanity-check the credential, and build the circuit input. Browser + Node tests.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('../../shared/constants'));
  else root.WalletCore = factory(root.ZK_CONSTANTS);
})(typeof self !== 'undefined' ? self : this, function (C) {
  'use strict';

  // An error whose message is meant for the user.
  class WalletError extends Error {}

  const DECIMAL = /^(0|[1-9][0-9]{0,77})$/;
  const isDecimal = (v) => typeof v === 'string' && DECIMAL.test(v);

  // "http://localhost:3003" stays the same; anything with a path, a trailing slash,
  // upper case or a non-http(s) scheme does not, so it is rejected.
  function isPlainOrigin(value) {
    try {
      const url = new URL(value);
      return (url.protocol === 'http:' || url.protocol === 'https:') && url.origin === value;
    } catch (err) {
      return false;
    }
  }

  // Exact string match only (no prefixes, no wildcards).
  function isAllowedOrigin(origin, allowlist) {
    return isPlainOrigin(origin) && allowlist.indexOf(origin) !== -1;
  }

  // Reads the public request from the popup URL (URLSearchParams or a plain object).
  function parseRequest(params) {
    const get = (key) => (typeof params.get === 'function' ? params.get(key) : params[key]);
    const request = {};
    for (const name of C.PUBLIC_SIGNALS) {
      const value = get(name);
      if (!isDecimal(value)) throw new WalletError(`The website sent an invalid request ("${name}" is missing or not a number).`);
      request[name] = value;
    }
    if (!/^[0-9]{8}$/.test(request.currentDate)) throw new WalletError('The website sent an invalid date.');
    const returnOrigin = get('returnOrigin');
    if (!isPlainOrigin(returnOrigin)) throw new WalletError('The website sent an invalid return address.');
    request.returnOrigin = returnOrigin;
    return request;
  }

  // verifierId = first 31 bytes of SHA-256(origin) (rule in shared/constants.js), via WebCrypto.
  async function verifierIdForOrigin(origin) {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(origin)));
    let hex = '';
    for (let i = 0; i < C.VERIFIER_ID_BYTES; i++) hex += digest[i].toString(16).padStart(2, '0');
    return BigInt('0x' + hex).toString();
  }

  function utcYYYYMMDD(ms) {
    return new Date(ms).toISOString().slice(0, 10).replace(/-/g, '');
  }

  // Extra privacy checks on what the website asks for (they are cheap, and they stop a site
  // from narrowing down your birthday by asking odd questions):
  //  - the age must be a whole number of years (180000 = 18 years, 210000 = 21 years);
  //  - currentDate must be today, give or take a day (time zones), by this computer's clock.
  function checkRequestIsReasonable(request, nowMs) {
    const threshold = BigInt(request.ageThreshold);
    if (threshold % 10000n !== 0n || threshold < 10000n || threshold > 1200000n) {
      throw new WalletError('The website asked for an unusual age threshold, so the wallet refuses.');
    }
    const day = 24 * 60 * 60 * 1000;
    const nearToday = [utcYYYYMMDD(nowMs - day), utcYYYYMMDD(nowMs), utcYYYYMMDD(nowMs + day)];
    if (nearToday.indexOf(request.currentDate) === -1) {
      throw new WalletError(`The website's date (${request.currentDate}) does not match today's date on this computer.`);
    }
  }

  function requiredAge(request) {
    return Number(BigInt(request.ageThreshold) / 10000n);
  }

  // Checks the credential JSON has the shape of shared/credential.schema.json (the parts we use).
  function checkCredential(credential) {
    const ok =
      credential && typeof credential === 'object' &&
      credential.version === C.CREDENTIAL_VERSION &&
      typeof credential.dob === 'string' && /^[0-9]{8}$/.test(credential.dob) &&
      isDecimal(credential.ID_Number) &&
      credential.issuerPubKey && isDecimal(credential.issuerPubKey.x) && isDecimal(credential.issuerPubKey.y) &&
      credential.signature && isDecimal(credential.signature.R8x) &&
      isDecimal(credential.signature.R8y) && isDecimal(credential.signature.S);
    if (!ok) throw new WalletError('This ID card does not contain a valid credential.');
    return credential;
  }

  function isFromRequestedIssuer(credential, request) {
    return credential.issuerPubKey.x === request.issuerPubKeyX && credential.issuerPubKey.y === request.issuerPubKeyY;
  }

  // Same rule as the circuit: dob <= currentDate and currentDate - dob >= ageThreshold.
  function meetsAgeRequirement(credential, request) {
    const dob = BigInt(credential.dob);
    const today = BigInt(request.currentDate);
    return dob <= today && today - dob >= BigInt(request.ageThreshold);
  }

  // Private values come from the credential; public values from the website's request.
  function buildCircuitInput(credential, request) {
    const input = {
      dob: credential.dob,
      ID_Number: credential.ID_Number,
      signatureR8x: credential.signature.R8x,
      signatureR8y: credential.signature.R8y,
      signatureS: credential.signature.S,
    };
    for (const name of C.PUBLIC_SIGNALS) input[name] = request[name];
    return input;
  }

  return {
    WalletError,
    isDecimal,
    isPlainOrigin,
    isAllowedOrigin,
    parseRequest,
    verifierIdForOrigin,
    checkRequestIsReasonable,
    requiredAge,
    checkCredential,
    isFromRequestedIssuer,
    meetsAgeRequirement,
    buildCircuitInput,
  };
});
