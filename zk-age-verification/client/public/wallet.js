// client/public/wallet.js
// Wallet popup page logic (DOM only; decisions live in wallet-core.js): check the request,
// read the dropped card, ask for consent, prove with snarkjs, postMessage to returnOrigin only.

(function () {
  'use strict';
  const Core = window.WalletCore;
  const Png = window.PngParse;
  const STORAGE_KEY = 'zkwallet.credential';
  const PROVE_TIMEOUT_MS = 60 * 1000; // proving normally takes 2-3 seconds
  const STEPS = ['loading-step', 'fatal-step', 'card-step', 'consent-step', 'progress-step', 'done-step'];
  const $ = (id) => document.getElementById(id);

  let request = null; // the website's public request (validated)
  let credential = null; // the card the user picked

  function show(step) {
    for (const id of STEPS) $(id).hidden = id !== step;
  }

  function fatal(message) {
    $('fatal-message').textContent = message;
    show('fatal-step');
  }

  function userMessage(err, fallback) {
    return err instanceof Core.WalletError ? err.message : fallback;
  }

  function fillText(selector, text) {
    for (const el of document.querySelectorAll(selector)) el.textContent = text;
  }

  // ---- "Remember my card" (localStorage, unencrypted: demo only) ----------------------------
  function loadRemembered() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? Core.checkCredential(JSON.parse(raw)) : null;
    } catch (err) {
      return null;
    }
  }
  function saveRemembered(cred) {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(cred)); } catch (err) { /* storage unavailable */ }
  }
  function forgetRemembered() {
    try { localStorage.removeItem(STORAGE_KEY); } catch (err) { /* storage unavailable */ }
  }

  // ---- 1. Check the request before showing anything ------------------------------------------
  async function start() {
    try {
      const config = await (await fetch('/config.json')).json();
      request = Core.parseRequest(new URLSearchParams(window.location.search));

      if (!Core.isAllowedOrigin(request.returnOrigin, config.allowedVerifierOrigins)) {
        throw new Core.WalletError(`${request.returnOrigin} is not on this wallet's list of approved websites, so the wallet will not talk to it.`);
      }
      if (!window.opener) {
        throw new Core.WalletError('Open this wallet using the "Verify" button of a website.');
      }
      // The verifierId must belong to the site that will receive the proof. Otherwise one
      // approved site could ask for a proof that is valid at a different site.
      if ((await Core.verifierIdForOrigin(request.returnOrigin)) !== request.verifierId) {
        throw new Core.WalletError('This request does not belong to the website it came from (verifierId mismatch).');
      }
      Core.checkRequestIsReasonable(request, Date.now());
    } catch (err) {
      fatal(userMessage(err, `Could not read the request: ${err.message}`));
      return;
    }

    fillText('.site', request.returnOrigin);
    fillText('.age', String(Core.requiredAge(request)));
    showCardStep();
  }

  function showCardStep() {
    const saved = loadRemembered();
    $('remembered').hidden = !saved;
    if (saved) $('remembered-name').textContent = saved.name || 'your card';
    show('card-step');
  }

  // ---- 2. Read the card ------------------------------------------------------------------------
  function useCredential(cred) {
    Core.checkCredential(cred);
    if (!Core.isFromRequestedIssuer(cred, request)) {
      throw new Core.WalletError('This ID is from a different issuer than the one this website trusts.');
    }
    if (!Core.meetsAgeRequirement(cred, request)) {
      throw new Core.WalletError(`This ID card does not meet the age requirement (at least ${Core.requiredAge(request)}), so no proof can be made.`);
    }
    credential = cred;
    show('consent-step');
  }

  async function useFile(file) {
    $('card-error').textContent = '';
    if (!file) return;
    try {
      if (file.size > 5 * 1024 * 1024) throw new Core.WalletError('That file is too large to be an ID card.');
      const bytes = new Uint8Array(await file.arrayBuffer());
      let cred;
      try {
        cred = Png.extractCredential(bytes);
      } catch (err) {
        throw new Core.WalletError(err.message);
      }
      if (!cred) {
        throw new Core.WalletError('No credential found in this image. Use the original id_card.png you downloaded (screenshots do not work).');
      }
      const preview = $('card-preview');
      preview.src = URL.createObjectURL(file);
      preview.hidden = false;
      useCredential(cred);
    } catch (err) {
      $('card-error').textContent = userMessage(err, 'Could not read that file.');
    }
  }

  // ---- 3. Prove and send -----------------------------------------------------------------------
  async function approve() {
    show('progress-step');
    if ($('remember').checked) saveRemembered(credential);

    const started = performance.now();
    const timer = setInterval(() => {
      $('elapsed').textContent = ((performance.now() - started) / 1000).toFixed(1);
    }, 100);

    try {
      $('progress-message').textContent = 'Generating your proof on this device (a few seconds)...';
      const input = Core.buildCircuitInput(credential, request);
      const proving = window.snarkjs.groth16.fullProve(
        input,
        '/artifacts/age_check.wasm',
        '/artifacts/age_check_final.zkey',
        undefined,
        undefined,
        { singleThread: true } // no Web Workers, so the strict CSP needs no worker exception
      );
      const tooSlow = new Promise((resolve, reject) => {
        setTimeout(() => reject(new Core.WalletError('Making the proof took too long. Please try again.')), PROVE_TIMEOUT_MS);
      });
      const { proof, publicSignals } = await Promise.race([proving, tooSlow]);

      if (!window.opener || window.opener.closed) throw new Core.WalletError('The website window was closed.');
      $('progress-message').textContent = 'Sending the proof...';
      // Exact target origin, NEVER "*": the browser delivers the proof only if the opener
      // is still on returnOrigin, so no other website can receive it.
      window.opener.postMessage({ proof, publicSignals }, request.returnOrigin);

      show('done-step');
      setTimeout(() => window.close(), 2500);
    } catch (err) {
      const assertFailed = /Assert Failed/.test(String(err && err.message));
      fatal(assertFailed
        ? 'The proof could not be made: the card data or its signature is not valid.'
        : userMessage(err, `The proof could not be made: ${err.message}`));
    } finally {
      clearInterval(timer);
    }
  }

  // ---- Wire up the page ------------------------------------------------------------------------
  const dropzone = $('dropzone');
  dropzone.addEventListener('dragover', (event) => {
    event.preventDefault();
    dropzone.classList.add('over');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('over'));
  dropzone.addEventListener('drop', (event) => {
    event.preventDefault();
    dropzone.classList.remove('over');
    useFile(event.dataTransfer.files[0]);
  });
  $('file-input').addEventListener('change', (event) => useFile(event.target.files[0]));

  $('use-remembered').addEventListener('click', () => {
    $('card-error').textContent = '';
    $('card-preview').hidden = true;
    try {
      useCredential(loadRemembered());
    } catch (err) {
      $('card-error').textContent = userMessage(err, 'The remembered card could not be used.');
    }
  });
  $('forget').addEventListener('click', () => {
    forgetRemembered();
    $('remembered').hidden = true;
  });
  $('approve').addEventListener('click', approve);
  for (const button of document.querySelectorAll('[data-action="close"]')) {
    button.addEventListener('click', () => window.close());
  }

  start();
})();
