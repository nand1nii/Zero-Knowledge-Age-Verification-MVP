// verifier/public/landing.js
// "Verify Age with ZK": gets a challenge, opens the wallet popup with the public request,
// accepts a proof ONLY from the wallet origin (and our popup), then POSTs it to /verify.

(function () {
  'use strict';
  const C = window.ZK_CONSTANTS;
  const button = document.getElementById('verify');
  const statusEl = document.getElementById('status');

  let popup = null;
  let popupWatcher = null;
  let proofReceived = false;

  function setStatus(message, kind) {
    statusEl.textContent = message;
    statusEl.className = kind || '';
  }

  if (new URLSearchParams(window.location.search).get('error') === 'not-verified') {
    setStatus('Please verify your age to see that page.', 'error');
  }

  // Tell the user if they close the wallet without sending a proof.
  function watchPopup() {
    clearInterval(popupWatcher);
    popupWatcher = setInterval(() => {
      if (popup && popup.closed) {
        clearInterval(popupWatcher);
        button.disabled = false;
        if (!proofReceived) setStatus('The wallet was closed. No proof was shared.', 'error');
      }
    }, 500);
  }

  button.addEventListener('click', async () => {
    proofReceived = false;
    // Open the popup immediately, inside the click, so pop-up blockers allow it.
    popup = window.open('', 'zk-wallet', 'popup,width=520,height=800');
    if (!popup) {
      setStatus('Please allow pop-ups for this site, then try again.', 'error');
      return;
    }
    button.disabled = true;
    setStatus('Waiting for your wallet...', 'info');

    try {
      const response = await fetch('/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || 'Could not start verification.');
      const request = await response.json();

      // Only public values go in the URL.
      const params = new URLSearchParams({
        challenge: request.challenge,
        currentDate: request.currentDate,
        ageThreshold: request.ageThreshold,
        issuerPubKeyX: request.issuerPubKeyX,
        issuerPubKeyY: request.issuerPubKeyY,
        verifierId: request.verifierId,
        returnOrigin: request.returnOrigin,
      });
      popup.location.href = C.WALLET_ORIGIN + '/?' + params.toString();
      watchPopup();
    } catch (err) {
      popup.close();
      button.disabled = false;
      setStatus(err.message, 'error');
    }
  });

  window.addEventListener('message', async (event) => {
    // Ignore everything that is not from the wallet origin AND from the popup we opened.
    if (event.origin !== C.WALLET_ORIGIN) return;
    if (!popup || event.source !== popup) return;
    const data = event.data;
    if (!data || typeof data !== 'object' || typeof data.proof !== 'object' || !Array.isArray(data.publicSignals)) return;
    if (proofReceived) return;
    proofReceived = true;

    setStatus('Checking your proof...', 'info');
    try {
      const response = await fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof: data.proof, publicSignals: data.publicSignals }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok || !body.ok) throw new Error(body.error || 'Verification failed.');
      setStatus('Verified! Taking you in...', 'ok');
      window.location.href = '/success';
    } catch (err) {
      button.disabled = false;
      setStatus(err.message, 'error');
    }
  });
})();
