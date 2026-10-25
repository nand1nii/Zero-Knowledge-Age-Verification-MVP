// issuer/public/issuer.js
// Sends the ID form to POST /issue and shows the returned card PNG with a download link.
// The download is the exact bytes from the server, so the hidden credential survives.

const form = document.getElementById('id-form');
const statusEl = document.getElementById('status');
const submitButton = document.getElementById('submit');
const result = document.getElementById('result');
const cardImg = document.getElementById('card');
const downloadLink = document.getElementById('download');
let lastUrl = null;

function showStatus(message, isError) {
  statusEl.textContent = message;
  statusEl.className = isError ? 'error' : '';
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  submitButton.disabled = true;
  showStatus('Signing your credential and printing the card...', false);

  try {
    const response = await fetch('/issue', { method: 'POST', body: new FormData(form) });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `The server answered ${response.status}.`);
    }
    const blob = await response.blob();
    if (lastUrl) URL.revokeObjectURL(lastUrl);
    lastUrl = URL.createObjectURL(blob);

    cardImg.src = lastUrl;
    downloadLink.href = lastUrl;
    result.hidden = false;
    showStatus('Done! Download your card below.', false);
    result.scrollIntoView({ behavior: 'smooth' });
  } catch (err) {
    showStatus(err.message, true);
  } finally {
    submitButton.disabled = false;
  }
});
