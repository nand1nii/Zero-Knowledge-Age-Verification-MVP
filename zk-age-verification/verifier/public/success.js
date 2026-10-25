// verifier/public/success.js
// "Start over" button on the success page: ends the verified session and goes back home.
// Contains no secrets (it lives in public/); the protected content is in success.html.

document.getElementById('logout').addEventListener('click', async () => {
  await fetch('/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  window.location.href = '/';
});
