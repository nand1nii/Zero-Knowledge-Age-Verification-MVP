// issuer/test/helpers.js
// Shared test fixtures for the issuer: a fixed demo key, a fixed "today", tiny images,
// and a helper that starts the Express app on a random port.

const sharp = require('sharp');

// A throwaway key used only by these tests.
const TEST_KEY_HEX = '0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0';
const TEST_KEY = Buffer.from(TEST_KEY_HEX, 'hex');

// "Today" for all issuer tests: 25 Oct 2026, UTC.
const NOW = new Date(Date.UTC(2026, 9, 25, 12, 0, 0));

function makeImage(format, { width = 64, height = 80 } = {}) {
  return sharp({ create: { width, height, channels: 3, background: { r: 30, g: 120, b: 200 } } })
    .toFormat(format)
    .toBuffer();
}

async function startServer(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

// Builds the multipart form the browser would send to POST /issue.
function issueForm(fields, photo) {
  const form = new FormData();
  for (const [key, value] of Object.entries(fields)) form.append(key, value);
  if (photo) form.append('photo', new Blob([photo.buffer], { type: photo.type }), photo.name);
  return form;
}

module.exports = { TEST_KEY_HEX, TEST_KEY, NOW, makeImage, startServer, issueForm };
