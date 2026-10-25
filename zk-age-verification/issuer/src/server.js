// issuer/src/server.js
// Mock government on port 3001: serves the ID form, and POST /issue validates the form,
// signs a credential, renders the ID card PNG, embeds the credential and returns the PNG.

const path = require('path');
const express = require('express');
const multer = require('multer');
const C = require('../../shared/constants');
const { validateForm, processPhoto, todayYYYYMMDD, ValidationError, PHOTO_MAX_BYTES } = require('./validate');
const { createCredential, parsePrivateKey } = require('./credential');
const { renderCard, closeBrowser } = require('./render-card');
const { embedCredential } = require('./png-embed');

// Pages may only load scripts, styles and data from this server.
function securityHeaders(req, res, next) {
  res.set({
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; " +
      "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  next();
}

// Photo upload rules (enforced while the upload streams in).
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: PHOTO_MAX_BYTES, files: 1, fields: 10, fieldSize: 2048, parts: 12 },
}).single('photo');

function parseUpload(req, res, next) {
  upload(req, res, (err) => {
    if (!err) return next();
    if (err.code === 'LIMIT_FILE_SIZE') return next(new ValidationError('Photo must be at most 2 MB.'));
    if (err instanceof multer.MulterError) return next(new ValidationError('Invalid form upload.'));
    next(err);
  });
}

// privateKey: 32-byte Buffer. now: clock function (tests pass a fixed date).
function createApp({ privateKey, now = () => new Date() }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(securityHeaders);
  app.use(express.static(path.join(__dirname, '..', 'public')));

  app.post('/issue', parseUpload, async (req, res, next) => {
    try {
      const today = now();
      const fields = validateForm(req.body, today);
      const photoDataUrl = await processPhoto(req.file);
      const credential = await createCredential(fields, privateKey);

      const card = await renderCard({
        name: fields.name,
        address: fields.address,
        dob: fields.dob,
        photoDataUrl,
        idNumber: credential.ID_Number,
        issuedOn: String(todayYYYYMMDD(today)),
      });
      const png = embedCredential(card, credential);

      res.set({
        'Content-Type': 'image/png',
        'Content-Disposition': 'attachment; filename="id_card.png"',
        'Cache-Control': 'no-store',
      });
      res.send(png);
    } catch (err) {
      next(err);
    }
  });

  // Validation problems -> 400 with a friendly message. Anything else -> 500, details only in the log.
  app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    if (err instanceof ValidationError) return res.status(400).json({ error: err.message });
    console.error('[issuer] error:', err);
    res.status(500).json({ error: 'Something went wrong while issuing the card.' });
  });

  return app;
}

if (require.main === module) {
  const privateKey = parsePrivateKey(process.env.ISSUER_PRIVATE_KEY);
  const port = Number(process.env.PORT || C.PORTS.ISSUER);
  const host = process.env.HOST || '127.0.0.1';
  const server = createApp({ privateKey }).listen(port, host, () => {
    console.log(`[issuer] listening on http://${host}:${port} (open ${C.ISSUER_ORIGIN})`);
  });

  const shutdown = () => {
    server.close();
    closeBrowser().finally(() => process.exit(0));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

module.exports = { createApp };
