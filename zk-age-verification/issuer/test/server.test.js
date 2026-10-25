// issuer/test/server.test.js
// End to end through HTTP: POST /issue returns a PNG; extracting the credential back out
// gives schema-valid JSON whose signature checks out. Bad input gets a 400.
// Needs Chromium (see render-card.test.js).

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const Ajv2020 = require('ajv/dist/2020');
const schema = require('../../shared/credential.schema.json');
const { createApp } = require('../src/server');
const { extractCredential } = require('../src/png-embed');
const { verifyCredentialSignature, publicKeyFromPrivate } = require('../src/credential');
const { closeBrowser } = require('../src/render-card');
const { TEST_KEY, NOW, makeImage, startServer, issueForm } = require('./helpers');

const validateSchema = new Ajv2020().compile(schema);
const fields = { name: 'José Álvarez नमस्ते', dob: '2000-01-15', address: '12 Analytical Way', contact: 'jose@example.com' };

describe('issuer server', () => {
  let server;

  before(async () => {
    server = await startServer(createApp({ privateKey: TEST_KEY, now: () => NOW }));
  });

  after(async () => {
    await server.close();
    await closeBrowser();
  });

  async function issue(formFields, photo) {
    return fetch(`${server.url}/issue`, { method: 'POST', body: issueForm(formFields, photo) });
  }

  it('serves the form with a strict Content-Security-Policy', async () => {
    const res = await fetch(`${server.url}/`);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /<form id="id-form"/);
    assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  });

  it('issues a PNG whose embedded credential is valid and correctly signed', async () => {
    const photo = { buffer: await makeImage('jpeg'), type: 'image/jpeg', name: 'me.jpg' };
    const res = await issue(fields, photo);
    assert.equal(res.status, 200, await res.clone().text());
    assert.equal(res.headers.get('content-type'), 'image/png');
    assert.match(res.headers.get('content-disposition'), /attachment; filename="id_card.png"/);

    const credential = extractCredential(Buffer.from(await res.arrayBuffer()));
    assert.ok(validateSchema(credential), JSON.stringify(validateSchema.errors));
    assert.equal(credential.name, fields.name); // non-Latin text survives
    assert.equal(credential.dob, '20000115');
    assert.equal(credential.contact, fields.contact);
    assert.deepEqual(credential.issuerPubKey, await publicKeyFromPrivate(TEST_KEY));
    assert.equal(await verifyCredentialSignature(credential), true);
  });

  it('works without a photo (default avatar)', async () => {
    const res = await issue(fields);
    assert.equal(res.status, 200);
    assert.ok(extractCredential(Buffer.from(await res.arrayBuffer())));
  });

  it('stores a malicious name as plain data, and still renders the card', async () => {
    const name = '<iframe src="file:///etc/passwd">';
    const res = await issue({ ...fields, name });
    assert.equal(res.status, 200);
    assert.equal(extractCredential(Buffer.from(await res.arrayBuffer())).name, name);
  });

  it('gives each card a different ID_Number', async () => {
    const a = extractCredential(Buffer.from(await (await issue(fields)).arrayBuffer()));
    const b = extractCredential(Buffer.from(await (await issue(fields)).arrayBuffer()));
    assert.notEqual(a.ID_Number, b.ID_Number);
  });

  const badRequests = [
    ['30 February', { ...fields, dob: '2023-02-30' }, undefined, /real calendar date/],
    ['a future birthday', { ...fields, dob: '2027-01-01' }, undefined, /future/],
    ['a missing name', { ...fields, name: '' }, undefined, /Name is required/],
    ['a 61-character name', { ...fields, name: 'x'.repeat(61) }, undefined, /at most 60/],
  ];
  for (const [label, formFields, photo, message] of badRequests) {
    it(`rejects ${label} with 400`, async () => {
      const res = await issue(formFields, photo);
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, message);
    });
  }

  it('rejects a GIF photo and a text file pretending to be a PNG', async () => {
    const gif = { buffer: await makeImage('gif'), type: 'image/png', name: 'me.png' };
    const text = { buffer: Buffer.from('hello'), type: 'image/png', name: 'me.png' };
    for (const photo of [gif, text]) {
      const res = await issue(fields, photo);
      assert.equal(res.status, 400);
      assert.match((await res.json()).error, /PNG or JPEG/);
    }
  });

  it('rejects photos over 2 MB while uploading', async () => {
    const big = { buffer: Buffer.alloc(2 * 1024 * 1024 + 1), type: 'image/png', name: 'big.png' };
    const res = await issue(fields, big);
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /2 MB/);
  });
});
