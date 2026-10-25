// issuer/test/png-embed.test.js
// The credential survives a round trip through the PNG tEXt chunk, including non-Latin
// text (that is why it is base64-encoded), and the PNG stays a valid image.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const sharp = require('sharp');
const extractChunks = require('png-chunks-extract');
const textChunk = require('png-chunk-text');
const { embedCredential, extractCredential } = require('../src/png-embed');
const { makeImage } = require('./helpers');

const credential = { version: 1, name: 'José Álvarez नमस्ते 李', dob: '20000115', ID_Number: '123' };

describe('png-embed', () => {
  it('round-trips the credential, including non-Latin characters', async () => {
    const png = embedCredential(await makeImage('png'), credential);
    assert.deepEqual(extractCredential(png), credential);
  });

  it('stores base64 text under the keyword "zkcred", before IEND', async () => {
    const chunks = extractChunks(embedCredential(await makeImage('png'), credential));
    const index = chunks.findIndex((c) => c.name === 'tEXt');
    const { keyword, text } = textChunk.decode(chunks[index].data);
    assert.equal(keyword, 'zkcred');
    assert.match(text, /^[A-Za-z0-9+/]+=*$/);
    assert.equal(chunks[index + 1].name, 'IEND');
  });

  it('keeps the PNG a valid image', async () => {
    const png = embedCredential(await makeImage('png'), credential);
    const meta = await sharp(png).metadata();
    assert.equal(meta.format, 'png');
    assert.equal(meta.width, 64);
  });

  it('replaces an existing credential instead of adding a second one', async () => {
    const once = embedCredential(await makeImage('png'), credential);
    const twice = embedCredential(once, { ...credential, name: 'Second' });
    assert.equal(extractChunks(twice).filter((c) => c.name === 'tEXt').length, 1);
    assert.equal(extractCredential(twice).name, 'Second');
  });

  it('returns null for a PNG without a credential', async () => {
    assert.equal(extractCredential(await makeImage('png')), null);
  });
});
