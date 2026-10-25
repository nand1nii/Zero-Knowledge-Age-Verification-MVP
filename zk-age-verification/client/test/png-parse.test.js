// client/test/png-parse.test.js
// The wallet's hand-written PNG reader, checked against PNGs built with an independent
// library (png-chunks-encode): finds the zkcred chunk, decodes Unicode, rejects bad files.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const extractChunks = require('png-chunks-extract');
const encodeChunks = require('png-chunks-encode');
const textChunk = require('png-chunk-text');
const { readChunks, extractCredential } = require('../public/png-parse');

// A valid 1x1 PNG.
const TINY_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
  'base64'
);

// Inserts tEXt chunks (keyword -> text) just before IEND.
function pngWithText(entries) {
  const chunks = extractChunks(TINY_PNG);
  const iend = chunks.pop();
  for (const [keyword, text] of entries) chunks.push(textChunk.encode(keyword, text));
  chunks.push(iend);
  return new Uint8Array(encodeChunks(chunks));
}

const base64Json = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
const credential = { version: 1, name: 'José Álvarez नमस्ते', dob: '20000115', ID_Number: '42' };

describe('png-parse', () => {
  it('reads the chunk list of a normal PNG', () => {
    assert.deepEqual(readChunks(new Uint8Array(TINY_PNG)).map((c) => c.type), ['IHDR', 'IDAT', 'IEND']);
  });

  it('finds and decodes the zkcred credential, including non-Latin text', () => {
    const png = pngWithText([['Software', 'demo'], ['zkcred', base64Json(credential)]]);
    assert.deepEqual(extractCredential(png), credential);
  });

  it('ignores other tEXt chunks and look-alike keywords', () => {
    const png = pngWithText([['zkcredX', base64Json({ fake: true })], ['Comment', 'zkcred']]);
    assert.equal(extractCredential(png), null);
  });

  it('returns null when there is no credential', () => {
    assert.equal(extractCredential(new Uint8Array(TINY_PNG)), null);
  });

  it('rejects files that are not PNGs', () => {
    assert.throws(() => extractCredential(new Uint8Array(Buffer.from('GIF89a........'))), /not a PNG/);
    assert.throws(() => extractCredential(new Uint8Array(0)), /not a PNG/);
  });

  it('rejects a truncated PNG', () => {
    const png = pngWithText([['zkcred', base64Json(credential)]]);
    assert.throws(() => extractCredential(png.subarray(0, png.length - 40)), /damaged/);
  });

  it('rejects a zkcred chunk that is not valid base64 JSON', () => {
    assert.throws(() => extractCredential(pngWithText([['zkcred', base64Json('x').slice(0, 2) + '!!']])));
  });
});
