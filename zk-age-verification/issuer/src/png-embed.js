// issuer/src/png-embed.js
// Hides the credential JSON inside the ID card PNG as a tEXt chunk (keyword "zkcred"),
// and reads it back. The JSON is base64-encoded because tEXt only supports Latin-1.

const extractChunks = require('png-chunks-extract');
const encodeChunks = require('png-chunks-encode');
const textChunk = require('png-chunk-text');
const C = require('../../shared/constants');

function isCredentialChunk(chunk) {
  return chunk.name === 'tEXt' && textChunk.decode(chunk.data).keyword === C.PNG_CHUNK_KEYWORD;
}

// Returns a new PNG buffer with the credential embedded just before the IEND chunk.
// Any older zkcred chunk is removed first, so a PNG never carries two credentials.
function embedCredential(pngBuffer, credential) {
  const chunks = extractChunks(new Uint8Array(pngBuffer)).filter((chunk) => !isCredentialChunk(chunk));
  const payload = Buffer.from(JSON.stringify(credential), 'utf8').toString('base64');

  const iendIndex = chunks.findIndex((chunk) => chunk.name === 'IEND');
  chunks.splice(iendIndex, 0, textChunk.encode(C.PNG_CHUNK_KEYWORD, payload));
  return Buffer.from(encodeChunks(chunks));
}

// Returns the credential object, or null if the PNG has no zkcred chunk.
function extractCredential(pngBuffer) {
  const chunk = extractChunks(new Uint8Array(pngBuffer)).find(isCredentialChunk);
  if (!chunk) return null;
  const base64 = textChunk.decode(chunk.data).text;
  return JSON.parse(Buffer.from(base64, 'base64').toString('utf8'));
}

module.exports = { embedCredential, extractCredential };
