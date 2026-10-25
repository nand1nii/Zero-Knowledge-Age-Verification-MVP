// client/public/png-parse.js
// Tiny PNG chunk reader: finds the "zkcred" tEXt chunk in an ID card PNG and decodes the
// base64 credential JSON. Runs in the browser (window.PngParse) and in Node tests.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('../../shared/constants'));
  else root.PngParse = factory(root.ZK_CONSTANTS);
})(typeof self !== 'undefined' ? self : this, function (C) {
  'use strict';

  const PNG_SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];

  function latin1(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }

  // A PNG is an 8-byte signature followed by chunks: [length:4][type:4][data:length][crc:4].
  function readChunks(bytes) {
    for (let i = 0; i < PNG_SIGNATURE.length; i++) {
      if (bytes[i] !== PNG_SIGNATURE[i]) throw new Error('This file is not a PNG image.');
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const chunks = [];
    let offset = 8;
    while (offset + 12 <= bytes.length) {
      const length = view.getUint32(offset);
      const type = latin1(bytes.subarray(offset + 4, offset + 8));
      const dataEnd = offset + 8 + length;
      if (dataEnd + 4 > bytes.length) throw new Error('This PNG file is damaged (cut short).');
      chunks.push({ type, data: bytes.subarray(offset + 8, dataEnd) });
      offset = dataEnd + 4; // skip the CRC
      if (type === 'IEND') break;
    }
    return chunks;
  }

  // Returns the credential object from the "zkcred" chunk, or null if there is none.
  function extractCredential(bytes) {
    for (const chunk of readChunks(bytes)) {
      if (chunk.type !== 'tEXt') continue;
      const separator = chunk.data.indexOf(0); // tEXt = keyword, 0 byte, text
      if (separator < 0 || latin1(chunk.data.subarray(0, separator)) !== C.PNG_CHUNK_KEYWORD) continue;

      const base64 = latin1(chunk.data.subarray(separator + 1));
      const jsonBytes = Uint8Array.from(atob(base64), (ch) => ch.charCodeAt(0));
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(jsonBytes));
    }
    return null;
  }

  return { readChunks, extractCredential };
});
