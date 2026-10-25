// issuer/test/validate.test.js
// Form validation: real calendar dates only, no future or >120-year-old birthdays,
// text length / character limits, and photo type, size and re-encoding.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { parseDob, validateForm, processPhoto, ValidationError } = require('../src/validate');
const { NOW, makeImage } = require('./helpers');

const valid = { name: 'Ada Lovelace', address: '12 Analytical Way', contact: 'ada@example.com', dob: '2000-01-15' };

describe('date of birth', () => {
  it('converts YYYY-MM-DD to a YYYYMMDD string', () => {
    assert.equal(parseDob('2008-03-15', NOW), '20080315');
  });

  it('rejects dates that do not exist (30 February, 29 February in a non-leap year, month 13)', () => {
    for (const bad of ['2023-02-30', '2023-02-29', '2001-13-01', '2001-04-31', '2001-00-10']) {
      assert.throws(() => parseDob(bad, NOW), ValidationError, bad);
    }
    assert.equal(parseDob('2004-02-29', NOW), '20040229'); // leap year is fine
  });

  it('rejects other formats', () => {
    for (const bad of ['15/03/2008', '20080315', '2008-3-15', '', undefined, 20080315, '0050-01-01']) {
      assert.throws(() => parseDob(bad, NOW), ValidationError, String(bad));
    }
  });

  it('rejects the future but allows today', () => {
    assert.equal(parseDob('2026-10-25', NOW), '20261025');
    assert.throws(() => parseDob('2026-10-26', NOW), /future/);
  });

  it('allows exactly 120 years ago but not older', () => {
    assert.equal(parseDob('1906-10-25', NOW), '19061025');
    assert.throws(() => parseDob('1906-10-24', NOW), /120 years/);
  });
});

describe('text fields', () => {
  it('accepts a valid form and trims whitespace', () => {
    const fields = validateForm({ ...valid, name: '  Ada Lovelace  ' }, NOW);
    assert.deepEqual(fields, { ...valid, name: 'Ada Lovelace', dob: '20000115' });
  });

  it('requires name and address, contact is optional', () => {
    assert.throws(() => validateForm({ ...valid, name: '   ' }, NOW), /Name is required/);
    assert.throws(() => validateForm({ ...valid, address: '' }, NOW), /Address is required/);
    assert.equal(validateForm({ ...valid, contact: undefined }, NOW).contact, '');
  });

  it('limits name to 60 and address to 120 characters (counting real characters, not bytes)', () => {
    assert.equal(validateForm({ ...valid, name: 'é'.repeat(60) }, NOW).name.length, 60);
    assert.throws(() => validateForm({ ...valid, name: 'a'.repeat(61) }, NOW), /at most 60/);
    assert.throws(() => validateForm({ ...valid, address: 'a'.repeat(121) }, NOW), /at most 120/);
    assert.throws(() => validateForm({ ...valid, contact: 'a'.repeat(101) }, NOW), /at most 100/);
  });

  it('keeps non-Latin names (José, Hindi) intact', () => {
    assert.equal(validateForm({ ...valid, name: 'José नमस्ते' }, NOW).name, 'José नमस्ते');
  });

  it('rejects control characters and bidi-override characters', () => {
    assert.throws(() => validateForm({ ...valid, name: 'Ada\u0000' }, NOW), /not allowed/);
    assert.throws(() => validateForm({ ...valid, name: 'Ada\nLovelace' }, NOW), /not allowed/);
    assert.throws(() => validateForm({ ...valid, name: 'Ada‮ecalevol' }, NOW), /not allowed/);
  });
});

describe('photo', () => {
  it('returns null when no photo was uploaded (default avatar)', async () => {
    assert.equal(await processPhoto(undefined), null);
  });

  it('re-encodes PNG and JPEG uploads to a fresh JPEG data URL', async () => {
    for (const format of ['png', 'jpeg']) {
      const url = await processPhoto({ buffer: await makeImage(format) });
      assert.match(url, /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/);
    }
  });

  it('rejects other image types and non-images', async () => {
    await assert.rejects(processPhoto({ buffer: await makeImage('gif') }), /PNG or JPEG/);
    await assert.rejects(processPhoto({ buffer: await makeImage('webp') }), /PNG or JPEG/);
    await assert.rejects(processPhoto({ buffer: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>') }), /PNG or JPEG/);
  });

  it('rejects a file that only pretends to be a PNG', async () => {
    const fake = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('not really a png')]);
    await assert.rejects(processPhoto({ buffer: fake }), /could not be read/);
  });

  it('rejects photos over 2 MB', async () => {
    const big = Buffer.concat([await makeImage('png'), Buffer.alloc(2 * 1024 * 1024)]);
    await assert.rejects(processPhoto({ buffer: big }), /2 MB/);
  });

  it('rejects a "decompression bomb" (tiny file, huge dimensions)', async () => {
    const bomb = await makeImage('png', { width: 5000, height: 5000 });
    assert.ok(bomb.length < 2 * 1024 * 1024);
    await assert.rejects(processPhoto({ buffer: bomb }), /could not be read/);
  });
});
