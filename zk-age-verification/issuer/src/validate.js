// issuer/src/validate.js
// Validates the ID form: text lengths, a real date of birth (not in the future, not over
// 120 years ago), and the photo (PNG/JPEG only, max 2 MB, decoded and re-encoded).

const sharp = require('sharp');

const LIMITS = Object.freeze({ name: 60, address: 120, contact: 100 });
const MAX_AGE_YEARS = 120;
const PHOTO_MAX_BYTES = 2 * 1024 * 1024;
const PHOTO_MAX_PIXELS = 4000 * 4000; // refuse "decompression bombs"
const PHOTO_SIZE = { width: 300, height: 380 };

const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const JPEG_MAGIC = Buffer.from([0xff, 0xd8, 0xff]);

// Control characters and Unicode "bidi override" characters (used to make text display
// in a misleading order). Zero-width joiners stay allowed: Indic scripts need them.
const FORBIDDEN_CHARS = /[\p{Cc}‪-‮⁦-⁩]/u;

// Errors whose message is safe to show to the user (sent back as HTTP 400).
class ValidationError extends Error {}

function cleanText(value, label, max, required) {
  const text = typeof value === 'string' ? value.normalize('NFC').trim() : '';
  if (required && text === '') throw new ValidationError(`${label} is required.`);
  if ([...text].length > max) throw new ValidationError(`${label} must be at most ${max} characters.`);
  if (FORBIDDEN_CHARS.test(text)) throw new ValidationError(`${label} contains characters that are not allowed.`);
  return text;
}

// Today as a YYYYMMDD integer, using UTC (the same clock rule as the verifier).
function todayYYYYMMDD(now) {
  return now.getUTCFullYear() * 10000 + (now.getUTCMonth() + 1) * 100 + now.getUTCDate();
}

// "2008-03-15" (from <input type="date">) -> "20080315", or throws ValidationError.
function parseDob(value, now) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(typeof value === 'string' ? value.trim() : '');
  if (!match) throw new ValidationError('Date of birth must be in YYYY-MM-DD format.');
  const [year, month, day] = match.slice(1).map(Number);

  // A real calendar date round-trips through Date unchanged (30 February does not).
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) {
    throw new ValidationError('Date of birth is not a real calendar date.');
  }

  const dob = year * 10000 + month * 100 + day;
  const today = todayYYYYMMDD(now);
  if (dob > today) throw new ValidationError('Date of birth cannot be in the future.');
  if (dob < today - MAX_AGE_YEARS * 10000) {
    throw new ValidationError(`Date of birth cannot be more than ${MAX_AGE_YEARS} years ago.`);
  }
  return String(dob);
}

// body = the form fields (strings). Returns { name, address, contact, dob }.
function validateForm(body, now = new Date()) {
  const form = body || {};
  return {
    name: cleanText(form.name, 'Name', LIMITS.name, true),
    address: cleanText(form.address, 'Address', LIMITS.address, true),
    contact: cleanText(form.contact, 'Contact info', LIMITS.contact, false),
    dob: parseDob(form.dob, now),
  };
}

// file = multer upload ({ buffer }) or undefined. Returns a JPEG data: URL, or null when
// no photo was uploaded (the card then shows a default avatar).
// Decoding and re-encoding the image means only clean pixels reach the card: no odd bytes,
// no metadata (EXIF, GPS), no polyglot files.
async function processPhoto(file) {
  if (!file || !file.buffer || file.buffer.length === 0) return null;
  const buffer = file.buffer;
  if (buffer.length > PHOTO_MAX_BYTES) throw new ValidationError('Photo must be at most 2 MB.');

  const looksLikePng = buffer.subarray(0, 8).equals(PNG_MAGIC);
  const looksLikeJpeg = buffer.subarray(0, 3).equals(JPEG_MAGIC);
  if (!looksLikePng && !looksLikeJpeg) throw new ValidationError('Photo must be a PNG or JPEG image.');

  try {
    const image = sharp(buffer, { limitInputPixels: PHOTO_MAX_PIXELS });
    const { format } = await image.metadata();
    if (format !== 'png' && format !== 'jpeg') throw new ValidationError('Photo must be a PNG or JPEG image.');

    const jpeg = await image
      .rotate() // apply the EXIF orientation, then the metadata is dropped
      .resize(PHOTO_SIZE.width, PHOTO_SIZE.height, { fit: 'cover' })
      .jpeg({ quality: 85 })
      .toBuffer();
    return 'data:image/jpeg;base64,' + jpeg.toString('base64');
  } catch (err) {
    if (err instanceof ValidationError) throw err;
    throw new ValidationError('Photo could not be read. Please upload a normal PNG or JPEG image.');
  }
}

module.exports = {
  LIMITS,
  PHOTO_MAX_BYTES,
  ValidationError,
  todayYYYYMMDD,
  parseDob,
  validateForm,
  processPhoto,
};
