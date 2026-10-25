// issuer/src/render-card.js
// Renders the "Smart ID Card" (HTML/CSS) to a PNG with headless Chromium (Puppeteer).
// Safety: every user string is HTML-escaped, JavaScript is off, only data: URLs may load.

const puppeteer = require('puppeteer');

const CARD = { width: 856, height: 540 }; // ID-1 card shape (85.6 x 54 mm)

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const DEFAULT_AVATAR =
  'data:image/svg+xml;base64,' +
  Buffer.from(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 380">' +
      '<rect width="300" height="380" fill="#dde4ec"/>' +
      '<circle cx="150" cy="145" r="72" fill="#9aabbd"/>' +
      '<path d="M26 380c0-86 56-138 124-138s124 52 124 138z" fill="#9aabbd"/>' +
      '</svg>'
  ).toString('base64');

// Turns characters that mean something in HTML into harmless entities, so a Name like
// <iframe src="file:///etc/passwd"> is shown as text instead of becoming a real iframe.
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// "20080315" -> "15 Mar 2008"
function formatDate(yyyymmdd) {
  const s = String(yyyymmdd);
  return `${s.slice(6, 8)} ${MONTHS[Number(s.slice(4, 6)) - 1]} ${s.slice(0, 4)}`;
}

// fields = { name, address, dob, photoDataUrl, idNumber, issuedOn } (dob/issuedOn: YYYYMMDD)
function buildCardHtml(fields) {
  const photo = typeof fields.photoDataUrl === 'string' && fields.photoDataUrl.startsWith('data:image/')
    ? fields.photoDataUrl
    : DEFAULT_AVATAR;
  // Only the last 4 digits are printed; the full ID_Number is a secret proof input.
  const idSuffix = String(fields.idNumber || '').slice(-4);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { width: ${CARD.width}px; height: ${CARD.height}px; background: #fff; }
  body { font-family: "DejaVu Sans", "Noto Sans", "Noto Sans Devanagari", Arial, sans-serif; color: #12263a; }
  .card { position: relative; width: 100%; height: 100%; overflow: hidden; border-radius: 28px;
          background: linear-gradient(135deg, #e9f2fb 0%, #f7fbff 45%, #e3eef9 100%); border: 2px solid #b7cbe0; }
  .band { height: 92px; padding: 18px 32px; color: #fff; background: linear-gradient(90deg, #0b4f8a, #1576c2); }
  .band .country { font-size: 15px; letter-spacing: 3px; text-transform: uppercase; opacity: .9; }
  .band .title { font-size: 30px; font-weight: bold; letter-spacing: 1px; }
  .photo { position: absolute; left: 32px; top: 120px; width: 210px; height: 266px; border-radius: 12px;
           border: 3px solid #fff; box-shadow: 0 2px 8px rgba(0,0,0,.25); object-fit: cover; background: #dde4ec; }
  .chip { position: absolute; right: 40px; top: 120px; width: 74px; height: 56px; border-radius: 10px;
          background: linear-gradient(135deg, #e8c766, #b8902d); border: 1px solid #8a6a1c; }
  .fields { position: absolute; left: 276px; top: 116px; right: 40px; }
  .label { font-size: 13px; letter-spacing: 2px; text-transform: uppercase; color: #4c6a88; margin-top: 14px; }
  .value { font-size: 24px; font-weight: bold; overflow-wrap: anywhere; }
  .name { font-size: 30px; max-width: 440px; }
  .address { font-size: 18px; font-weight: normal; line-height: 1.3; max-height: 72px; overflow: hidden; }
  .row { display: flex; gap: 48px; }
  .footer { position: absolute; left: 0; right: 0; bottom: 0; height: 64px; padding: 20px 32px;
            background: #0b4f8a; color: #fff; font-size: 15px; letter-spacing: 1px; display: flex; justify-content: space-between; }
  .specimen { position: absolute; right: -40px; bottom: 120px; transform: rotate(-18deg); font-size: 64px;
              font-weight: bold; color: rgba(11, 79, 138, .08); letter-spacing: 8px; }
</style>
</head>
<body>
  <div class="card">
    <div class="band">
      <div class="country">Republic of Demoland</div>
      <div class="title">SMART ID CARD</div>
    </div>
    <img class="photo" src="${escapeHtml(photo)}" alt="">
    <div class="chip"></div>
    <div class="fields">
      <div class="label">Name</div>
      <div class="value name">${escapeHtml(fields.name)}</div>
      <div class="row">
        <div><div class="label">Date of birth</div><div class="value dob">${escapeHtml(formatDate(fields.dob))}</div></div>
        <div><div class="label">ID number</div><div class="value">&bull;&bull;&bull;&bull; ${escapeHtml(idSuffix)}</div></div>
      </div>
      <div class="label">Address</div>
      <div class="value address">${escapeHtml(fields.address)}</div>
    </div>
    <div class="specimen">SPECIMEN</div>
    <div class="footer">
      <span>DEMO CREDENTIAL &middot; NOT A REAL IDENTITY DOCUMENT</span>
      <span>Issued ${escapeHtml(formatDate(fields.issuedOn))}</span>
    </div>
  </div>
</body>
</html>`;
}

// One shared headless browser, started on first use.
let browserPromise = null;
function getBrowser() {
  if (!browserPromise) {
    const args = ['--disable-dev-shm-usage', '--disable-gpu'];
    // Chromium's sandbox does not work inside Docker, so the Dockerfile sets this to 1.
    // That is acceptable here only because the page has no JavaScript and no network.
    if (process.env.CHROMIUM_NO_SANDBOX === '1') args.push('--no-sandbox');

    browserPromise = puppeteer
      .launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined, args })
      .then((browser) => {
        browser.on('disconnected', () => { browserPromise = null; });
        return browser;
      });
    browserPromise.catch(() => { browserPromise = null; });
  }
  return browserPromise;
}

// Opens `html` in a locked-down page and runs fn(page). Used for the screenshot, and by
// the tests to inspect the exact same page the card is rendered from.
async function withCardPage(html, fn) {
  const browser = await getBrowser();
  const context = await browser.createBrowserContext(); // fresh, isolated profile per card
  try {
    const page = await context.newPage();
    await page.setJavaScriptEnabled(false);
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      const allowed = request.url().startsWith('data:');
      (allowed ? request.continue() : request.abort('blockedbyclient')).catch(() => {});
    });
    await page.setViewport({ ...CARD, deviceScaleFactor: 1 });
    const url = 'data:text/html;base64,' + Buffer.from(html, 'utf8').toString('base64');
    await page.goto(url, { waitUntil: 'load', timeout: 15000 });
    return await fn(page);
  } finally {
    await context.close();
  }
}

// Returns the card as a PNG Buffer.
async function renderCard(fields) {
  const png = await withCardPage(buildCardHtml(fields), (page) =>
    page.screenshot({ type: 'png', clip: { x: 0, y: 0, ...CARD } })
  );
  return Buffer.from(png);
}

async function closeBrowser() {
  const pending = browserPromise;
  browserPromise = null;
  const browser = pending && (await pending.catch(() => null));
  if (browser) await browser.close();
}

module.exports = { CARD, escapeHtml, formatDate, buildCardHtml, withCardPage, renderCard, closeBrowser };
