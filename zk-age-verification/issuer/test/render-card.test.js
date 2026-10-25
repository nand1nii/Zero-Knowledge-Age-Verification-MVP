// issuer/test/render-card.test.js
// HTML injection: a Name like <script> or <iframe src="file:///etc/passwd"> must show up as
// plain text on the card. Also checks each renderer safety layer on its own.
// Needs Chromium: set CHROMIUM_PATH, or let `npm install` download Puppeteer's browser.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const os = require('os');
const sharp = require('sharp');
const { buildCardHtml, withCardPage, renderCard, closeBrowser, escapeHtml, CARD } = require('../src/render-card');

const baseFields = { name: 'Ada Lovelace', address: '12 Analytical Way', dob: '20000115', idNumber: '1234567890', issuedOn: '20261025' };

function lanAddress() {
  const addresses = Object.values(os.networkInterfaces()).flat();
  const lan = addresses.find((a) => a && a.family === 'IPv4' && !a.internal);
  return lan ? lan.address : null;
}

const ATTACKS = [
  '<script>document.body.innerHTML="pwned"</script>',
  '<iframe src="file:///etc/passwd"></iframe>',
  '<img src=x onerror="alert(1)">',
  '"><b>bold</b><!--',
];

describe('card rendering', () => {
  after(closeBrowser);

  it('escapes HTML special characters', () => {
    assert.equal(escapeHtml(`<a href="x">'&'</a>`), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
  });

  for (const attack of ATTACKS) {
    it(`shows ${JSON.stringify(attack)} in the Name and Address as plain text`, async () => {
      const html = buildCardHtml({ ...baseFields, name: attack, address: attack });
      assert.equal(html.includes(attack), false, 'raw attack string must not be in the HTML');

      const dom = await withCardPage(html, (page) =>
        page.evaluate(() => ({
          name: document.querySelector('.name').textContent,
          address: document.querySelector('.address').textContent,
          injected: document.querySelectorAll('script, iframe, b').length,
          images: document.querySelectorAll('img').length, // only the photo
          bodyStart: document.body.textContent.trim().slice(0, 20),
        }))
      );
      assert.equal(dom.name, attack);
      assert.equal(dom.address, attack);
      assert.equal(dom.injected, 0);
      assert.equal(dom.images, 1);
      assert.notEqual(dom.bodyStart, 'pwned');
    });
  }

  it('renders a PNG of the card size, with or without a photo', async () => {
    const png = await renderCard({ ...baseFields, name: ATTACKS[1] });
    const meta = await sharp(png).metadata();
    assert.equal(meta.format, 'png');
    assert.equal(meta.width, CARD.width);
    assert.equal(meta.height, CARD.height);
  });

  describe('safety layers, each tested on its own with raw (unescaped) HTML', () => {
    it('JavaScript is disabled', async () => {
      const title = await withCardPage('<title>before</title><script>document.title = "ran"</script>', (page) => page.title());
      assert.equal(title, 'before');
    });

    it('network requests are blocked (a test server on this machine sees no hits)', async (t) => {
      // Chrome already refuses requests from a data: page to 127.0.0.1 / localhost on its
      // own, so use a non-loopback address: only our request interception can block that.
      const host = lanAddress();
      if (!host) return t.skip('no non-loopback network interface on this machine');

      let hits = 0;
      const server = http.createServer((req, res) => { hits++; res.end('x'); });
      await new Promise((resolve) => server.listen(0, host, resolve));
      const base = `http://${host}:${server.address().port}`;
      try {
        await withCardPage(
          `<link rel="stylesheet" href="${base}/a.css"><img src="${base}/b.png">` +
            `<div style="background:url(${base}/c.png)">x</div><iframe src="${base}/d"></iframe>`,
          () => null
        );
      } finally {
        server.close();
      }
      assert.equal(hits, 0);
    });

    it('local files cannot be read into the page', async () => {
      const content = await withCardPage('<iframe src="file:///etc/passwd"></iframe>', (page) =>
        page.evaluate(() => {
          try {
            const doc = document.querySelector('iframe').contentDocument;
            return doc ? doc.documentElement.textContent : '';
          } catch (err) {
            return '';
          }
        })
      );
      assert.equal(content.includes('root:'), false);
    });
  });
});
