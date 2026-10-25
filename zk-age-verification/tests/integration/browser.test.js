// tests/integration/browser.test.js
// The full demo in a real (headless) Chromium: issue a card in the issuer UI, drop it into the
// wallet popup opened by the verifier, approve, and get access. Plus the wallet's refusals.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const puppeteer = require('puppeteer');
const C = require('../../shared/constants');
const stack = require('./stack');

const TIMEOUT = { timeout: 120000 };

describe('full flow in a browser', () => {
  let s;
  let browser;
  const problems = []; // console errors and page errors from every page (e.g. CSP violations)

  before(async () => {
    s = await stack.start();
    const args = process.env.CHROMIUM_NO_SANDBOX === '1' ? ['--no-sandbox'] : [];
    browser = await puppeteer.launch({ headless: true, executablePath: process.env.CHROMIUM_PATH || undefined, args });
    browser.on('targetcreated', async (target) => {
      const page = await target.page();
      if (!page) return;
      page.on('console', (msg) => { if (msg.type() === 'error') problems.push(`${page.url()}: ${msg.text()}`); });
      page.on('pageerror', (err) => problems.push(`${page.url()}: ${err.message}`));
    });
  });

  after(async () => {
    if (browser) await browser.close();
    if (s) await s.stop();
  });

  // Fills in the issuer form and downloads the card; returns the PNG's path.
  async function issueCardInBrowser({ name, dob }) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zk-card-'));
    const page = await browser.newPage();
    const cdp = await page.createCDPSession();
    await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: dir });

    await page.goto(C.ISSUER_ORIGIN + '/');
    await page.type('input[name=name]', name);
    await page.$eval('input[name=dob]', (el, value) => { el.value = value; }, dob);
    await page.type('textarea[name=address]', '12 Analytical Way');
    await page.click('#submit');
    await page.waitForSelector('#result:not([hidden])', { timeout: 30000 });
    await page.click('#download');

    const file = path.join(dir, 'id_card.png');
    for (let i = 0; i < 100 && !fs.existsSync(file); i++) await new Promise((r) => setTimeout(r, 100));
    assert.ok(fs.existsSync(file), 'the card was not downloaded');
    await page.close();
    return file;
  }

  // Opens the verifier, clicks "Verify Age with ZK" and returns { site, wallet }.
  async function openWalletFromVerifier() {
    const site = await browser.newPage();
    await site.goto(C.VERIFIER_ORIGIN + '/');
    const popupOpened = new Promise((resolve) => site.once('popup', resolve));
    await site.click('#verify');
    const wallet = await popupOpened;
    await wallet.waitForSelector('#card-step:not([hidden]), #fatal-step:not([hidden])', { timeout: 15000 });
    return { site, wallet };
  }

  async function uploadCard(wallet, file) {
    const input = await wallet.$('#file-input');
    await input.uploadFile(file);
  }

  const text = (page, selector) => page.$eval(selector, (el) => el.textContent.replace(/\s+/g, ' ').trim());

  it('issue a card, drop it into the wallet, approve, get access', TIMEOUT, async () => {
    const card = await issueCardInBrowser({ name: 'Ada Lovelace', dob: '2000-01-15' });
    const { site, wallet } = await openWalletFromVerifier();

    assert.match(await text(wallet, '#card-step .request'), /http:\/\/localhost:3003 asks you to prove you are at least 18/);
    await uploadCard(wallet, card);
    await wallet.waitForSelector('#consent-step:not([hidden])');
    assert.match(await text(wallet, '.consent'), /http:\/\/localhost:3003 wants proof that you are at least 18\. Your birthdate will NOT be shared/);

    await wallet.click('#remember');
    const navigated = site.waitForNavigation({ timeout: 60000 });
    await wallet.click('#approve');
    await navigated;

    assert.equal(site.url(), C.VERIFIER_ORIGIN + '/success');
    assert.equal(await text(site, '#secret'), 'Welcome to the 18+ Lounge');
    await site.close();
  });

  it('"Remember my card" lets the next verification skip the file, and "Forget" removes it', TIMEOUT, async () => {
    const { site, wallet } = await openWalletFromVerifier();
    await wallet.waitForSelector('#remembered:not([hidden])');
    assert.equal(await text(wallet, '#remembered-name'), 'Ada Lovelace');

    const navigated = site.waitForNavigation({ timeout: 60000 });
    await wallet.click('#use-remembered');
    await wallet.waitForSelector('#consent-step:not([hidden])');
    await wallet.click('#approve');
    await navigated;
    assert.equal(site.url(), C.VERIFIER_ORIGIN + '/success');
    await site.close();

    const second = await openWalletFromVerifier();
    await second.wallet.click('#forget');
    assert.equal(await second.wallet.$eval('#remembered', (el) => el.hidden), true);
    assert.equal(await second.wallet.evaluate(() => localStorage.getItem('zkwallet.credential')), null);
    await second.site.close();
  });

  it('the wallet refuses an underage card before proving', TIMEOUT, async () => {
    const card = await issueCardInBrowser({ name: 'Young Person', dob: '2015-06-01' });
    const { site, wallet } = await openWalletFromVerifier();
    await uploadCard(wallet, card);
    await wallet.waitForFunction(() => document.getElementById('card-error').textContent.length > 0);
    assert.match(await text(wallet, '#card-error'), /does not meet the age requirement/);
    assert.equal(await wallet.$eval('#consent-step', (el) => el.hidden), true);
    await site.close();
  });

  it('the wallet refuses a PNG without the hidden credential (e.g. a screenshot)', TIMEOUT, async () => {
    const page = await browser.newPage();
    await page.goto(C.ISSUER_ORIGIN + '/');
    const screenshot = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'zk-shot-')), 'screenshot.png');
    await page.screenshot({ path: screenshot });
    await page.close();

    const { site, wallet } = await openWalletFromVerifier();
    await uploadCard(wallet, screenshot);
    await wallet.waitForFunction(() => document.getElementById('card-error').textContent.length > 0);
    assert.match(await text(wallet, '#card-error'), /No credential found/);
    await site.close();
  });

  // Opens the wallet directly with hand-made parameters (as an attacker could).
  async function openWalletWith(params) {
    const opener = await browser.newPage();
    await opener.goto(C.VERIFIER_ORIGIN + '/');
    const popupOpened = new Promise((resolve) => opener.once('popup', resolve));
    await opener.evaluate((url) => window.open(url, '_blank', 'popup'), `${C.WALLET_ORIGIN}/?${new URLSearchParams(params)}`);
    const wallet = await popupOpened;
    await wallet.waitForSelector('#fatal-step:not([hidden]), #card-step:not([hidden])');
    return { opener, wallet };
  }

  async function genuineParams() {
    const res = await fetch(`${s.verifier}/challenge`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    return res.json();
  }

  it('the wallet refuses a returnOrigin that is not on its allowlist', TIMEOUT, async () => {
    const { opener, wallet } = await openWalletWith({ ...(await genuineParams()), returnOrigin: 'http://evil.example' });
    assert.equal(await wallet.$eval('#card-step', (el) => el.hidden), true);
    assert.match(await text(wallet, '#fatal-message'), /http:\/\/evil\.example is not on this wallet's list of approved websites/);
    await opener.close();
  });

  it('the wallet refuses a verifierId that belongs to another site', TIMEOUT, async () => {
    const params = await genuineParams();
    const { opener, wallet } = await openWalletWith({ ...params, verifierId: '12345' });
    assert.match(await text(wallet, '#fatal-message'), /verifierId mismatch/);
    await opener.close();
  });

  it('the wallet refuses to be used without an opening website', TIMEOUT, async () => {
    const page = await browser.newPage();
    await page.goto(`${C.WALLET_ORIGIN}/?${new URLSearchParams(await genuineParams())}`);
    await page.waitForSelector('#fatal-step:not([hidden])');
    assert.match(await text(page, '#fatal-message'), /Verify/);
    await page.close();
  });

  it('the verifier page ignores proofs posted from any origin other than the wallet', TIMEOUT, async () => {
    const { site, wallet } = await openWalletFromVerifier();
    const verifyCalls = [];
    site.on('request', (req) => { if (req.url().endsWith('/verify')) verifyCalls.push(req.url()); });

    // The popup ends up on a different origin (here: the issuer) and posts a "proof".
    await wallet.goto(C.ISSUER_ORIGIN + '/');
    await wallet.evaluate(() => window.opener.postMessage({ proof: { pi_a: [] }, publicSignals: ['1', '2', '3', '4', '5', '6'] }, '*'));
    await new Promise((resolve) => setTimeout(resolve, 1000));

    assert.deepEqual(verifyCalls, []);
    assert.doesNotMatch(await text(site, '#status'), /Checking your proof/);
    await site.close();
  });

  it('no page logged an error or a Content-Security-Policy violation', () => {
    assert.deepEqual(problems, []);
  });
});
