// End-to-end test of the buddy panel's confirmation gate.
//
// It exists because that interaction lives entirely in the page's client
// state, which had no coverage at all -- and shipped broken on 17 Oct. The
// reveal step cleared the typed pair and the add step resent it, so the
// server's own check rejected every add and the Add button could never work.
// Every HTTP check passed throughout, because they drive the endpoint and
// not the page; a reviewer found it by reading two lines together.
//
// Run through `tests/ui-e2e.sh`, which builds the fixture and skips cleanly
// when playwright or a system chromium is missing.
import { chromium } from 'playwright';

const [base, key, wantPair, wrongPair] = process.argv.slice(2);
let failed = 0;
const ok = (c, m) => { if (!c) { failed++; console.log('  FAIL: ' + m); } };

const browser = await chromium.launch({
  executablePath: process.env.CHROME || '/usr/bin/chromium',
});
const page = await browser.newPage();
const errors = [];
page.on('pageerror', e => errors.push(String(e)));

// Every wait is wrapped: a timeout IS the failure here, and letting it throw
// reported "TimeoutError" instead of saying which property broke.
const waitFor = async (sel, what) => {
  try { await page.waitForSelector(sel, { timeout: 10000 }); return true; }
  catch { failed++; console.log('  FAIL: ' + what); return false; }
};

try {
  await page.goto(base + '/#buddies=' + encodeURIComponent(key));
  if (await waitFor('.dev.ask', 'the connection request never appeared')) {
    const card = page.locator('.dev.ask').first();

    // The pair is not on the page before it is typed. This is the property
    // the whole gate rests on: a card that already shows the answer turns
    // confirming it into copying.
    ok(!(await page.content()).includes(wantPair),
       'the asked pair was on the page before it was typed');

    // A wrong answer reveals nothing and echoes nothing.
    await card.locator('input.lanin').first().fill(wrongPair);
    await card.getByText('Check this pair').click();
    if (await waitFor('.berr', 'a wrong pair produced no error')) {
      ok(!(await page.content()).includes(wantPair),
         'a wrong answer revealed or echoed the expected pair');
      ok(await page.locator('.dev.ask .devfp').count() === 0,
         'a wrong answer revealed a fingerprint');
    }

    // The right answer reveals all four.
    await card.locator('input.lanin').first().fill(wantPair);
    await card.getByText('Check this pair').click();
    if (await waitFor('.dev.ask .devfp', 'the right pair did not reveal the fingerprint')) {
      ok((await page.content()).includes(wantPair),
         'the revealed fingerprint does not contain the pair that was typed');

      // And the add succeeds. The reveal clears the input, so this passes
      // only if the confirmed pair survived in page state -- which is the
      // regression that shipped.
      await card.locator('input.lanin').first().fill('e2e-contact');
      await card.getByText('All four match').click();
      if (await waitFor('.bok', 'the add never reported success -- the button is dead')) {
        ok(/added/.test((await page.locator('.bok').first().textContent()) || ''),
           'the add reported something other than having added them');
        try {
          await page.waitForFunction(() => !document.querySelector('.dev.ask'),
                                     { timeout: 10000 });
        } catch { failed++; console.log('  FAIL: the request stayed after being approved'); }
        ok((await page.content()).includes('e2e-contact'),
           'the approved request did not become a buddy');
      }
    }
  }
  ok(errors.length === 0, 'the page threw: ' + errors.join(' | '));
} catch (e) {
  failed++;
  console.log('  FAIL: the run itself broke: ' + (e && e.message ? e.message : e));
} finally {
  await browser.close();
}
console.log(failed ? `ui-e2e: ${failed} failed` : 'ui-e2e: ok');
process.exit(failed ? 1 : 0);
