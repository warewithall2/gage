// End-to-end tests of the parts of the viewer that live in the page.
//
// It exists because those parts had no coverage at all -- and the buddy
// panel's confirmation gate shipped broken on 17 Oct. The reveal step
// cleared the typed pair and the add step resent it, so the server's own
// check rejected every add and the Add button could never work. Every HTTP
// check passed throughout, because they drive the endpoint and not the page;
// a reviewer found it by reading two lines together. A page's client state
// is a place defects hide from curl, so each scenario here drives a real
// browser and asserts on what a person would see.
//
// Scenarios, each run as its own process by `tests/ui-e2e.sh`, which builds
// the fixtures and skips cleanly when playwright or a system chromium is
// missing:
//
//   buddies  <base> <key> <wantPair> <wrongPair>
//     the connection-request gate: a pair is not on the page before it is
//     typed, a wrong answer reveals nothing, the right one reveals and adds.
//
//   firstrun <base> <handle> <label> <buddyName> <subject>
//     a home with NO identity: the wizard appears, creates an identity
//     through the page, pairs with the device on the nearby list after an
//     explicit spoken-comparison confirm, and sends a first bundle. Prints
//     `WORDS <...>` so the shell can check them against the key the CLI
//     sees.
//
//   receive  <base> <subject> <sender>
//     the second fixture's console: the bundle that arrived renders with the
//     verified verdict and as pending, and accepting it is a separate act.
import { chromium } from 'playwright';

const [mode, ...args] = process.argv.slice(2);
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
const waitFor = async (sel, what, timeout = 10000) => {
  try { await page.waitForSelector(sel, { timeout }); return true; }
  catch { failed++; console.log('  FAIL: ' + what); return false; }
};
const text = async sel => (await page.locator(sel).first().textContent()) || '';
const has = async s => (await page.content()).includes(s);

// The confirmation gate on an incoming connection request.
async function buddies([base, key, wantPair, wrongPair]) {
  await page.goto(base + '/#buddies=' + encodeURIComponent(key));
  if (await waitFor('.dev.ask', 'the connection request never appeared')) {
    const card = page.locator('.dev.ask').first();

    // The pair is not on the page before it is typed. This is the property
    // the whole gate rests on: a card that already shows the answer turns
    // confirming it into copying.
    ok(!(await has(wantPair)),
       'the asked pair was on the page before it was typed');

    // A wrong answer reveals nothing and echoes nothing.
    await card.locator('input.lanin').first().fill(wrongPair);
    await card.getByText('Check this pair').click();
    if (await waitFor('.berr', 'a wrong pair produced no error')) {
      ok(!(await has(wantPair)),
         'a wrong answer revealed or echoed the expected pair');
      ok(await page.locator('.dev.ask .devfp').count() === 0,
         'a wrong answer revealed a fingerprint');
    }

    // The right answer reveals all four.
    await card.locator('input.lanin').first().fill(wantPair);
    await card.getByText('Check this pair').click();
    if (await waitFor('.dev.ask .devfp', 'the right pair did not reveal the fingerprint')) {
      ok(await has(wantPair),
         'the revealed fingerprint does not contain the pair that was typed');

      // And the add succeeds. The reveal clears the input, so this passes
      // only if the confirmed pair survived in page state -- which is the
      // regression that shipped.
      await card.locator('input.lanin').first().fill('e2e-contact');
      await card.getByText('All four match').click();
      if (await waitFor('.bok', 'the add never reported success -- the button is dead')) {
        ok(/added/.test(await text('.bok')),
           'the add reported something other than having added them');
        try {
          await page.waitForFunction(() => !document.querySelector('.dev.ask'),
                                     { timeout: 10000 });
        } catch { failed++; console.log('  FAIL: the request stayed after being approved'); }
        ok(await has('e2e-contact'),
           'the approved request did not become a buddy');
      }
    }
  }
}

// A stranger with only the binary, going from nothing to a sent bundle in
// the page. The CLI is not used on this side at all: if any step here needs
// a terminal, the front door is not a front door.
async function firstrun([base, handle, label, buddyName, subject]) {
  const wiz = '#wizard:not([hidden])';
  await page.goto(base + '/');

  // The wizard is not an empty state inside the console -- it covers it,
  // because a person who has no identity cannot do anything the console
  // offers and should not be reading about it.
  if (!(await waitFor(wiz, 'the wizard never appeared on a home with no identity'))) return;
  ok(/Welcome/.test(await text('#wizard h1')),
     'the first screen is not the welcome: ' + await text('#wizard h1'));

  await page.locator('#wizard').getByText('Get started').click();
  if (!(await waitFor('#whandle', 'the handle field never appeared'))) return;

  // A hostile handle is refused, and refused BY THE SERVER's words: the
  // page must not grow a second grammar that drifts from the one that
  // actually guards the write.
  await page.locator('#whandle').fill('../etc');
  await page.locator('#wizard').getByText('Create identity').click();
  if (await waitFor('.werror', 'a traversal handle was accepted by the page')) {
    ok(/handle is letters/.test(await text('.werror')),
       'the refusal did not say what a handle may be: ' + await text('.werror'));
  }
  // And it is still the handle screen: a refused create must not advance.
  ok(await page.locator('#whandle').count() === 1,
     'a refused handle moved the wizard on anyway');

  await page.locator('#whandle').fill(handle);
  await page.locator('#wizard').getByText('Create identity').click();
  if (!(await waitFor('.wwords', 'creating an identity from the page produced no word-pairs'))) return;

  const words = (await text('.wwords')).trim();
  console.log('WORDS ' + words.replace(/\s*\n\s*/g, ' '));
  ok(words.split('·').length === 4,
     'the words screen did not show four pairs: ' + JSON.stringify(words));
  // The one warning a new identity gets, and the pointer to the terminal
  // that is the only place a backup can be made. If the page stops saying
  // this, a stranger has no way to know the key is the only copy.
  ok(await has('gage export-identity'),
     'the words screen does not point at `gage export-identity`');
  ok(await has('lose the key, lose everything'),
     "the words screen softened the CLI's own warning about losing the key");
  // Nothing on this screen may be a passphrase prompt: export and restore
  // are terminal-only, and a form here would be the whole reason that rule
  // exists being quietly dropped.
  ok(await page.locator('#wizard input[type=password]').count() === 0,
     'the wizard asked for a passphrase, which never transits a browser form');

  await page.locator('#wizard').getByText('Continue to pairing').click();
  if (!(await waitFor('#wizard input[name=wdevice]', 'the nearby device never appeared in the wizard'))) return;
  ok(await has(label), 'the nearby list does not show the device label ' + label);

  await page.locator('#wizard input[name=wdevice]').first().check();
  if (!(await waitFor('#wizard .wwords', "the chosen device's fingerprint was not shown"))) return;
  const shown = (await text('#wizard .wwords')).trim();
  ok(shown.split('·').length === 4,
     'the device fingerprint was not four pairs: ' + JSON.stringify(shown));

  // The ceremony: the four pairs are compared aloud and said to match
  // before anything is written to the contact list. Until that is ticked
  // the pair button must not act -- this is the same moment as the CLI's
  // y/N and it is the only thing standing between a person and pairing
  // with whoever answered.
  const pairBtn = page.locator('#wizard button', { hasText: 'Pair buddy' }).first();
  ok(await pairBtn.isDisabled(),
     'the wizard would pair before the pairs were said to match aloud');
  await page.locator('#wizard input[type=checkbox]').first().check();
  await page.locator('#wname').fill(buddyName);
  try {
    await page.waitForFunction(
      () => { const b = [...document.querySelectorAll('#wizard button')]
                .find(x => /Pair buddy/.test(x.textContent || ''));
              return b && !b.disabled; }, { timeout: 5000 });
  } catch {
    failed++;
    console.log('  FAIL: confirming the comparison did not enable the pair button -- ' +
                'the ceremony cannot be completed from the page');
    return;
  }
  await pairBtn.click();

  if (!(await waitFor('#wsubject', 'pairing from the wizard never reached the send step'))) return;
  await page.locator('#wsubject').fill(subject);
  await page.locator('#wmessage').fill('first bundle, sent from the page');
  await page.locator('#wizard').getByText('Send first bundle').click();

  if (!(await waitFor('#wizard button:has-text("Open console")',
                      'sending the first bundle never reached the done step'))) {
    const e = await page.locator('.werror').count()
      ? await text('.werror') : '(no error shown)';
    console.log('        the wizard said: ' + e);
    return;
  }
  // Done hands off to the console that was always there, rather than
  // becoming a second client.
  await page.locator('#wizard').getByText('Open console').click();
  try {
    await page.waitForFunction(
      () => document.getElementById('wizard').hidden, { timeout: 5000 });
    ok(true, '');
  } catch { failed++; console.log('  FAIL: the wizard stayed up after being dismissed'); }
  ok(await page.locator('#list').count() === 1,
     'dismissing the wizard did not reveal the existing console');
}

// The other end: what the person who was sent to actually sees.
async function receive([base, subject, sender]) {
  await page.goto(base + '/');
  if (!(await waitFor('button.t', 'the bundle that arrived is not in the thread list'))) return;
  ok(await has(subject), 'the thread list does not show the subject ' + subject);
  await page.locator('button.t').first().click();
  if (!(await waitFor('.verdict', 'the message rendered with no trust verdict at all'))) return;

  // The verdict is the whole point of the page. A key on the list renders
  // as verified, in the class that is reserved for it -- and never as the
  // raw label or a milder nearby one.
  const v = (await text('.verdict')).trim();
  ok(v === 'Verified', 'the verdict reads ' + JSON.stringify(v) + ', not "Verified"');
  ok(await page.locator('.verdict.v-ok').count() === 1,
     'the verified verdict is not in the class reserved for a pass');
  ok(await page.locator('.verdict.v-warn, .verdict.v-bad').count() === 0,
     'a verified bundle also rendered a warning verdict');
  ok(await has(sender), 'the message does not name the sender as ' + sender);

  // Arriving is not accepting, and the page says so in those words.
  ok(await has('arriving is not accepting'),
     'the pending bundle did not say that arriving is not accepting');
  if (!(await waitFor('button:has-text("Accept")', 'a pending bundle offered no accept'))) return;
  await page.locator('button:has-text("Accept")').first().click();
  try {
    await page.waitForFunction(
      () => !![...document.querySelectorAll('.cmd')]
              .find(x => /gage open/.test(x.textContent || '')),
      { timeout: 10000 });
    ok(true, '');
  } catch { failed++; console.log('  FAIL: accepting from the page never staged the bundle'); }
  // And accepting does not change the verdict: it is about the key, not
  // about what this machine decided to do with the bundle.
  ok((await text('.verdict')).trim() === 'Verified',
     'accepting the bundle changed its verdict');
}

const SCENARIOS = { buddies, firstrun, receive };

try {
  const run = SCENARIOS[mode];
  if (!run) throw new Error('no scenario called ' + JSON.stringify(mode));
  await run(args);
  ok(errors.length === 0, 'the page threw: ' + errors.join(' | '));
} catch (e) {
  failed++;
  console.log('  FAIL: the run itself broke: ' + (e && e.message ? e.message : e));
} finally {
  await browser.close();
}
console.log(failed ? `ui-e2e ${mode}: ${failed} failed` : `ui-e2e ${mode}: ok`);
process.exit(failed ? 1 : 0);
