// Projde webové rozhraní v headless prohlížeči: od prvního přihlášení
// jednorázovým tokenem až po vytvoření uživatele a zásady.
import fs from 'node:fs';

// Playwright může být nainstalovaný v projektu i globálně.
let chromium;
try {
  ({ chromium } = await import('playwright'));
} catch {
  try {
    const modul = await import('/opt/node-tools/node_modules/playwright/index.js');
    chromium = modul.chromium ?? modul.default?.chromium;
  } catch {
    console.error('Playwright není nainstalovaný:');
    console.error('  npm install -g playwright && npx playwright install chromium');
    process.exit(2);
  }
}

const DATA = process.argv[2];
const VEN = process.argv[3];
const ZAKLAD = 'http://127.0.0.1:8080';
const HESLO = 'Spravce-Heslo1';

let proslo = 0; let spadlo = 0;
const ok = (t) => { proslo++; console.log('  OK   ' + t); };
const chyba = (t) => { spadlo++; console.log(' FAIL  ' + t); };
const tvrd = (podminka, t) => (podminka ? ok(t) : chyba(t));

const prohlizec = await chromium.launch({ args: ['--no-sandbox'] });
const kontext = await prohlizec.newContext({ viewport: { width: 1440, height: 900 } });
const stranka = await kontext.newPage();

const chybyKonzole = [];
stranka.on('console', (m) => {
  if (m.type() !== 'error') return;
  // Neúspěšné odpovědi vyvolává test schválně (401 před přihlášením,
  // 403 u pokusu bez CSRF). Prohlížeč je hlásí do konzole, ale chyba
  // aplikace to není — zajímají nás výjimky v JavaScriptu.
  if (m.text().startsWith('Failed to load resource')) return;
  chybyKonzole.push(m.text());
});
stranka.on('pageerror', (e) => chybyKonzole.push('pageerror: ' + e.message));
const neuspesne = [];
stranka.on('response', (r) => {
  if (r.status() >= 500) neuspesne.push(`${r.status()} ${r.url()}`);
});

/** Počká, až se vykreslí stránka s daným nadpisem. Bez toho bychom
 *  četli ještě předchozí nástroj — oba mají stejné třídy. */
const pockejNaStranku = async (nadpis) => {
  await stranka.waitForFunction(
    (t) => document.querySelector('main h2.nadpis-stranky')?.textContent === t,
    nadpis, { timeout: 15000 });
};

const snimek = async (jmeno) => {
  await stranka.screenshot({ path: `${VEN}/${jmeno}.png`, fullPage: false });
};

try {
  // ---------- 1. přihlašovací obrazovka ----------
  console.log('\n== Přihlášení jednorázovým tokenem ==');
  await stranka.goto(ZAKLAD, { waitUntil: 'networkidle' });
  tvrd(await stranka.locator('#prihlaseni').isVisible(), 'přihlašovací obrazovka se zobrazila');
  tvrd((await stranka.title()).includes('Správce serveru'), 'titulek stránky');
  const podtitul = await stranka.locator('#prihlaseni-podtitul').textContent();
  tvrd(podtitul.includes('není řadičem'), 'podtitul hlásí, že doména není');
  tvrd(await stranka.locator('#pole-token').isVisible(),
    'nabídl se rovnou jednorázový token');
  await snimek('01-prihlaseni');

  const token = fs.readFileSync(`${DATA}/setup-token.txt`, 'utf8').trim();
  await stranka.fill('#prihlaseni-token', 'spatny-token');
  await stranka.click('#prihlaseni-tlacitko');
  await stranka.waitForSelector('#prihlaseni-chyba:not(.skryto)');
  ok('špatný token hlásí chybu a nepustí dál');

  await stranka.fill('#prihlaseni-token', token);
  await stranka.click('#prihlaseni-tlacitko');
  await stranka.waitForSelector('#aplikace:not(.skryto)');
  ok('přihlášení tokenem prošlo');

  // ---------- 2. přehled ----------
  console.log('\n== Přehled ==');
  await stranka.waitForSelector('.vitejte');
  tvrd(await stranka.locator('.vitejte h3').textContent() === 'Vítá vás Správce serveru',
    'uvítací panel');
  tvrd((await stranka.locator('.rychly-start button').count()) >= 5,
    'číslovaný rychlý start');
  tvrd(await stranka.locator('#odznak-upozorneni').isVisible(), 'odznak s počtem upozornění');
  const upozorneni = await stranka.locator('main .upozorneni .nazev').first().textContent();
  tvrd(upozorneni.includes('role'), 'upozornění vyzývá k přidání rolí');
  tvrd((await stranka.locator('.dlazdice-role').count()) === 4, 'dlaždice rolí');
  await snimek('02-prehled-cisty');

  // vlaječka s upozorněními
  await stranka.click('#tlacitko-upozorneni');
  await stranka.waitForSelector('.nabidka');
  tvrd((await stranka.locator('.nabidka .upozorneni').count()) >= 1, 'nabídka upozornění');
  await snimek('03-upozorneni');
  await stranka.keyboard.press('Escape');
  await stranka.click('main', { position: { x: 5, y: 5 } });

  // ---------- 3. průvodce Přidat role a funkce ----------
  console.log('\n== Průvodce Přidat role a funkce ==');
  await stranka.click('#tlacitko-spravovat');
  await stranka.locator('.nabidka button', { hasText: 'Přidat role a funkce' }).click();
  await stranka.waitForSelector('.pruvodce');
  tvrd((await stranka.locator('.pruvodce-kroky div').count()) === 6, 'průvodce má šest kroků');
  tvrd(await stranka.locator('.pruvodce-hlavicka h3').textContent() === 'Před zahájením',
    'první krok je Před zahájením');
  await snimek('04-pruvodce-role-1');

  for (const krok of ['Typ instalace', 'Výběr serveru', 'Role serveru']) {
    await stranka.locator('.radek-tlacitek button', { hasText: 'Další' }).click();
    await stranka.waitForFunction(
      (t) => document.querySelector('.pruvodce-hlavicka h3')?.textContent === t, krok);
  }
  ok('proklikání na krok Role serveru');
  tvrd((await stranka.locator('.pruvodce-obsah input[type=checkbox]').count()) === 2,
    'dvě role na výběr');
  await stranka.locator('.pruvodce-obsah input[type=checkbox]').nth(0).check();
  await stranka.locator('.pruvodce-obsah input[type=checkbox]').nth(1).check();
  await snimek('05-pruvodce-role-vyber');

  await stranka.locator('.radek-tlacitek button', { hasText: 'Další' }).click();
  await stranka.waitForFunction(
    () => document.querySelector('.pruvodce-hlavicka h3')?.textContent === 'Potvrzení');
  const instalovat = stranka.locator('.radek-tlacitek button', { hasText: 'Instalovat' });
  tvrd(await instalovat.isDisabled(), 'bez souhlasu je Instalovat zakázané');
  await stranka.locator('.pruvodce-obsah input[type=checkbox]').last().check();
  tvrd(!(await instalovat.isDisabled()), 'po souhlasu se Instalovat povolí');
  await snimek('06-pruvodce-role-potvrzeni');
  await instalovat.click();
  await stranka.waitForFunction(
    () => document.querySelector('.pruvodce-hlavicka h3')?.textContent === 'Výsledky');
  ok('role nainstalované');
  tvrd((await stranka.locator('.pruvodce-obsah').textContent()).includes('Povýšit server'),
    'výsledek nabízí povýšení na řadič domény');
  await snimek('07-pruvodce-role-vysledek');

  // ---------- 4. konfigurační průvodce ----------
  console.log('\n== Konfigurační průvodce (povýšení) ==');
  await stranka.locator('.pruvodce-obsah button', { hasText: 'Otevřít průvodce' }).click();
  await stranka.waitForSelector('.pruvodce');
  tvrd((await stranka.locator('.pruvodce-kroky div').count()) === 6,
    'konfigurační průvodce má šest kroků');
  await snimek('08-povyseni-1');

  const nazevKroku = () => stranka.locator('.pruvodce-hlavicka h3').textContent();
  const dalsi = () => stranka.locator('.radek-tlacitek button', { hasText: 'Další' }).click();

  // krok 1: jméno domény — nejdřív naschvál .local
  await stranka.fill('#pole-domena', 'skola.local');
  await dalsi();
  tvrd(await nazevKroku() === 'Konfigurace nasazení',
    'doménu .local průvodce nepustí dál (kontroluje to už prohlížeč)');
  await stranka.fill('#pole-domena', 'skola');
  await dalsi();
  tvrd(await nazevKroku() === 'Konfigurace nasazení', 'jednoslovné jméno neprojde');
  await stranka.fill('#pole-domena', 'škola.internal');
  await dalsi();
  tvrd(await nazevKroku() === 'Konfigurace nasazení', 'diakritika ve jménu neprojde');

  await stranka.fill('#pole-domena', 'skola.internal');
  await dalsi();
  await stranka.waitForFunction(
    () => document.querySelector('.pruvodce-hlavicka h3')?.textContent === 'Možnosti řadiče domény');
  ok('krok Možnosti řadiče domény');

  // krátké heslo a neshoda hesel nesmí projít
  await stranka.fill('#pole-hostname', 'DC01');
  await stranka.fill('#pole-ip', '127.0.0.1');
  await stranka.fill('#pole-heslo', 'kratke');
  await stranka.fill('#pole-heslo2', 'kratke');
  await dalsi();
  tvrd(await nazevKroku() === 'Možnosti řadiče domény', 'krátké heslo průvodce nepustí dál');

  await stranka.fill('#pole-heslo', HESLO);
  await stranka.fill('#pole-heslo2', 'jine');
  await dalsi();
  tvrd(await nazevKroku() === 'Možnosti řadiče domény', 'neshodná hesla průvodce nepustí dál');

  await stranka.fill('#pole-ip', '300.1.2.3');
  await stranka.fill('#pole-heslo2', HESLO);
  await dalsi();
  tvrd(await nazevKroku() === 'Možnosti řadiče domény', 'nesmyslná IP adresa neprojde');

  await stranka.fill('#pole-ip', '127.0.0.1');
  await snimek('09-povyseni-radic');
  await dalsi();

  await stranka.waitForFunction(
    () => document.querySelector('.pruvodce-hlavicka h3')?.textContent === 'Možnosti DNS');
  await stranka.fill('#pole-forwardery', '1.1.1.1');
  await snimek('10-povyseni-dns');
  await dalsi();

  await stranka.waitForFunction(
    () => document.querySelector('.pruvodce-hlavicka h3')?.textContent === 'Zkontrolovat možnosti');
  tvrd((await stranka.locator('.souhrn').textContent()).includes('skola.internal'),
    'souhrn ukazuje jméno domény');
  await snimek('11-povyseni-souhrn');
  await dalsi();

  await stranka.waitForFunction(
    () => document.querySelector('.pruvodce-hlavicka h3')?.textContent === 'Kontrola předpokladů');
  const kontroly = await stranka.locator('.seznam-kontrol li').count();
  tvrd(kontroly >= 10, `kontrola předpokladů vypsala ${kontroly} položek`);
  tvrd((await stranka.locator('.znak.pass').count()) >= 8, 'většina kontrol prošla');
  await snimek('12-povyseni-kontrola');

  const nainstalovat = stranka.locator('.radek-tlacitek button', { hasText: 'Nainstalovat' });
  tvrd(!(await nainstalovat.isDisabled()), 'Nainstalovat je povolené');
  await nainstalovat.click();
  await stranka.waitForFunction(
    () => document.querySelector('.pruvodce-hlavicka h3')?.textContent === 'Výsledky',
    null, { timeout: 30000 });
  ok('doména vytvořena průvodcem');
  const vysledek = await stranka.locator('.pruvodce-obsah').textContent();
  tvrd(vysledek.includes('skola.internal'), 'výsledek ukazuje doménu');
  tvrd(vysledek.includes('dc01.skola.internal'), 'výsledek ukazuje řadič');
  tvrd(/[0-9A-F]{2}:[0-9A-F]{2}/.test(vysledek), 'výsledek ukazuje otisk CA');
  await snimek('13-povyseni-vysledek');

  // ---------- 5. přihlášení doménovým účtem ----------
  console.log('\n== Přihlášení doménového správce ==');
  await stranka.goto(ZAKLAD, { waitUntil: 'networkidle' });
  await stranka.waitForSelector('#prihlaseni:not(.skryto)');
  const podtitul2 = await stranka.locator('#prihlaseni-podtitul').textContent();
  tvrd(podtitul2.includes('skola.internal'), 'přihlašovací obrazovka zná doménu');
  await stranka.locator('#prepinac-rezimu button', { hasText: 'Doménový účet' }).click();
  await stranka.fill('#prihlaseni-jmeno', 'administrator');
  await stranka.fill('#prihlaseni-heslo', HESLO);
  await stranka.click('#prihlaseni-tlacitko');
  await stranka.waitForSelector('#aplikace:not(.skryto)');
  ok('správce přihlášen');
  await stranka.waitForSelector('.dlazdice-role');
  tvrd((await stranka.locator('.navigace button').count()) >= 5,
    'navigace má položky pro role a zásady');
  await snimek('14-prehled-domena');

  // obnovení stránky nesmí vyhodit z přihlášení
  await stranka.reload({ waitUntil: 'networkidle' });
  await stranka.waitForSelector('#aplikace:not(.skryto)', { timeout: 10000 });
  ok('po obnovení stránky zůstáváme přihlášení (CSRF token se obnoví z /me)');

  // ---------- 6. místní server ----------
  console.log('\n== Místní server ==');
  await stranka.locator('.navigace button', { hasText: 'Místní server' }).click();
  await pockejNaStranku('Místní server');
  const mistni = await stranka.locator('main').textContent();
  tvrd(mistni.includes('skola.internal'), 'vlastnosti ukazují doménu');
  tvrd(mistni.includes('ad-client join'), 'je tu hotový příkaz pro klienta s otiskem');
  await snimek('15-mistni-server');

  // ---------- 7. Uživatelé a počítače ----------
  console.log('\n== Uživatelé a počítače ==');
  await stranka.click('#tlacitko-nastroje');
  await stranka.locator('.nabidka button', { hasText: 'Uživatelé a počítače' }).click();
  await pockejNaStranku('Uživatelé a počítače');
  await stranka.waitForSelector('.levy-panel .strom button');
  tvrd((await stranka.locator('.levy-panel .strom button').count()) >= 4,
    'strom vlevo obsahuje doménu a výchozí OU');
  await snimek('16-uzivatele-strom');

  // nová OU
  await stranka.locator('.panel-nastroju button', { hasText: 'Nová OU' }).click();
  await stranka.waitForSelector('.dialog');
  await stranka.locator('.dialog input[type=text]').first().fill('Zaci');
  await stranka.locator('.dialog input[type=text]').nth(1).fill('Žáci školy');
  await snimek('17-nova-ou');
  await stranka.locator('.dialog button', { hasText: 'Vytvořit' }).click();
  await stranka.waitForSelector('.dialog', { state: 'detached' });
  await stranka.waitForFunction(() =>
    [...document.querySelectorAll('.levy-panel .strom button')]
      .some((b) => b.textContent.includes('Zaci')));
  ok('organizační jednotka vytvořená');

  // vybereme OU Zaci a vytvoříme uživatele
  await stranka.locator('.levy-panel .strom button', { hasText: 'Zaci' }).click();
  await stranka.locator('.panel-nastroju button', { hasText: 'Nový uživatel' }).click();
  await stranka.waitForSelector('.dialog');
  await stranka.locator('.dialog input[type=text]').nth(0).fill('Jan');
  await stranka.locator('.dialog input[type=text]').nth(1).fill('Novák');
  const navrh = await stranka.locator('.dialog input[type=text]').nth(2).inputValue();
  tvrd(navrh === 'jan.novak', `přihlašovací jméno se navrhlo bez diakritiky (${navrh})`);

  // slabé heslo musí server odmítnout
  await stranka.locator('.dialog input[type=password]').fill('heslo');
  await stranka.locator('.dialog button', { hasText: 'Vytvořit' }).click();
  await stranka.waitForSelector('#hlaseni .chyba');
  const chybaHesla = await stranka.locator('#hlaseni .chyba').textContent();
  tvrd(chybaHesla.includes('zásad'), 'slabé heslo odmítnuto se seznamem pravidel');
  await snimek('18-slabe-heslo');

  await stranka.locator('.dialog input[type=password]').fill('Zak-Heslo-2026');
  await snimek('19-novy-uzivatel');
  await stranka.locator('.dialog button', { hasText: 'Vytvořit' }).click();
  await stranka.waitForSelector('.dialog', { state: 'detached' });
  await stranka.waitForFunction(() =>
    document.querySelector('.pravy-panel table.seznam tbody')?.textContent.includes('jan.novak'));
  ok('uživatel vytvořený ve vybrané OU');

  // detail uživatele
  await stranka.locator('.pravy-panel tbody tr', { hasText: 'jan.novak' }).click();
  await stranka.waitForSelector('.detail-panel dl.vlastnosti');
  const detail = await stranka.locator('.detail-panel').textContent();
  tvrd(detail.includes('jan.novak@skola.internal'), 'detail ukazuje UPN');
  tvrd(!detail.toLowerCase().includes('hash'), 'detail neukazuje nic o hashi hesla');
  await snimek('20-detail-uzivatele');

  // nová skupina a členství
  await stranka.locator('.panel-nastroju button', { hasText: 'Nová skupina' }).click();
  await stranka.waitForSelector('.dialog');
  await stranka.locator('.dialog input[type=text]').first().fill('Žáci 1.A');
  await stranka.locator('.dialog button', { hasText: 'Vytvořit' }).click();
  await stranka.waitForSelector('.dialog', { state: 'detached' });
  await stranka.waitForFunction(() =>
    document.querySelector('.pravy-panel table.seznam tbody')?.textContent.includes('Žáci 1.A'));
  ok('skupina vytvořená');

  await stranka.locator('.pravy-panel tbody tr', { hasText: 'jan.novak' }).click();
  await stranka.locator('.panel-nastroju button', { hasText: 'Členství' }).click();
  await stranka.waitForSelector('.dialog');
  await stranka.locator('.dialog tbody tr', { hasText: 'Žáci 1.A' })
    .locator('button', { hasText: 'přidat' }).click();
  await stranka.waitForFunction(() => {
    const tr = [...document.querySelectorAll('.dialog tbody tr')]
      .find((r) => r.textContent.includes('Žáci 1.A'));
    return tr && tr.textContent.includes('je členem');
  });
  ok('členství přidáno');
  await snimek('21-clenstvi');
  await stranka.keyboard.press('Escape');

  // ---------- 8. Správce DNS ----------
  console.log('\n== Správce DNS ==');
  await stranka.click('#tlacitko-nastroje');
  await stranka.locator('.nabidka button', { hasText: 'Správce DNS' }).click();
  await pockejNaStranku('Správce DNS');
  await stranka.waitForFunction(() =>
    document.querySelector('.pravy-panel table.seznam tbody tr'));
  const dnsStrom = await stranka.locator('.levy-panel').textContent();
  tvrd(dnsStrom.includes('Dopředné zóny') && dnsStrom.includes('Reverzní zóny'),
    'strom má dopředné i reverzní zóny');
  tvrd(dnsStrom.includes('skola.internal'), 'dopředná zóna domény');
  tvrd(dnsStrom.includes('in-addr.arpa'), 'reverzní zóna');
  const zaznamy = await stranka.locator('.pravy-panel').textContent();
  tvrd(zaznamy.includes('_ad._tcp'), 'SRV záznam služby je v seznamu');
  tvrd(zaznamy.includes('spravovaný'), 'záznamy řadiče jsou označené jako spravované');
  await snimek('22-dns');

  // nový záznam
  await stranka.locator('.panel-nastroju button', { hasText: 'Nový záznam' }).click();
  await stranka.waitForSelector('.dialog');
  await stranka.locator('.dialog input.mono').first().fill('tiskarna');
  await stranka.locator('.dialog input.mono').last().fill('192.168.56.50');
  await snimek('23-novy-zaznam');
  await stranka.locator('.dialog button', { hasText: 'Vytvořit' }).click();
  await stranka.waitForSelector('.dialog', { state: 'detached' });
  await stranka.waitForFunction(() =>
    document.querySelector('.pravy-panel table.seznam')?.textContent.includes('tiskarna'));
  ok('DNS záznam vytvořený');

  // ---------- 9. Zásady skupiny ----------
  console.log('\n== Správa zásad skupiny ==');
  await stranka.click('#tlacitko-nastroje');
  await stranka.locator('.nabidka button', { hasText: 'Správa zásad skupiny' }).click();
  await pockejNaStranku('Správa zásad skupiny');
  await stranka.locator('.panel-nastroju button', { hasText: 'Nová zásada' }).click();
  await stranka.waitForSelector('.dialog');
  await stranka.locator('.dialog input[type=text]').first().fill('Silná hesla pro žáky');
  // zapneme skupinu Pravidla hesel a nastavíme délku 12
  await stranka.locator('.dialog .panel h3 input[type=checkbox]').first().check();
  await stranka.locator('.dialog input[type=number]').first().fill('12');
  // uvítací zpráva
  const zatrzitka = stranka.locator('.dialog .panel h3 input[type=checkbox]');
  await zatrzitka.nth(2).check();
  await stranka.locator('.dialog .panel').nth(2).locator('input[type=text]').fill('Vítej ve škole');
  await stranka.locator('.dialog textarea').fill('Tohle je školní počítač.');
  await snimek('24-nova-zasada');
  await stranka.locator('.dialog button', { hasText: 'Vytvořit' }).click();
  await stranka.waitForSelector('.dialog', { state: 'detached' });
  await stranka.waitForFunction(() =>
    document.querySelector('.levy-panel')?.textContent.includes('Silná hesla'));
  ok('zásada vytvořená');
  const obsahZasady = await stranka.locator('.pravy-panel').textContent();
  tvrd(obsahZasady.includes('nejméně 12 znaků'), 'přehled zásady ukazuje pravidla');
  tvrd(obsahZasady.includes('není nikam připojená'), 'upozorní, že zásada nikam nemíří');
  await snimek('25-zasada-detail');

  // připojíme na OU Zaci
  await stranka.locator('.pravy-panel button', { hasText: 'Připojit k' }).click();
  await stranka.waitForSelector('.dialog');
  await stranka.locator('.dialog select').selectOption({ label: 'OU /Zaci' });
  await stranka.locator('.dialog button', { hasText: 'Připojit' }).click();
  await stranka.waitForSelector('.dialog', { state: 'detached' });
  await stranka.waitForFunction(() =>
    document.querySelector('.pravy-panel')?.textContent.includes('/Zaci'));
  ok('zásada připojená k OU');

  // výsledná sada zásad
  const vyberOu = stranka.locator('.pravy-panel select').last();
  await vyberOu.selectOption({ label: '/Zaci' });
  await stranka.waitForFunction(() =>
    document.querySelector('.pravy-panel')?.textContent.includes('Použité zásady'));
  const rsop = await stranka.locator('.pravy-panel').textContent();
  tvrd(rsop.includes('Silná hesla pro žáky'), 'výsledná sada zásad jmenuje použitou zásadu');
  await snimek('26-vysledne-zasady');

  // ---------- 10. auditní log ----------
  console.log('\n== Auditní log ==');
  await stranka.locator('.navigace button', { hasText: 'Auditní log' }).click();
  await pockejNaStranku('Auditní log');
  await stranka.waitForFunction(() =>
    document.querySelector('main table.seznam tbody tr td')?.textContent.includes('.'));
  const audit = await stranka.locator('main').textContent();
  for (const akce of ['domain.promote', 'user.create', 'ou.create', 'gpo.create']) {
    tvrd(audit.includes(akce), `audit obsahuje ${akce}`);
  }
  tvrd(!audit.includes(HESLO), 'v auditu není heslo');
  await snimek('27-audit');

  // ---------- 11. bezpečnostní kontroly v prohlížeči ----------
  console.log('\n== Bezpečnost v prohlížeči ==');
  const hlavicky = (await stranka.goto(ZAKLAD)).headers();
  tvrd((hlavicky['content-security-policy'] || '').includes("default-src 'self'"),
    'hlavička Content-Security-Policy');
  tvrd(!(hlavicky['content-security-policy'] || '').includes('unsafe-inline'),
    'CSP nepovoluje inline skripty');
  tvrd(hlavicky['x-frame-options'] === 'DENY', 'hlavička X-Frame-Options');
  tvrd(hlavicky['x-content-type-options'] === 'nosniff', 'hlavička X-Content-Type-Options');

  const csrfPokus = await stranka.evaluate(async () => {
    const r = await fetch('/admin/api/v1/ous', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'BezCsrf' }),
      credentials: 'same-origin',
    });
    return r.status;
  });
  tvrd(csrfPokus === 403, `požadavek bez CSRF hlavičky odmítnut (${csrfPokus})`);

  const cookieViditelna = await stranka.evaluate(() => document.cookie);
  tvrd(!cookieViditelna.includes('ad_admin_session'),
    'session cookie není vidět ze skriptu (HttpOnly)');

  // odhlášení
  await stranka.waitForSelector('#aplikace:not(.skryto)');
  await stranka.click('#tlacitko-spravovat');
  await stranka.locator('.nabidka button', { hasText: 'Odhlásit' }).click();
  await stranka.waitForSelector('#prihlaseni:not(.skryto)');
  ok('odhlášení funguje');

  // ---------- 12. chyby v konzoli ----------
  console.log('\n== Konzole prohlížeče ==');
  if (chybyKonzole.length === 0) ok('žádná chyba v konzoli prohlížeče');
  else {
    chyba('chyby v konzoli: ' + chybyKonzole.slice(0, 5).join(' | '));
  }
  if (neuspesne.length === 0) ok('žádná odpověď 5xx ze serveru');
  else chyba('odpovědi 5xx: ' + neuspesne.slice(0, 5).join(' | '));
} catch (e) {
  chyba('výjimka: ' + e.message);
  await snimek('99-chyba');
  console.log(e.stack?.split('\n').slice(0, 6).join('\n'));
} finally {
  await prohlizec.close();
}

console.log(`\n==================================================`);
console.log(`Prošlo: ${proslo}   Spadlo: ${spadlo}`);
console.log(`Snímky: ${VEN}`);
console.log(`==================================================`);
process.exit(spadlo === 0 ? 0 : 1);
