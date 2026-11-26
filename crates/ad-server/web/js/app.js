// Vstupní bod rozhraní: přihlášení, rám aplikace, navigace, směrování.

import { api, dialog, dotaz, el, hlas, hlasChybu, ikona, nahrad, stav, udalosti }
  from './jadro.js';
import * as pohledy from './pohledy.js';
import * as nastroje from './nastroje.js';

// --------------------------------------------------------------- trasy

const TRASY = {
  '/prehled': { nazev: 'Přehled', vykresli: pohledy.prehled },
  '/server': { nazev: 'Místní server', vykresli: pohledy.mistniServer },
  '/role': { nazev: 'Přidat role a funkce', vykresli: pohledy.pruvodceRole },
  '/povyseni': { nazev: 'Konfigurace doménových služeb', vykresli: pohledy.pruvodcePovyseni },
  '/audit': { nazev: 'Auditní log', vykresli: pohledy.audit },
  '/uzivatele': { nazev: 'Uživatelé a počítače', vykresli: nastroje.uzivateleAPocitace },
  '/dns': { nazev: 'Správce DNS', vykresli: nastroje.spravceDns },
  '/zasady': { nazev: 'Správa zásad skupiny', vykresli: nastroje.spravaZasad },
};

// --------------------------------------------------------- přihlášení

let rezimPrihlaseni = 'password';

async function start() {
  try {
    stav.hello = await api('/hello');
  } catch (e) {
    hlasChybu(e);
    return;
  }
  document.title = `Správce serveru — ${stav.hello.domain_dns_name || 'nenastaveno'}`;

  // Když je server čistý a token ještě platí, nabídneme ho jako první.
  if (!stav.hello.domain_dns_name && stav.hello.setup_token_active) {
    rezimPrihlaseni = 'setup_token';
  }
  pripravPrihlaseni();

  // Po obnovení stránky cookie pořád platí — z /me si vezmeme i CSRF
  // token, který v paměti prohlížeče po obnovení nezůstal.
  try {
    const session = await api('/me');
    stav.principal = session.principal;
    stav.csrf = session.csrf_token;
    await poPrihlaseni();
  } catch {
    zobrazPrihlaseni();
  }
}

function pripravPrihlaseni() {
  const podtitul = dotaz('#prihlaseni-podtitul');
  if (stav.hello.domain_dns_name) {
    podtitul.textContent =
      `${stav.hello.domain_dns_name} — přihlas se účtem ve skupině Domain Admins`;
  } else {
    podtitul.textContent =
      'Server ještě není řadičem domény. Přihlas se jednorázovým tokenem z konzole.';
  }

  for (const tl of document.querySelectorAll('#prepinac-rezimu button')) {
    tl.addEventListener('click', () => nastavRezim(tl.dataset.rezim));
  }
  nastavRezim(rezimPrihlaseni);

  dotaz('#prihlaseni-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    await prihlas();
  });
}

function nastavRezim(rezim) {
  rezimPrihlaseni = rezim;
  for (const tl of document.querySelectorAll('#prepinac-rezimu button')) {
    tl.classList.toggle('aktivni', tl.dataset.rezim === rezim);
  }
  dotaz('#pole-password').classList.toggle('skryto', rezim !== 'password');
  dotaz('#pole-token').classList.toggle('skryto', rezim !== 'setup_token');
  const pole = rezim === 'password' ? '#prihlaseni-jmeno' : '#prihlaseni-token';
  setTimeout(() => dotaz(pole).focus(), 0);
}

async function prihlas() {
  const chyba = dotaz('#prihlaseni-chyba');
  const tlacitko = dotaz('#prihlaseni-tlacitko');
  chyba.classList.add('skryto');
  tlacitko.disabled = true;

  const telo = rezimPrihlaseni === 'setup_token'
    ? { method: 'setup_token', token: dotaz('#prihlaseni-token').value.trim() }
    : {
        method: 'password',
        username: dotaz('#prihlaseni-jmeno').value.trim() || 'administrator',
        password: dotaz('#prihlaseni-heslo').value,
      };

  try {
    const odpoved = await api('/session', { metoda: 'POST', telo });
    stav.csrf = odpoved.csrf_token;
    stav.principal = odpoved.principal;
    dotaz('#prihlaseni-heslo').value = '';
    dotaz('#prihlaseni-token').value = '';
    await poPrihlaseni();
  } catch (e) {
    dotaz('#prihlaseni-chyba-text').textContent = e.message;
    chyba.classList.remove('skryto');
  } finally {
    tlacitko.disabled = false;
  }
}

function zobrazPrihlaseni() {
  dotaz('#aplikace').classList.add('skryto');
  dotaz('#prihlaseni').classList.remove('skryto');
}

udalosti.odhlaseno = () => {
  stav.csrf = null;
  stav.principal = null;
  zobrazPrihlaseni();
};

async function poPrihlaseni() {
  // CSRF token držíme jen v paměti stránky, nikdy v localStorage —
  // tam by ho mohl přečíst jiný skript na stejném původu.
  if (!stav.csrf) {
    zobrazPrihlaseni();
    return;
  }
  dotaz('#prihlaseni').classList.add('skryto');
  dotaz('#aplikace').classList.remove('skryto');
  pripravRam();
  stav.hello = await api('/hello').catch(() => stav.hello);
  await vykresli();
}

// ------------------------------------------------------------- rám

let ramPripraven = false;

function pripravRam() {
  if (ramPripraven) return;
  ramPripraven = true;

  dotaz('#tlacitko-obnovit').addEventListener('click', () => obnov());
  dotaz('#tlacitko-upozorneni').addEventListener('click', (e) => {
    e.stopPropagation();
    nabidkaUpozorneni();
  });
  dotaz('#tlacitko-spravovat').addEventListener('click', (e) => {
    e.stopPropagation();
    nabidkaSpravovat();
  });
  dotaz('#tlacitko-nastroje').addEventListener('click', (e) => {
    e.stopPropagation();
    nabidkaNastroje();
  });

  document.addEventListener('click', zavriNabidky);
  window.addEventListener('hashchange', () => vykresli());
  document.addEventListener('keydown', (e) => {
    if (e.key === 'F5') { e.preventDefault(); obnov(); }
  });
}

/**
 * Načte stav serveru. Děláme to před každým vykreslením stránky:
 * průvodci stav mění (nainstalují role, vytvoří doménu) a navazující
 * stránka musí vidět, co je teď — ne co bylo při přihlášení.
 */
async function nactiStav() {
  stav.status = await api('/status');
  vykresliNavigaci();
  vykresliOdznak();
}

/** Znovu načte stav serveru a překreslí stránku. */
export async function obnov() {
  await vykresli();
}

function vykresliNavigaci() {
  const nav = dotaz('#navigace');
  const cesta = aktualniCesta();
  const polozky = [
    { cesta: '/prehled', nazev: 'Přehled', ikonka: 'prehled' },
    { cesta: '/server', nazev: 'Místní server', ikonka: 'server' },
  ];
  const skupinaRoli = [];
  if (stav.status?.roles.directory) {
    skupinaRoli.push({ cesta: '/uzivatele', nazev: 'Doménové služby', ikonka: 'domena' });
  }
  if (stav.status?.roles.dns) {
    skupinaRoli.push({ cesta: '/dns', nazev: 'DNS', ikonka: 'dns' });
  }
  if (stav.status?.stage === 'domain_controller') {
    skupinaRoli.push({ cesta: '/zasady', nazev: 'Zásady skupiny', ikonka: 'zasada' });
  }

  const tlacitko = (p) => el('button', {
    class: cesta === p.cesta ? 'aktivni' : '',
    type: 'button',
    on: { click: () => { location.hash = '#' + p.cesta; } },
  }, ikona(p.ikonka), el('span', { class: 'text-navigace', text: p.nazev }));

  nahrad(nav,
    polozky.map(tlacitko),
    skupinaRoli.length
      ? [el('div', { class: 'skupina-navigace', text: 'Role a funkce' }), skupinaRoli.map(tlacitko)]
      : null,
    el('div', { class: 'skupina-navigace', text: 'Záznamy' }),
    tlacitko({ cesta: '/audit', nazev: 'Auditní log', ikonka: 'log' }));
}

function vykresliOdznak() {
  const odznak = dotaz('#odznak-upozorneni');
  const pocet = stav.status?.alerts?.length || 0;
  odznak.textContent = String(pocet);
  odznak.classList.toggle('skryto', pocet === 0);
}

// ----------------------------------------------------------- nabídky

function zavriNabidky() {
  for (const n of document.querySelectorAll('.nabidka')) n.remove();
  for (const t of document.querySelectorAll('.hlavicka-tlacitko[aria-expanded]')) {
    t.setAttribute('aria-expanded', 'false');
  }
}

function otevriNabidku(tlacitko, obsah) {
  const bylaOtevrena = tlacitko.getAttribute('aria-expanded') === 'true';
  zavriNabidky();
  if (bylaOtevrena) return;
  tlacitko.setAttribute('aria-expanded', 'true');
  const nabidka = el('div', { class: 'nabidka' }, obsah);
  nabidka.addEventListener('click', (e) => e.stopPropagation());
  dotaz('.hlavicka').append(nabidka);
}

function polozkaNabidky(text, akce) {
  return el('button', { type: 'button', text, on: { click: () => { zavriNabidky(); akce(); } } });
}

function nabidkaUpozorneni() {
  const alerts = stav.status?.alerts || [];
  const obsah = [el('div', { class: 'hlavicka-nabidky', text: 'Upozornění' })];
  if (alerts.length === 0) {
    obsah.push(el('div', { class: 'maly slabe', text: 'Nic, co by potřebovalo pozornost.' }));
  }
  for (const a of alerts) {
    obsah.push(el('div', { class: `upozorneni ${a.level}` },
      el('div', { class: 'text' },
        el('div', { class: 'nazev', text: a.title }),
        el('div', { class: 'detail', text: a.detail }),
        a.action
          ? el('button', {
              class: 'odkaz mezera-nad', type: 'button', text: 'Otevřít',
              on: { click: () => { zavriNabidky(); location.hash = a.action; } },
            })
          : null)));
  }
  otevriNabidku(dotaz('#tlacitko-upozorneni'), obsah);
}

function nabidkaSpravovat() {
  const polozky = [
    polozkaNabidky('Přidat role a funkce', () => { location.hash = '#/role'; }),
  ];
  if (stav.status?.stage !== 'domain_controller' && stav.status?.roles.directory) {
    polozky.push(polozkaNabidky('Povýšit tento server na řadič domény',
      () => { location.hash = '#/povyseni'; }));
  }
  if (stav.status?.stage === 'domain_controller') {
    polozky.push(polozkaNabidky('Zrušit řadič domény…', zrusitRadic));
  }
  polozky.push(el('div', { class: 'oddelovac' }));
  polozky.push(polozkaNabidky('Odhlásit', odhlas));
  otevriNabidku(dotaz('#tlacitko-spravovat'), polozky);
}

function nabidkaNastroje() {
  const jeDomena = stav.status?.stage === 'domain_controller';
  const polozky = [el('div', { class: 'hlavicka-nabidky', text: 'Nástroje' })];
  const pridej = (text, cesta, povoleno = true) => {
    polozky.push(povoleno
      ? polozkaNabidky(text, () => { location.hash = '#' + cesta; })
      : el('button', { type: 'button', text, disabled: true, class: 'slabe' }));
  };
  pridej('Uživatelé a počítače', '/uzivatele', jeDomena);
  pridej('Správce DNS', '/dns', stav.status?.roles.dns);
  pridej('Správa zásad skupiny', '/zasady', jeDomena);
  polozky.push(el('div', { class: 'oddelovac' }));
  pridej('Auditní log', '/audit');
  if (!jeDomena) {
    polozky.push(el('div', { class: 'maly slabe', text: 'Nástroje domény se zpřístupní po povýšení serveru.' }));
  }
  otevriNabidku(dotaz('#tlacitko-nastroje'), polozky);
}

async function odhlas() {
  try {
    await api('/session', { metoda: 'DELETE' });
  } catch (e) {
    // I když se odhlášení nepovede, přihlašovací obrazovku ukážeme.
    hlasChybu(e);
  }
  stav.csrf = null;
  stav.principal = null;
  zobrazPrihlaseni();
}

async function zrusitRadic() {
  const jmeno = stav.status?.domain?.dns_name;
  if (!jmeno) return;
  let smazatVse = null;
  const obsah = el('div', {},
    el('p', { text: 'Zrušením řadiče zmizí doména i všechny její objekty: '
      + 'uživatelé, skupiny, počítače, zásady a DNS zóny. Smaže se i '
      + 'certifikační autorita, takže připojení klienti přestanou serveru věřit.' }),
    el('label', { class: 'zatrzitko' },
      (smazatVse = el('input', { type: 'checkbox' })),
      el('span', {}, 'Smazat i auditní log a nastavení',
        el('span', { class: 'popis', text: 'Bez zatržení audit zůstane, aby bylo vidět, co se dělo.' }))));

  const potvrzeno = await new Promise((splnit) => {
    let vstup = null;
    obsah.append(el('label', { class: 'pole mezera-nad' },
      el('span', { text: `Pro potvrzení opiš jméno domény: ${jmeno}` }),
      (vstup = el('input', { type: 'text', class: 'mono' }))));
    dialog({
      nazev: 'Zrušit řadič domény',
      obsah,
      tlacitka: [{
        text: 'Zrušit doménu',
        nebezpecne: true,
        akce: async () => {
          if (vstup.value.trim().toLowerCase() !== jmeno.toLowerCase()) {
            hlas('Jméno nesouhlasí', 'Opiš ho přesně.', 'chyba');
            return false;
          }
          await api('/demote', {
            metoda: 'POST',
            telo: { confirm_domain_name: vstup.value.trim(), wipe_database: smazatVse.checked },
          });
          splnit(true);
          return true;
        },
      }],
    });
  });

  if (potvrzeno) {
    hlas('Doména zrušena', 'Server je zpátky ve stavu před povýšením.', 'uspech');
    location.hash = '#/prehled';
    await obnov();
  }
}

// -------------------------------------------------------- směrování

export function aktualniCesta() {
  const cela = location.hash.replace(/^#/, '') || '/prehled';
  return cela.split('?')[0];
}

function parametry() {
  const cela = location.hash.replace(/^#/, '');
  const index = cela.indexOf('?');
  return new URLSearchParams(index >= 0 ? cela.slice(index + 1) : '');
}

export async function vykresli() {
  const cesta = aktualniCesta();
  const trasa = TRASY[cesta];
  const obsah = dotaz('#obsah');

  try {
    await nactiStav();
  } catch (e) {
    hlasChybu(e);
    return;
  }

  if (!trasa) {
    nahrad(obsah, el('h2', { class: 'nadpis-stranky', text: 'Taková stránka tu není' }),
      el('p', {}, el('button', {
        class: 'odkaz', type: 'button', text: 'Zpět na přehled',
        on: { click: () => { location.hash = '#/prehled'; } },
      })));
    return;
  }

  dotaz('#cesta').textContent = '• ' + trasa.nazev;
  nahrad(obsah, el('div', { class: 'nacitani', text: 'Načítám…' }));
  try {
    await trasa.vykresli(obsah, parametry(), { obnov, vykresli });
  } catch (e) {
    hlasChybu(e);
    nahrad(obsah,
      el('h2', { class: 'nadpis-stranky', text: trasa.nazev }),
      el('div', { class: 'upozorneni error' },
        el('div', { class: 'text' },
          el('div', { class: 'nazev', text: 'Stránku se nepodařilo načíst' }),
          el('div', { class: 'detail', text: e.message }),
          el('div', { class: 'maly slabe', text: e.kod || '' }))));
  }
}

start();
