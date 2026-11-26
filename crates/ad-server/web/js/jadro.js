// Jádro rozhraní: práce s DOM, volání API, dialogy, hlášení.
//
// Žádná knihovna z internetu — rozhraní musí fungovat i na serveru bez
// připojení. Hlavička Content-Security-Policy stejně nic cizího
// nepustí.
//
// Pravidlo, které se tady drží všude: do stránky se text vkládá jen
// přes textContent, nikdy přes innerHTML. Jména uživatelů, popisy
// a hlavně to, co o sobě tvrdí klient (jméno systému), jsou cizí text
// a nesmí se chovat jako HTML.

export const stav = {
  hello: null,       // nepřihlášené údaje o serveru
  principal: null,   // kdo je přihlášený
  csrf: null,        // token pro měnící požadavky
  status: null,      // poslední /status
};

// ---------------------------------------------------------------- DOM

/**
 * Vytvoří prvek. `vlastnosti` rozumí: class, id, type, title, disabled,
 * value, placeholder, checked, min, max, step, rows, data (objekt),
 * on (objekt s posluchači), text (textContent).
 */
export function el(tag, vlastnosti = {}, ...deti) {
  const prvek = document.createElement(tag);
  for (const [klic, hodnota] of Object.entries(vlastnosti)) {
    if (hodnota === null || hodnota === undefined || hodnota === false) continue;
    if (klic === 'class') prvek.className = hodnota;
    else if (klic === 'text') prvek.textContent = String(hodnota);
    else if (klic === 'html') throw new Error('html se nepoužívá, jen text');
    else if (klic === 'on') {
      for (const [udalost, funkce] of Object.entries(hodnota)) {
        prvek.addEventListener(udalost, funkce);
      }
    } else if (klic === 'data') {
      for (const [k, v] of Object.entries(hodnota)) prvek.dataset[k] = v;
    } else if (klic === 'checked' || klic === 'disabled' || klic === 'selected') {
      prvek[klic] = Boolean(hodnota);
    } else if (klic === 'value') {
      prvek.value = hodnota;
    } else {
      prvek.setAttribute(klic, hodnota);
    }
  }
  pridej(prvek, deti);
  return prvek;
}

function pridej(prvek, deti) {
  for (const dite of deti.flat(4)) {
    if (dite === null || dite === undefined || dite === false) continue;
    prvek.append(dite instanceof Node ? dite : document.createTextNode(String(dite)));
  }
}

/** Vyprázdní prvek a vloží nový obsah. */
export function nahrad(prvek, ...deti) {
  prvek.textContent = '';
  pridej(prvek, deti);
  return prvek;
}

export function dotaz(selektor) {
  return document.querySelector(selektor);
}

/** Jednoduchá SVG ikona podle jména. Kreslíme si je samy. */
export function ikona(jmeno, velka = false) {
  const cesty = {
    domena: 'M8 1 1 4.5v3C1 11.5 4 14.5 8 15.5c4-1 7-4 7-8v-3L8 1z',
    uzivatel: 'M8 2a2.8 2.8 0 1 1 0 5.6A2.8 2.8 0 0 1 8 2zm0 6.6c3 0 5.5 1.5 5.5 3.4V14H2.5v-2c0-1.9 2.5-3.4 5.5-3.4z',
    skupina: 'M5 3a2.2 2.2 0 1 1 0 4.4A2.2 2.2 0 0 1 5 3zm6 0a2.2 2.2 0 1 1 0 4.4A2.2 2.2 0 0 1 11 3zM5 8.4c2.2 0 4 1.1 4 2.5V13H1v-2.1c0-1.4 1.8-2.5 4-2.5zm6 0c2.2 0 4 1.1 4 2.5V13h-4.5v-2.1c0-.8-.4-1.5-1-2.1.5-.2 1-.4 1.5-.4z',
    pocitac: 'M2 3h12v8H2V3zm0 9h12l1 2H1l1-2z',
    ou: 'M2 3h5l1.2 1.6H14V13H2V3z',
    dns: 'M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1zm0 1.4c1 0 2 1.9 2.3 4.6H5.7C6 5.3 7 3.4 8 3.4zM4.3 7h-1.8A5.6 5.6 0 0 1 5.6 3.3C5 4.2 4.5 5.5 4.3 7zm0 2c.2 1.5.7 2.8 1.3 3.7A5.6 5.6 0 0 1 2.5 9h1.8zm1.4 0h4.6C10 11.7 9 13.6 8 13.6S6 11.7 5.7 9zm6 0h1.8a5.6 5.6 0 0 1-3.1 3.7c.6-.9 1.1-2.2 1.3-3.7zm0-2c-.2-1.5-.7-2.8-1.3-3.7A5.6 5.6 0 0 1 13.5 7h-1.8z',
    zasada: 'M8 1 2 3.4v4.2c0 3.6 2.4 6.6 6 7.4 3.6-.8 6-3.8 6-7.4V3.4L8 1zm-.8 9.8L4.6 8.2l1.1-1.1 1.5 1.5 3.1-3.1 1.1 1.1-4.2 4.2z',
    prehled: 'M2 2h5.2v5.2H2V2zm6.8 0H14v3.4H8.8V2zM2 8.8h5.2V14H2V8.8zm6.8-1.6H14V14H8.8V7.2z',
    server: 'M2 2h12v4H2V2zm0 5h12v4H2V7zm0 5h12v2H2v-2z',
    role: 'M3 2h10v3H3V2zm0 4.5h10v3H3v-3zM3 11h10v3H3v-3z',
    log: 'M3 1h7l3 3v11H3V1zm6 1v3h3L9 2zM5 7h6v1.2H5V7zm0 2.4h6v1.2H5V9.4zm0 2.4h4v1.2H5v-1.2z',
  };
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('class', velka ? 'ikona-velka' : 'ikona');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('fill', 'currentColor');
  path.setAttribute('d', cesty[jmeno] || cesty.server);
  svg.append(path);
  return svg;
}

// ---------------------------------------------------------------- API

/** Co se má stát, když vyprší přihlášení. Nastaví app.js. */
export const udalosti = { odhlaseno: () => {} };

/**
 * Zavolá správní API. Měnící metody samy přidají hlavičku x-ad-csrf.
 * Chyba se vyhodí jako `Error` s polem `.kod` (strojový kód z API).
 */
export async function api(cesta, { metoda = 'GET', telo = null } = {}) {
  const hlavicky = {};
  if (telo !== null) hlavicky['content-type'] = 'application/json';
  if (metoda !== 'GET' && stav.csrf) hlavicky['x-ad-csrf'] = stav.csrf;

  let odpoved;
  try {
    odpoved = await fetch('/admin/api/v1' + cesta, {
      method: metoda,
      headers: hlavicky,
      body: telo === null ? null : JSON.stringify(telo),
      credentials: 'same-origin',
      cache: 'no-store',
    });
  } catch {
    const chyba = new Error('Server neodpovídá. Běží ještě ad-server?');
    chyba.kod = 'bez_spojeni';
    throw chyba;
  }

  if (odpoved.status === 204) return null;

  let data = null;
  const typ = odpoved.headers.get('content-type') || '';
  if (typ.includes('application/json')) {
    try { data = await odpoved.json(); } catch { data = null; }
  }

  if (!odpoved.ok) {
    const kod = data?.error?.code || 'http_' + odpoved.status;
    const chyba = new Error(data?.error?.message || ('HTTP ' + odpoved.status));
    chyba.kod = kod;
    chyba.detaily = data?.error?.details || null;
    if (kod === 'session_expired' || kod === 'auth_required') {
      udalosti.odhlaseno();
    }
    throw chyba;
  }
  return data;
}

/**
 * Nahraje soubor. Tělo je přímo jeho obsah — žádné kódování navíc.
 * Formát rozhoduje server podle obsahu, ne podle toho, co napíšeme
 * do hlavičky.
 */
export async function apiSoubor(cesta, soubor) {
  const hlavicky = { 'content-type': soubor.type || 'application/octet-stream' };
  if (stav.csrf) hlavicky['x-ad-csrf'] = stav.csrf;
  const odpoved = await fetch('/admin/api/v1' + cesta, {
    method: 'POST',
    headers: hlavicky,
    body: soubor,
    credentials: 'same-origin',
    cache: 'no-store',
  });
  let data = null;
  try { data = await odpoved.json(); } catch { data = null; }
  if (!odpoved.ok) {
    const chyba = new Error(data?.error?.message || ('HTTP ' + odpoved.status));
    chyba.kod = data?.error?.code || 'http_' + odpoved.status;
    throw chyba;
  }
  return data;
}

// ------------------------------------------------------------ hlášení

/** Krátká zpráva v pravém dolním rohu. */
export function hlas(nazev, podrobnost = '', druh = 'info') {
  const misto = dotaz('#hlaseni');
  const box = el('div', { class: druh === 'chyba' ? 'chyba' : druh === 'uspech' ? 'uspech' : '' },
    el('div', { class: 'nazev', text: nazev }),
    podrobnost ? el('div', { text: podrobnost }) : null,
  );
  misto.append(box);
  const odstran = () => box.remove();
  box.addEventListener('click', odstran);
  setTimeout(odstran, druh === 'chyba' ? 9000 : 4500);
}

/** Zobrazí chybu z API tak, aby se z ní dalo poznat co dělat. */
export function hlasChybu(chyba) {
  let podrobnost = chyba.message || '';
  const stiznosti = chyba.detaily?.complaints;
  if (Array.isArray(stiznosti)) {
    podrobnost += ' (' + stiznosti.map(popisStiznosti).join(', ') + ')';
  }
  const box = el('div', { class: 'chyba' },
    el('div', { class: 'nazev', text: 'Nepovedlo se' }),
    el('div', { text: podrobnost }),
    el('div', { class: 'kod', text: chyba.kod || '' }),
  );
  dotaz('#hlaseni').append(box);
  box.addEventListener('click', () => box.remove());
  setTimeout(() => box.remove(), 11000);
}

/** Přeloží strojové kódy porušených pravidel hesla do češtiny. */
export function popisStiznosti(s) {
  switch (s.rule) {
    case 'too_short': return `nejméně ${s.min} znaků`;
    case 'too_long': return `nejvýš ${s.max} znaků`;
    case 'missing_uppercase': return 'chybí velké písmeno';
    case 'missing_lowercase': return 'chybí malé písmeno';
    case 'missing_digit': return 'chybí číslice';
    case 'missing_symbol': return 'chybí symbol';
    case 'contains_username': return 'obsahuje přihlašovací jméno';
    case 'in_history': return `shoduje se s posledními ${s.count} hesly`;
    case 'control_character': return 'obsahuje řídicí znak';
    case 'too_common': return 'je příliš běžné';
    default: return s.rule;
  }
}

// ------------------------------------------------------------- dialog

let zavriAktualni = null;

/**
 * Otevře modální dialog. `tlacitka` je seznam
 * `{ text, hlavni, nebezpecne, akce }`; když `akce` vrátí `false`,
 * dialog zůstane otevřený (třeba kvůli chybě ve formuláři).
 */
export function dialog({ nazev, obsah, tlacitka = [], siroky = false }) {
  const vrstva = dotaz('#dialog-vrstva');
  const telo = el('div', { class: 'dialog-telo' }, obsah);

  const radek = el('div', { class: 'radek-tlacitek' });
  for (const t of tlacitka) {
    const tl = el('button', {
      class: 'tlacitko' + (t.hlavni ? ' hlavni' : '') + (t.nebezpecne ? ' nebezpecne' : ''),
      type: 'button',
      text: t.text,
      on: {
        click: async () => {
          tl.disabled = true;
          try {
            const vysledek = await t.akce?.();
            if (vysledek !== false) zavri();
          } catch (e) {
            hlasChybu(e);
          } finally {
            tl.disabled = false;
          }
        },
      },
    });
    radek.append(tl);
  }
  radek.append(el('button', {
    class: 'tlacitko', type: 'button', text: 'Zavřít',
    on: { click: () => zavri() },
  }));

  const okno = el('div', { class: 'dialog' + (siroky ? ' siroky' : '') },
    el('h3', { text: nazev }), telo, radek);

  nahrad(vrstva, okno);
  vrstva.classList.remove('skryto');
  const prvniPole = okno.querySelector('input, select, textarea, button.hlavni');
  prvniPole?.focus();

  function zavri() {
    vrstva.classList.add('skryto');
    vrstva.textContent = '';
    zavriAktualni = null;
    document.removeEventListener('keydown', naEscape);
  }
  function naEscape(e) {
    if (e.key === 'Escape') zavri();
  }
  document.addEventListener('keydown', naEscape);
  zavriAktualni = zavri;
  return zavri;
}

export function zavriDialog() {
  zavriAktualni?.();
}

/** Potvrzení nebezpečné akce. Vrací Promise<boolean>. */
export function potvrd({ nazev, otazka, tlacitko = 'Pokračovat', opis = null }) {
  return new Promise((splnit) => {
    let vstup = null;
    const obsah = el('div', {}, el('p', { text: otazka }));
    if (opis) {
      obsah.append(el('label', { class: 'pole' },
        el('span', { text: `Pro potvrzení opiš: ${opis}` }),
        (vstup = el('input', { type: 'text', class: 'mono' }))));
    }
    const zavri = dialog({
      nazev,
      obsah,
      tlacitka: [{
        text: tlacitko,
        nebezpecne: true,
        akce: () => {
          if (opis && vstup.value.trim() !== opis) {
            hlas('Text nesouhlasí', 'Opiš ho přesně.', 'chyba');
            return false;
          }
          splnit(true);
          return true;
        },
      }],
    });
    const puvodni = zavri;
    // Zavření bez potvrzení = ne.
    const pozorovatel = new MutationObserver(() => {
      if (dotaz('#dialog-vrstva').classList.contains('skryto')) {
        pozorovatel.disconnect();
        splnit(false);
      }
    });
    pozorovatel.observe(dotaz('#dialog-vrstva'), { attributes: true, attributeFilter: ['class'] });
    void puvodni;
  });
}

// ------------------------------------------------------- formátování

export function datum(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString('cs-CZ', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

export function datumKratke(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString('cs-CZ', {
    day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}

export function doba(sekundy) {
  const s = Math.max(0, Math.floor(sekundy));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d} d ${h} h`;
  if (h > 0) return `${h} h ${m} min`;
  return `${m} min ${s % 60} s`;
}

/** Otisk certifikátu rozdělený po skupinách, ať se dá přečíst. */
export function otiskPoSkupinach(otisk) {
  if (!otisk) return '—';
  const casti = otisk.split(':');
  const radky = [];
  for (let i = 0; i < casti.length; i += 8) {
    radky.push(casti.slice(i, i + 8).join(':'));
  }
  return radky.join('\n');
}

export function nazevStavu(stage) {
  switch (stage) {
    case 'fresh': return 'Čistý server';
    case 'roles_installed': return 'Role nainstalované';
    case 'domain_controller': return 'Řadič domény';
    default: return String(stage);
  }
}

/** Pomůcka pro tabulky: hlavička + řádky. */
export function tabulka(hlavicky, radky, { prazdne = 'Žádné záznamy.' } = {}) {
  const thead = el('thead', {}, el('tr', {}, hlavicky.map((h) => el('th', { text: h }))));
  const tbody = el('tbody', {});
  if (radky.length === 0) {
    tbody.append(el('tr', {}, el('td', {
      class: 'prazdno', colspan: String(hlavicky.length), text: prazdne,
    })));
  } else {
    for (const r of radky) tbody.append(r);
  }
  return el('table', { class: 'seznam' }, thead, tbody);
}

/** Panel s nadpisem. */
export function panel(nadpis, obsah, { pocet = null, bezRamu = false } = {}) {
  return el('div', { class: 'panel' },
    el('h3', {}, nadpis, pocet !== null ? el('span', { class: 'pocet', text: `(${pocet})` }) : null),
    bezRamu ? obsah : el('div', { class: 'panel-telo' }, obsah));
}

/** Ukazatel síly hesla, který se hýbe při psaní. */
export function siloměr(vstup) {
  const pruh = el('div', {});
  const obal = el('div', { class: 'sila-hesla' }, pruh);
  const prepocitej = () => {
    const skore = odhadSily(vstup.value);
    pruh.style.width = skore + '%';
    pruh.className = skore >= 70 ? 'dobra' : skore >= 40 ? 'stredni' : '';
  };
  vstup.addEventListener('input', prepocitej);
  prepocitej();
  return obal;
}

/**
 * Kontrola jména domény v prohlížeči — stejná pravidla jako
 * `ad_core::names::validuj_jmeno_domeny`. Rozhoduje vždycky server,
 * tohle jen šetří jedno kolečko po síti a řekne to hned.
 *
 * Vrací text chyby, nebo `null`, když je jméno v pořádku.
 */
export function zkontrolujJmenoDomeny(vstup) {
  const s = String(vstup || '').trim().replace(/\.$/, '').toLowerCase();
  if (!s) return 'Zadej jméno domény.';
  if (/[^\x00-\x7F]/.test(s)) return 'Jméno domény musí být ASCII, bez diakritiky.';
  const casti = s.split('.');
  if (casti.length < 2) return 'Jméno domény musí mít alespoň dvě části, např. skola.internal.';
  for (const c of casti) {
    if (!c) return 'Jméno domény má prázdnou část (dvě tečky za sebou?).';
    if (c.length > 63) return 'Část jména je delší než 63 znaků.';
    if (!/^[a-z0-9-]+$/.test(c)) return `Část „${c}" smí mít jen a-z, 0-9 a pomlčku.`;
    if (c.startsWith('-') || c.endsWith('-')) return 'Část jména nesmí začínat ani končit pomlčkou.';
  }
  const tld = casti[casti.length - 1];
  if (['local', 'localhost', 'onion', 'arpa'].includes(tld)) {
    return `Koncovka .${tld} je zakázaná — koliduje s mDNS. Použij např. skola.internal.`;
  }
  return null;
}

/**
 * Kontrola jména počítače (řadiče domény) — obdoba
 * `ad_core::names::validuj_jmeno_pocitace`.
 */
export function zkontrolujJmenoPocitace(vstup) {
  const s = String(vstup || '').trim().toUpperCase();
  if (!s) return 'Zadej jméno řadiče domény.';
  if (s.length > 15) return 'Jméno počítače má nejvýš 15 znaků.';
  if (!/^[A-Z0-9-]+$/.test(s)) return 'Jméno počítače smí mít jen A-Z, 0-9 a pomlčku.';
  if (s.startsWith('-') || s.endsWith('-')) return 'Jméno nesmí začínat ani končit pomlčkou.';
  if (/^[0-9]+$/.test(s)) return 'Jméno počítače nesmí být jen číslo.';
  return null;
}

/** Je to platná IPv4 adresa? */
export function jeIpv4(vstup) {
  const casti = String(vstup || '').trim().split('.');
  return casti.length === 4 && casti.every((c) => /^[0-9]{1,3}$/.test(c) && Number(c) <= 255);
}

/**
 * Hrubý odhad síly hesla — stejný postup jako na serveru
 * (`ad_core::password::odhad_sily`), jen pro okamžitou odezvu v UI.
 * Rozhoduje vždycky server.
 */
export function odhadSily(heslo) {
  if (!heslo) return 0;
  let abeceda = 0;
  if (/[a-z]/.test(heslo)) abeceda += 26;
  if (/[A-Z]/.test(heslo)) abeceda += 26;
  if (/[0-9]/.test(heslo)) abeceda += 10;
  if (/[^A-Za-z0-9]/.test(heslo)) abeceda += 33;
  if (/[^\x00-\x7F]/.test(heslo)) abeceda += 100;
  const bity = heslo.length * Math.log2(Math.max(2, abeceda));
  return Math.max(0, Math.min(100, Math.round((bity / 80) * 100)));
}
