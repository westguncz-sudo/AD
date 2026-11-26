// Stránky: Přehled, Místní server, průvodce Přidat role a funkce,
// konfigurační průvodce doménových služeb, auditní log.

import {
  api, datum, datumKratke, doba, el, ikona, jeIpv4, nahrad, nazevStavu,
  otiskPoSkupinach, panel, siloměr, stav, tabulka, zkontrolujJmenoDomeny,
  zkontrolujJmenoPocitace,
} from './jadro.js';
import { pruvodce, stranka } from './pruvodce.js';

// =====================================================================
// Přehled (Dashboard)
// =====================================================================

export async function prehled(kontejner) {
  const s = stav.status;
  const jeDomena = s.stage === 'domain_controller';

  // --- uvítací panel s číslovaným rychlým startem ---
  const krok = (text, akce, hotovo = false, povoleno = true) => el('button', {
    type: 'button', text, class: hotovo ? 'hotovo' : '',
    disabled: !povoleno,
    on: { click: akce },
  });

  const rychlyStart = el('div', { class: 'rychly-start' },
    krok('Zkontrolovat tento místní server', () => { location.hash = '#/server'; }, true),
    krok(s.roles.directory && s.roles.dns
      ? 'Role jsou nainstalované'
      : 'Přidat role a funkce',
      () => { location.hash = '#/role'; },
      s.roles.directory && s.roles.dns),
    krok(jeDomena
      ? `Doména ${s.domain.dns_name} je vytvořená`
      : 'Povýšit tento server na řadič domény',
      () => { location.hash = '#/povyseni'; },
      jeDomena,
      s.roles.directory),
    krok(jeDomena && s.counts.users > 2
      ? `Uživatelé jsou vytvoření (${s.counts.users})`
      : 'Vytvořit organizační jednotky a uživatele',
      () => { location.hash = '#/uzivatele'; },
      jeDomena && s.counts.users > 2,
      jeDomena),
    krok(jeDomena && s.counts.gpos > 0
      ? `Zásady skupiny jsou nastavené (${s.counts.gpos})`
      : 'Nastavit zásady skupiny',
      () => { location.hash = '#/zasady'; },
      jeDomena && s.counts.gpos > 0,
      jeDomena),
    krok(s.counts.computers > 0
      ? `Počítače v doméně: ${s.counts.computers}`
      : 'Připojit počítače klientem ad-client',
      () => { location.hash = '#/uzivatele'; },
      s.counts.computers > 0,
      jeDomena));

  const vitejte = el('div', { class: 'panel vitejte' },
    el('h3', { text: 'Vítá vás Správce serveru' }),
    rychlyStart);

  // --- upozornění ---
  const upozorneni = s.alerts.length
    ? panel('Co potřebuje pozornost', el('div', {},
        s.alerts.map((a) => el('div', { class: `upozorneni ${a.level}` },
          el('div', { class: 'text' },
            el('div', { class: 'nazev', text: a.title }),
            el('div', { class: 'detail', text: a.detail }),
            a.action
              ? el('button', {
                  class: 'odkaz', type: 'button', text: 'Provést →',
                  on: { click: () => { location.hash = a.action; } },
                })
              : null)))), { pocet: s.alerts.length })
    : null;

  // --- dlaždice rolí a skupin serverů ---
  const dlazdice = [];

  dlazdice.push(dlazdiceRole({
    nazev: 'Doménové služby',
    ikonka: 'domena',
    stav: jeDomena ? 'ok' : s.roles.directory ? 'varovani' : 'neaktivni',
    radky: jeDomena
      ? [
          ['Doména', s.domain.dns_name],
          ['Řadič', s.domain.dc_fqdn],
          ['Uživatelé', s.counts.users],
          ['Skupiny', s.counts.groups],
          ['Organizační jednotky', s.counts.ous],
          ['Zamčené účty', s.counts.locked_users],
        ]
      : [['Role', s.roles.directory ? 'nainstalovaná' : 'není'],
         ['Doména', 'není vytvořená']],
    cesta: jeDomena ? '/uzivatele' : s.roles.directory ? '/povyseni' : '/role',
  }));

  dlazdice.push(dlazdiceRole({
    nazev: 'DNS',
    ikonka: 'dns',
    stav: s.roles.dns ? (jeDomena ? 'ok' : 'varovani') : 'neaktivni',
    radky: [
      ['Role', s.roles.dns ? 'nainstalovaná' : 'není'],
      ['Zóny', s.counts.zones],
      ['Server na portu 53', 've fázi 4'],
    ],
    cesta: s.roles.dns ? '/dns' : '/role',
  }));

  dlazdice.push(dlazdiceRole({
    nazev: 'Počítače v doméně',
    ikonka: 'pocitac',
    stav: s.counts.computers === 0 ? 'neaktivni'
      : s.counts.computers_online === s.counts.computers ? 'ok' : 'varovani',
    radky: [
      ['Celkem', s.counts.computers],
      ['Ohlásily se za 24 h', s.counts.computers_online],
    ],
    cesta: '/uzivatele',
  }));

  dlazdice.push(dlazdiceRole({
    nazev: 'Zásady skupiny',
    ikonka: 'zasada',
    stav: jeDomena ? (s.counts.gpos > 0 ? 'ok' : 'varovani') : 'neaktivni',
    radky: [['Zásady', s.counts.gpos]],
    cesta: '/zasady',
  }));

  // --- poslední události ---
  let posledni = null;
  try {
    const udalosti = await api('/events?limit=6');
    posledni = panel('Poslední události', tabulka(
      ['Čas', 'Akce', 'Kdo', 'Čeho se týkalo', 'Výsledek'],
      udalosti.items.map((u) => el('tr', {},
        el('td', { text: datumKratke(u.at) }),
        el('td', { class: 'mono', text: u.action }),
        el('td', { text: u.actor }),
        el('td', { text: u.target || '—' }),
        el('td', {}, el('span', {
          class: 'odznacek ' + (u.success ? 'zapnuto' : 'zamceno'),
          text: u.success ? 'ok' : 'chyba',
        })))),
      { prazdne: 'Zatím se nic nestalo.' }),
      { bezRamu: true });
  } catch {
    posledni = null;
  }

  nahrad(kontejner,
    el('h2', { class: 'nadpis-stranky', text: 'Přehled' }),
    vitejte,
    upozorneni,
    panel('Role a skupiny serverů', el('div', { class: 'mrizka' }, dlazdice), { bezRamu: false }),
    posledni);
}

function dlazdiceRole({ nazev, ikonka, stav: stavDlazdice, radky, cesta }) {
  return el('div', { class: 'dlazdice-role' },
    el('div', { class: `pruh-stavu ${stavDlazdice}` }),
    el('h4', {}, ikona(ikonka, true), nazev),
    radky.map(([k, v]) => el('div', { class: 'radek' },
      el('span', { text: k }), el('span', { text: String(v) }))),
    el('div', { class: 'radek' },
      el('button', {
        class: 'odkaz', type: 'button', text: 'Otevřít →',
        on: { click: () => { location.hash = '#' + cesta; } },
      })));
}

// =====================================================================
// Místní server
// =====================================================================

export async function mistniServer(kontejner) {
  const s = stav.status;
  const radek = (klic, hodnota, mono = false) => el('tr', {},
    el('th', { text: klic }),
    el('td', { class: mono ? 'mono' : '', text: String(hodnota) }));

  const vlastnosti = el('table', { class: 'seznam' }, el('tbody', {},
    radek('Jméno počítače', s.hostname),
    radek('Operační systém', s.os),
    radek('Produkt', `${s.product} ${s.version}`),
    radek('Stav serveru', nazevStavu(s.stage)),
    radek('Doménové služby', s.roles.directory ? 'nainstalované' : 'nejsou'),
    radek('DNS', s.roles.dns ? 'nainstalované' : 'není'),
    radek('Doména', s.domain ? s.domain.dns_name : 'není vytvořená'),
    s.domain ? radek('Krátké jméno domény', s.domain.short_name) : null,
    s.domain ? radek('Řadič domény', s.domain.dc_fqdn) : null,
    s.domain ? radek('Adresa řadiče', s.domain.dc_ip) : null,
    s.domain ? radek('Identifikátor domény', s.domain.domain_sid
      ? `S-1-5-21-${s.domain.domain_sid.a}-${s.domain.domain_sid.b}-${s.domain.domain_sid.c}`
      : '—', true) : null,
    s.domain ? radek('Vytvořena', datum(s.domain.created_at)) : null,
    radek('Server běží', doba(s.uptime_seconds)),
    radek('Čas serveru', datum(s.server_time))));

  const poslouchatka = tabulka(['Poslouchátko', 'Adresa', 'TLS', 'Stav'],
    s.listeners.map((l) => el('tr', {},
      el('td', { text: popisPoslouchatka(l.name) }),
      el('td', { class: 'mono', text: l.address }),
      el('td', { text: l.tls ? 'ano' : 'ne' }),
      el('td', {}, el('span', {
        class: 'odznacek ' + (l.running ? 'zapnuto' : 'vypnuto'),
        text: l.running ? 'běží' : 'neběží',
      })))));

  const otisk = s.ca_fingerprint_sha256
    ? el('div', {},
        el('p', { class: 'maly slabe', text:
          'Tenhle otisk opiš klientům. Klient si ho připne a dál věří jen '
          + 'certifikátům z této autority — tím pozná podvržený server.' }),
        el('pre', { class: 'mono', text: otiskPoSkupinach(s.ca_fingerprint_sha256) }),
        el('p', { class: 'maly' },
          el('span', { text: 'Příkaz pro klienta: ' }),
          el('code', { class: 'mono', text:
            `ad-client join --server ${s.domain ? s.domain.dc_fqdn : '<server>'} `
            + `--fingerprint ${s.ca_fingerprint_sha256}` })))
    : el('p', { class: 'slabe', text:
        'Certifikační autorita vznikne při povýšení serveru na řadič domény.' });

  nahrad(kontejner,
    el('h2', { class: 'nadpis-stranky', text: 'Místní server' }),
    panel('Vlastnosti', vlastnosti, { bezRamu: true }),
    panel('Poslouchátka', poslouchatka, { bezRamu: true }),
    panel('Certifikační autorita domény', otisk));
}

function popisPoslouchatka(jmeno) {
  switch (jmeno) {
    case 'admin': return 'Webová správa';
    case 'domain-api': return 'Doménové API pro klienty';
    case 'dns': return 'DNS server';
    default: return jmeno;
  }
}

// =====================================================================
// Průvodce „Přidat role a funkce“
// =====================================================================

export async function pruvodceRole(kontejner) {
  const jiz = stav.status.roles;
  const data = {
    directory: jiz.directory,
    dns: jiz.dns,
    consent: false,
    vysledek: null,
  };

  pruvodce(kontejner, {
    nazev: 'Přidat role a funkce',
    cil: `Cílový server: ${stav.status.hostname}`,
    data,
    kroky: [
      {
        nazev: 'Před zahájením',
        vykresli: () => stranka('Než začneš',
          'Tenhle průvodce zapne role na tomhle serveru. Role je část '
          + 'serveru, kterou chceš používat — doménové služby nebo DNS. '
          + 'Samotná instalace nic nestahuje z internetu: všechno je už '
          + 'v programu, zapíná se jen to, co se má spustit.',
          el('ul', {},
            el('li', { text: 'Nic se neinstaluje bez tvého výslovného souhlasu na konci průvodce.' }),
            el('li', { text: 'Role se dá kdykoli vypnout zrušením řadiče domény.' }),
            el('li', { text: 'Doména se tím ještě nevytvoří — to je druhý průvodce.' }))),
      },
      {
        nazev: 'Typ instalace',
        vykresli: () => stranka('Typ instalace',
          'Instalujeme role přímo na tenhle server. Vzdálená instalace '
          + 'na jiné stroje ani virtuální disky se v tomhle projektu nedělají.',
          el('label', { class: 'zatrzitko' },
            el('input', { type: 'radio', checked: true, disabled: true }),
            el('span', {}, 'Instalace rolí a funkcí na tento server',
              el('span', { class: 'popis', text: stav.status.hostname })))),
      },
      {
        nazev: 'Výběr serveru',
        vykresli: () => stranka('Výběr cílového serveru',
          'Vybraný server je ten, na kterém běží tato správa.',
          tabulka(['Jméno', 'Systém', 'Stav'], [
            el('tr', { class: 'vybrany' },
              el('td', { text: stav.status.hostname }),
              el('td', { text: stav.status.os }),
              el('td', { text: nazevStavu(stav.status.stage) })),
          ])),
      },
      {
        nazev: 'Role serveru',
        vykresli: (d, prekresli) => {
          const zatrzitko = (klic, nazev, popis, jizNainstalovano) => el('label',
            { class: 'zatrzitko' },
            el('input', {
              type: 'checkbox', checked: d[klic], disabled: jizNainstalovano,
              on: { change: (e) => { d[klic] = e.target.checked; prekresli(); } },
            }),
            el('span', {}, nazev,
              el('span', { class: 'popis', text: popis }),
              jizNainstalovano
                ? el('span', { class: 'odznacek zapnuto', text: 'už je nainstalovaná' })
                : null));

          return stranka('Vyber role, které chceš na serveru zapnout', null,
            zatrzitko('directory', 'Doménové služby',
              'Vlastní databáze domény: uživatelé, skupiny, organizační jednotky '
              + 'a počítače. Bez této role se server nedá povýšit na řadič domény.',
              jiz.directory),
            zatrzitko('dns', 'DNS server',
              'Vlastní DNS server s dopřednou a reverzní zónou. Klienti si '
              + 'podle něj najdou řadič domény. Bez DNS musí klient znát '
              + 'adresu serveru ručně.',
              jiz.dns),
            el('p', { class: 'maly slabe mezera-nad', text:
              'Role, které už jsou nainstalované, nejde v tomhle průvodci vypnout. '
              + 'Odebírají se zrušením řadiče domény.' }));
        },
        overit: (d) => (d.directory || d.dns ? null : 'Vyber alespoň jednu roli.'),
      },
      {
        nazev: 'Potvrzení',
        dalsiText: 'Instalovat',
        vykresli: (d, prekresli) => {
          const kInstalaci = [];
          if (d.directory && !jiz.directory) kInstalaci.push('Doménové služby');
          if (d.dns && !jiz.dns) kInstalaci.push('DNS server');

          return stranka('Potvrď, co se má zapnout', null,
            kInstalaci.length === 0
              ? el('p', { text: 'Vybrané role už jsou nainstalované, nic se nezmění.' })
              : el('ul', {}, kInstalaci.map((r) => el('li', { text: r }))),
            el('label', { class: 'zatrzitko mezera-nad' },
              el('input', {
                type: 'checkbox', checked: d.consent,
                on: { change: (e) => { d.consent = e.target.checked; prekresli(); } },
              }),
              el('span', {}, 'Souhlasím s instalací vybraných rolí na tento server',
                el('span', { class: 'popis', text:
                  'Bez zatržení server instalaci odmítne — žádná role se '
                  + 'nezapne „mimochodem“.' }))));
        },
        dalsiMozne: (d) => d.consent,
        akce: async (d) => {
          d.vysledek = await api('/roles', {
            metoda: 'POST',
            telo: { directory: d.directory, dns: d.dns, consent: true },
          });
        },
      },
      {
        nazev: 'Výsledky',
        konec: true,
        zrusit: false,
        vykresli: (d) => stranka('Instalace dokončena', null,
          el('ul', {},
            el('li', { text: `Doménové služby: ${d.vysledek?.directory ? 'nainstalované' : 'nejsou'}` }),
            el('li', { text: `DNS server: ${d.vysledek?.dns ? 'nainstalovaný' : 'není'}` })),
          d.vysledek?.directory && stav.status.stage !== 'domain_controller'
            ? el('div', { class: 'upozorneni warning mezera-nad' },
                el('div', { class: 'text' },
                  el('div', { class: 'nazev', text: 'Povýšit server na řadič domény' }),
                  el('div', { class: 'detail', text:
                    'Role doménových služeb je nainstalovaná, ale doména ještě '
                    + 'neexistuje. Dalším krokem je konfigurační průvodce.' }),
                  el('button', {
                    class: 'odkaz', type: 'button', text: 'Otevřít průvodce →',
                    on: { click: () => { location.hash = '#/povyseni'; } },
                  })))
            : null,
          el('p', { class: 'mezera-nad' },
            el('button', {
              class: 'tlacitko', type: 'button', text: 'Zpět na přehled',
              on: { click: () => { location.hash = '#/prehled'; } },
            }))),
      },
    ],
  });
}

// =====================================================================
// Konfigurační průvodce — povýšení na řadič domény
// =====================================================================

export async function pruvodcePovyseni(kontejner) {
  if (stav.status.stage === 'domain_controller') {
    nahrad(kontejner,
      el('h2', { class: 'nadpis-stranky', text: 'Konfigurace doménových služeb' }),
      el('div', { class: 'upozorneni info' },
        el('div', { class: 'text' },
          el('div', { class: 'nazev', text: 'Doména už existuje' }),
          el('div', { class: 'detail', text:
            `Tento server je řadičem domény ${stav.status.domain.dns_name}. `
            + 'Druhá doména na jednom serveru být nemůže.' }))));
    return;
  }
  if (!stav.status.roles.directory) {
    nahrad(kontejner,
      el('h2', { class: 'nadpis-stranky', text: 'Konfigurace doménových služeb' }),
      el('div', { class: 'upozorneni error' },
        el('div', { class: 'text' },
          el('div', { class: 'nazev', text: 'Chybí role doménových služeb' }),
          el('div', { class: 'detail', text:
            'Nejdřív ji zapni v průvodci Přidat role a funkce.' }),
          el('button', {
            class: 'odkaz', type: 'button', text: 'Otevřít průvodce →',
            on: { click: () => { location.hash = '#/role'; } },
          }))));
    return;
  }

  const data = {
    domain_dns_name: 'skola.internal',
    short_name: '',
    dc_hostname: (stav.status.hostname || 'DC01').toUpperCase().replace(/[^A-Z0-9-]/g, '').slice(0, 15) || 'DC01',
    dc_ip: '',
    heslo: '',
    heslo2: '',
    dns: { create_reverse: true, reverse_prefix: 24, forwarders: '', enable_server: true },
    kontrola: null,
    vysledek: null,
  };

  const telo = () => ({
    domain_dns_name: data.domain_dns_name.trim(),
    short_name: data.short_name.trim() || null,
    dc_hostname: data.dc_hostname.trim(),
    dc_ip: data.dc_ip.trim(),
    administrator_password: data.heslo,
    dns: {
      create_reverse: data.dns.create_reverse,
      reverse_prefix: Number(data.dns.reverse_prefix),
      forwarders: data.dns.forwarders.split(',').map((f) => f.trim()).filter(Boolean),
      enable_server: data.dns.enable_server,
    },
    confirm: true,
  });

  pruvodce(kontejner, {
    nazev: 'Konfigurace doménových služeb',
    cil: `Cílový server: ${stav.status.hostname}`,
    data,
    kroky: [
      {
        nazev: 'Konfigurace nasazení',
        vykresli: (d) => stranka('Nová doména',
          'Vytvoříme novou doménu. Připojení k existující doméně nebo '
          + 'další řadič do stávající domény tento projekt neumí a nepředstírá to.',
          el('div', { class: 'radek-poli' },
            el('label', { class: 'pole' },
              el('span', { text: 'Jméno domény (DNS)' }),
              el('input', {
                id: 'pole-domena', type: 'text', value: d.domain_dns_name,
                placeholder: 'skola.internal',
                on: { input: (e) => { d.domain_dns_name = e.target.value; } },
              })),
            el('label', { class: 'pole' },
              el('span', { text: 'Krátké jméno (nepovinné, odvodí se)' }),
              el('input', {
                id: 'pole-kratke', type: 'text', value: d.short_name, placeholder: 'SKOLA',
                on: { input: (e) => { d.short_name = e.target.value; } },
              }))),
          el('div', { class: 'upozorneni info' },
            el('div', { class: 'text' },
              el('div', { class: 'nazev', text: 'Nepoužívej koncovku .local' }),
              el('div', { class: 'detail', text:
                'Koliduje s mDNS (Avahi, Bonjour) a rozbila by objevování '
                + 'služeb v síti. Server ji odmítne. Doporučená koncovka je '
                + '.internal, kterou ICANN vyhradila právě pro vnitřní sítě.' })))),
        overit: (d) => zkontrolujJmenoDomeny(d.domain_dns_name),
      },
      {
        nazev: 'Možnosti řadiče domény',
        vykresli: (d) => {
          const heslo = el('input', {
            id: 'pole-heslo', type: 'password', value: d.heslo,
            autocomplete: 'new-password',
            on: { input: (e) => { d.heslo = e.target.value; } },
          });
          return stranka('Řadič domény a účet správce', null,
            el('div', { class: 'radek-poli' },
              el('label', { class: 'pole' },
                el('span', { text: 'Jméno řadiče domény' }),
                el('input', {
                  id: 'pole-hostname', type: 'text', value: d.dc_hostname,
                  placeholder: 'DC01',
                  on: { input: (e) => { d.dc_hostname = e.target.value.toUpperCase(); } },
                })),
              el('label', { class: 'pole' },
                el('span', { text: 'IP adresa, na které bude server dostupný' }),
                el('input', {
                  id: 'pole-ip', type: 'text', value: d.dc_ip,
                  placeholder: '192.168.56.10',
                  on: { input: (e) => { d.dc_ip = e.target.value; } },
                }))),
            el('label', { class: 'pole' },
              el('span', { text: 'Heslo vestavěného účtu administrator' }),
              heslo, siloměr(heslo)),
            el('label', { class: 'pole' },
              el('span', { text: 'Heslo znovu' }),
              el('input', {
                id: 'pole-heslo2', type: 'password', value: d.heslo2,
                autocomplete: 'new-password',
                on: { input: (e) => { d.heslo2 = e.target.value; } },
              })),
            el('p', { class: 'maly slabe', text:
              'Heslo se uloží jako Argon2id — zpátky se z databáze přečíst nedá. '
              + 'Kdybys ho zapomněl, jediná cesta zpátky je zrušit doménu.' }));
        },
        overit: (d) => {
          const chybaJmena = zkontrolujJmenoPocitace(d.dc_hostname);
          if (chybaJmena) return chybaJmena;
          if (!jeIpv4(d.dc_ip)) return 'Zadej platnou IPv4 adresu, např. 192.168.56.10.';
          if (d.heslo.length < 8) return 'Heslo musí mít alespoň 8 znaků.';
          if (d.heslo !== d.heslo2) return 'Hesla se neshodují.';
          return null;
        },
      },
      {
        nazev: 'Možnosti DNS',
        vykresli: (d, prekresli) => stranka('DNS zóny a přeposílání',
          'Při vytvoření domény se založí dopředná zóna pro jméno domény '
          + 'a volitelně reverzní zóna pro tvoji síť. Dotazy, na které '
          + 'neumíme odpovědět, se přeposílají dál.',
          el('label', { class: 'zatrzitko' },
            el('input', {
              type: 'checkbox', checked: d.dns.enable_server,
              on: { change: (e) => { d.dns.enable_server = e.target.checked; prekresli(); } },
            }),
            el('span', {}, 'Spustit vlastní DNS server na portu 53',
              el('span', { class: 'popis', text: 'Samotné poslouchání na portu 53 přijde ve fázi 4; zóny se vytvoří teď.' }))),
          el('label', { class: 'zatrzitko' },
            el('input', {
              type: 'checkbox', checked: d.dns.create_reverse,
              on: { change: (e) => { d.dns.create_reverse = e.target.checked; prekresli(); } },
            }),
            el('span', {}, 'Vytvořit reverzní zónu (překlad adresy na jméno)')),
          d.dns.create_reverse
            ? el('label', { class: 'pole' },
                el('span', { text: 'Maska sítě pro reverzní zónu' }),
                el('select', {
                  on: { change: (e) => { d.dns.reverse_prefix = e.target.value; } },
                },
                  [24, 16, 8].map((p) => el('option', {
                    value: String(p), selected: Number(d.dns.reverse_prefix) === p,
                    text: `/${p}`,
                  }))))
            : null,
          el('label', { class: 'pole' },
            el('span', { text: 'Přeposílat dotazy na (IP adresy, oddělené čárkou)' }),
            el('input', {
              id: 'pole-forwardery', type: 'text', value: d.dns.forwarders,
              placeholder: '1.1.1.1, 8.8.8.8',
              on: { input: (e) => { d.dns.forwarders = e.target.value; } },
            })),
          el('p', { class: 'maly slabe', text:
            'Když necháš prázdné, server použije to, co měl systém nastavené '
            + 'před námi. Prázdné a nenalezené = dotazy mimo doménu se odmítnou.' })),
      },
      {
        nazev: 'Zkontrolovat možnosti',
        vykresli: (d) => {
          const souhrn = el('dl', { class: 'souhrn' });
          const polozka = (k, v) => {
            souhrn.append(el('dt', { text: k }), el('dd', { text: String(v) }));
          };
          polozka('Jméno domény', d.domain_dns_name.trim().toLowerCase());
          polozka('Krátké jméno', d.short_name.trim() || '(odvodí se z prvního slova)');
          polozka('Řadič domény', `${d.dc_hostname.trim()} (${d.dc_ip.trim()})`);
          polozka('Účet správce', 'administrator');
          polozka('DNS server', d.dns.enable_server ? 'zapnout' : 'nezapínat');
          polozka('Reverzní zóna', d.dns.create_reverse ? `ano, /${d.dns.reverse_prefix}` : 'ne');
          polozka('Přeposílání', d.dns.forwarders.trim() || 'podle systému');
          return stranka('Zkontroluj, co se vytvoří',
            'Dalším krokem je kontrola předpokladů. Ta jen čte a nic nemění.',
            souhrn);
        },
        akce: async (d) => { d.kontrola = await api('/promote/precheck', { metoda: 'POST', telo: telo() }); },
      },
      {
        nazev: 'Kontrola předpokladů',
        dalsiText: 'Nainstalovat',
        vykresli: (d, prekresli) => {
          const k = d.kontrola;
          const znak = (s) => (s === 'pass' ? '✓' : s === 'warn' ? '!' : '✕');
          return stranka('Kontrola předpokladů',
            k.can_continue
              ? 'Všechny potřebné předpoklady jsou splněné. Položky s vykřičníkem '
                + 'jen upozorňují, povýšení nebrání.'
              : 'Některé předpoklady nejsou splněné. Dokud se neopraví, doména se nevytvoří.',
            el('ul', { class: 'seznam-kontrol' },
              k.items.map((i) => el('li', {},
                el('div', { class: `znak ${i.status}`, text: znak(i.status) }),
                el('div', {},
                  el('div', { class: 'nazev', text: i.title }),
                  el('div', { class: 'detail', text: i.detail }),
                  i.remedy ? el('div', { class: 'rada', text: '→ ' + i.remedy }) : null)))),
            el('p', { class: 'mezera-nad' },
              el('button', {
                class: 'tlacitko', type: 'button', text: 'Zkontrolovat znovu',
                on: {
                  click: async () => {
                    d.kontrola = await api('/promote/precheck', { metoda: 'POST', telo: telo() });
                    prekresli();
                  },
                },
              })));
        },
        dalsiMozne: (d) => Boolean(d.kontrola?.can_continue),
        akce: async (d) => { d.vysledek = await api('/promote', { metoda: 'POST', telo: telo() }); },
      },
      {
        nazev: 'Výsledky',
        konec: true,
        zrusit: false,
        vykresli: (d) => {
          const v = d.vysledek;
          return stranka('Doména je vytvořená', null,
            el('dl', { class: 'souhrn' },
              el('dt', { text: 'Doména' }), el('dd', { text: v.domain.dns_name }),
              el('dt', { text: 'Krátké jméno' }), el('dd', { text: v.domain.short_name }),
              el('dt', { text: 'Řadič domény' }), el('dd', { text: v.domain.dc_fqdn }),
              el('dt', { text: 'Pro klienty' }), el('dd', { class: 'mono', text: v.client_endpoint }),
              el('dt', { text: 'DNS zóny' }), el('dd', { text: v.zones.join(', ') || 'žádné' })),
            el('div', { class: 'panel mezera-nad' },
              el('h3', { text: 'Otisk certifikační autority' }),
              el('div', { class: 'panel-telo' },
                el('p', { class: 'maly slabe', text:
                  'Tenhle otisk opiš klientům. Klient si ho připne a pozná '
                  + 'podle něj podvržený server. Je taky v Místní server.' }),
                el('pre', { class: 'mono', text: otiskPoSkupinach(v.ca_fingerprint_sha256) }))),
            el('h4', { class: 'mezera-nad', text: 'Co dál' }),
            el('ul', {}, v.next_steps.map((s) => el('li', { text: s }))),
            el('div', { class: 'radek-tlacitek' },
              el('button', {
                class: 'tlacitko hlavni', type: 'button', text: 'Přihlásit se znovu',
                on: { click: () => { location.reload(); } },
              })),
            el('p', { class: 'maly slabe', text:
              'Jednorázový token přestal platit. Od teď se přihlašuješ účtem '
              + 'administrator s heslem, které jsi právě zadal.' }));
        },
      },
    ],
  });
}

// =====================================================================
// Auditní log
// =====================================================================

export async function audit(kontejner, parametry) {
  const filtr = {
    action: parametry.get('akce') || '',
    only_failures: parametry.get('chyby') === '1',
    limit: 100,
  };

  const telo = el('div', {});
  const poleAkce = el('input', {
    type: 'text', value: filtr.action, placeholder: 'např. user. nebo auth.',
  });
  const poleChyby = el('input', { type: 'checkbox', checked: filtr.only_failures });

  async function nacti() {
    const q = new URLSearchParams({ limit: String(filtr.limit) });
    if (poleAkce.value.trim()) q.set('action', poleAkce.value.trim());
    if (poleChyby.checked) q.set('only_failures', 'true');
    const data = await api('/events?' + q.toString());
    nahrad(telo, tabulka(
      ['Čas', 'Akce', 'Kdo', 'Čeho se týkalo', 'Odkud', 'Výsledek', 'Podrobnost'],
      data.items.map((u) => el('tr', {},
        el('td', { text: datum(u.at) }),
        el('td', { class: 'mono', text: u.action }),
        el('td', { text: u.actor }),
        el('td', { text: u.target || '—' }),
        el('td', { class: 'mono', text: u.source_ip || '—' }),
        el('td', {}, el('span', {
          class: 'odznacek ' + (u.success ? 'zapnuto' : 'zamceno'),
          text: u.success ? 'ok' : 'chyba',
        })),
        el('td', { class: 'maly', text: u.detail || '' }))),
      { prazdne: 'Žádné události neodpovídají filtru.' }));
    return data.total;
  }

  const nastroje = el('div', { class: 'panel-nastroju' },
    el('span', { text: 'Akce začíná na' }), poleAkce,
    el('label', { class: 'zatrzitko' }, poleChyby, el('span', { text: 'jen chyby' })),
    el('button', { class: 'tlacitko', type: 'button', text: 'Filtrovat', on: { click: () => nacti() } }),
    el('span', { class: 'mezera' }),
    el('span', { class: 'maly slabe', text: 'Hesla a tokeny se do auditu nikdy nezapisují.' }));

  nahrad(kontejner,
    el('h2', { class: 'nadpis-stranky', text: 'Auditní log' }),
    el('div', { class: 'panel' }, nastroje, telo));
  await nacti();
}
