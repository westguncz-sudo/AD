// Nástroje: Uživatelé a počítače, Správce DNS, Správa zásad skupiny.
// Každý nástroj je dvoupanelové okno — vlevo strom, vpravo seznam
// a podrobnosti, stejně jako konzole ve Windows Serveru.

import {
  api, datum, datumKratke, dialog, el, hlas, hlasChybu, ikona, nahrad, panel,
  popisStiznosti, siloměr, stav, tabulka,
} from './jadro.js';

// =====================================================================
// Uživatelé a počítače
// =====================================================================

export async function uzivateleAPocitace(kontejner, parametry) {
  if (stav.status.stage !== 'domain_controller') {
    nahrad(kontejner, bezDomeny('Uživatelé a počítače'));
    return;
  }

  const strom = await api('/ous/tree');
  // `0` znamená „přímo pod doménou“, `null` by znamenalo „kdekoli“.
  let vybranaOu = 0;
  let vybranyObjekt = null;
  let hledani = '';
  let jenZamcene = parametry.get('zamcene') === '1';

  const levy = el('div', { class: 'levy-panel' });
  const tabulkaMista = el('div', { class: 'obsah-panelu' });
  const detail = el('div', { class: 'detail-panel' });
  const nastrojeRadek = el('div', { class: 'panel-nastroju' });

  function vykresliStrom() {
    const uzel = (n, hloubka) => {
      const id = n.ou_id === null ? 0 : n.ou_id;
      const li = el('li', {},
        el('button', {
          class: id === vybranaOu ? 'vybrany' : '',
          type: 'button',
          on: { click: () => { vybranaOu = id; vybranyObjekt = null; prekresli(); } },
        },
          ikona(n.ou_id === null ? 'domena' : 'ou'),
          el('span', { text: n.name }),
          el('span', { class: 'pocet', text: `(${n.object_count})` })));
      if (n.children.length) {
        li.append(el('ul', {}, n.children.map((d) => uzel(d, hloubka + 1))));
      }
      return li;
    };
    nahrad(levy, el('ul', { class: 'strom' }, uzel(strom, 0)));
  }

  async function nacti() {
    const q = new URLSearchParams({ limit: '500' });
    if (hledani) q.set('q', hledani);
    // Při hledání nás zajímá celá doména, ne jen vybraná OU.
    if (!hledani) q.set('ou_id', String(vybranaOu));

    const [uzivatele, skupiny, pocitace] = await Promise.all([
      api('/users?' + q.toString()),
      api('/groups?' + q.toString()),
      api('/computers?' + q.toString()),
    ]);

    let radky = [
      ...uzivatele.items.map((u) => ({ druh: 'user', o: u })),
      ...skupiny.items.map((g) => ({ druh: 'group', o: g })),
      ...pocitace.items.map((p) => ({ druh: 'computer', o: p })),
    ];
    if (jenZamcene) {
      radky = radky.filter((r) => r.druh === 'user' && jeZamceny(r.o));
    }

    nahrad(tabulkaMista, tabulka(
      ['', 'Jméno', 'Typ', 'Stav', 'Popis', 'Naposledy'],
      radky.map((r) => radekObjektu(r)),
      { prazdne: hledani ? 'Nic nenalezeno.' : 'Tady nic není.' }));
  }

  function radekObjektu(r) {
    const o = r.o;
    const jmeno = r.druh === 'user' ? o.sam_account_name : o.name;
    const tr = el('tr', {
      class: 'klikaci' + (vybranyObjekt
        && vybranyObjekt.druh === r.druh && vybranyObjekt.o.id === o.id ? ' vybrany' : ''),
      on: { click: () => { vybranyObjekt = r; vykresliDetail(); zvyrazni(); } },
    },
      el('td', {}, ikona(r.druh === 'user' ? 'uzivatel' : r.druh === 'group' ? 'skupina' : 'pocitac')),
      el('td', {}, el('span', { class: 'tucne', text: jmeno }),
        r.druh === 'user' && o.display_name && o.display_name !== jmeno
          ? el('span', { class: 'slabe', text: ` — ${o.display_name}` })
          : null),
      el('td', { text: nazevDruhu(r.druh) }),
      el('td', {}, odznacekStavu(r)),
      el('td', { class: 'maly', text: o.description || '' }),
      el('td', { class: 'maly slabe', text: r.druh === 'user'
        ? datumKratke(o.last_logon_at)
        : r.druh === 'computer' ? datumKratke(o.last_seen_at) : '—' }));
    return tr;
  }

  function zvyrazni() {
    for (const tr of tabulkaMista.querySelectorAll('tbody tr')) tr.classList.remove('vybrany');
    nacti().catch(hlasChybu);
  }

  function vykresliDetail() {
    if (!vybranyObjekt) {
      nahrad(detail, el('p', { class: 'slabe maly', text:
        'Vyber objekt v seznamu. Nahoře jsou akce pro vybraný objekt.' }));
      return;
    }
    const { druh, o } = vybranyObjekt;
    const vlastnosti = el('dl', { class: 'vlastnosti' });
    const pridej = (k, v) => {
      vlastnosti.append(el('dt', { text: k }), el('dd', { class: 'mono', text: String(v) }));
    };

    if (druh === 'user') {
      pridej('Přihlašovací jméno', o.sam_account_name);
      pridej('UPN', o.upn);
      pridej('Zobrazované jméno', o.display_name || '—');
      pridej('Jméno a příjmení', `${o.given_name} ${o.surname}`.trim() || '—');
      pridej('E-mail', o.email || '—');
      pridej('Identifikátor', o.sid);
      pridej('Účet', o.enabled ? 'zapnutý' : 'vypnutý');
      pridej('Zamčený do', o.locked_until ? datum(o.locked_until) : '—');
      pridej('Heslo nastaveno', datum(o.password_set_at));
      pridej('Heslo nevyprší', o.password_never_expires ? 'ano' : 'ne');
      pridej('Změna hesla při příštím přihlášení', o.must_change_password ? 'ano' : 'ne');
      pridej('Poslední přihlášení', datum(o.last_logon_at));
      pridej('Vytvořen', datum(o.created_at));
      pridej('Vestavěný', o.builtin ? 'ano' : 'ne');
    } else if (druh === 'group') {
      pridej('Jméno', o.name);
      pridej('Přihlašovací jméno', o.sam_account_name);
      pridej('Identifikátor', o.sid);
      pridej('Druh', o.kind === 'security' ? 'bezpečnostní' : 'distribuční');
      pridej('Členů', o.member_count);
      pridej('Vestavěná', o.builtin ? 'ano' : 'ne');
    } else {
      pridej('Jméno', o.name);
      pridej('DNS jméno', o.dns_name);
      pridej('Identifikátor', o.sid);
      pridej('Účet', o.enabled ? 'zapnutý' : 'vypnutý');
      pridej('Systém', `${o.os_name} ${o.os_version}`.trim() || '—');
      pridej('Poslední adresa', o.last_ip || '—');
      pridej('Připojen', datum(o.joined_at));
      pridej('Naposledy se ohlásil', datum(o.last_seen_at));
    }

    nahrad(detail,
      el('h4', {}, ikona(druh === 'user' ? 'uzivatel' : druh === 'group' ? 'skupina' : 'pocitac'),
        druh === 'user' ? o.sam_account_name : o.name),
      druh === 'computer'
        ? el('p', { class: 'maly slabe', text:
            'Jméno systému a verzi hlásí klient sám — je to jeho tvrzení, '
            + 'ne ověřený údaj.' })
        : null,
      vlastnosti);
  }

  function vykresliNastroje() {
    const polePro = el('input', {
      type: 'text', value: hledani, placeholder: 'hledat v celé doméně…',
      on: {
        keydown: (e) => { if (e.key === 'Enter') { hledani = polePro.value.trim(); prekresli(); } },
      },
    });

    const vybrany = vybranyObjekt;
    const akce = [];
    const tl = (text, fn, { nebezpecne = false, povoleno = true } = {}) => el('button', {
      class: 'tlacitko' + (nebezpecne ? ' nebezpecne' : ''),
      type: 'button', text, disabled: !povoleno,
      on: { click: fn },
    });

    akce.push(tl('Nový uživatel', () => dialogNovyUzivatel(vybranaOu, prekresli)));
    akce.push(tl('Nová skupina', () => dialogNovaSkupina(vybranaOu, prekresli)));
    akce.push(tl('Nová OU', () => dialogNovaOu(vybranaOu, prekresliCely)));

    if (vybrany?.druh === 'user') {
      akce.push(tl('Nastavit heslo', () => dialogHeslo(vybrany.o, prekresli)));
      akce.push(tl('Odemknout', async () => {
        await api(`/users/${vybrany.o.id}/unlock`, { metoda: 'POST' });
        hlas('Účet odemčen', vybrany.o.sam_account_name, 'uspech');
        prekresli();
      }, { povoleno: jeZamceny(vybrany.o) }));
      akce.push(tl(vybrany.o.enabled ? 'Vypnout účet' : 'Zapnout účet', async () => {
        await api(`/users/${vybrany.o.id}`, {
          metoda: 'PATCH', telo: { enabled: !vybrany.o.enabled },
        });
        prekresli();
      }, { povoleno: !(vybrany.o.builtin && vybrany.o.enabled) }));
      akce.push(tl('Členství', () => dialogClenstvi(vybrany.o, prekresli)));
    }
    if (vybrany?.druh === 'group') {
      akce.push(tl('Členové', () => dialogClenoveSkupiny(vybrany.o, prekresli)));
    }
    if (vybrany) {
      akce.push(tl('Přesunout', () => dialogPresun(vybrany, strom, prekresli)));
      akce.push(tl('Smazat', () => dialogSmazat(vybrany, () => {
        vybranyObjekt = null;
        prekresliCely();
      }), { nebezpecne: true, povoleno: !vybrany.o.builtin }));
    }

    nahrad(nastrojeRadek,
      akce,
      el('span', { class: 'mezera' }),
      el('label', { class: 'zatrzitko' },
        el('input', {
          type: 'checkbox', checked: jenZamcene,
          on: { change: (e) => { jenZamcene = e.target.checked; prekresli(); } },
        }),
        el('span', { text: 'jen zamčené' })),
      polePro,
      el('button', {
        class: 'tlacitko', type: 'button', text: 'Hledat',
        on: { click: () => { hledani = polePro.value.trim(); prekresli(); } },
      }),
      hledani
        ? el('button', {
            class: 'odkaz', type: 'button', text: 'zrušit hledání',
            on: { click: () => { hledani = ''; prekresli(); } },
          })
        : null);
  }

  function prekresli() {
    vykresliStrom();
    vykresliNastroje();
    vykresliDetail();
    nacti().catch(hlasChybu);
  }

  async function prekresliCely() {
    const novy = await api('/ous/tree');
    Object.assign(strom, novy);
    prekresli();
  }

  nahrad(kontejner,
    el('h2', { class: 'nadpis-stranky', text: 'Uživatelé a počítače' }),
    el('p', { class: 'maly slabe', text:
      `Doména ${stav.status.domain.dns_name}. Vlevo organizační jednotky, `
      + 'vpravo objekty ve vybrané jednotce.' }),
    el('div', { class: 'dva-panely' },
      levy,
      el('div', { class: 'pravy-panel' }, nastrojeRadek, tabulkaMista, detail)));

  prekresli();
}

function jeZamceny(u) {
  return Boolean(u.locked_until) && new Date(u.locked_until) > new Date();
}

function nazevDruhu(d) {
  return d === 'user' ? 'Uživatel' : d === 'group' ? 'Skupina' : 'Počítač';
}

function odznacekStavu(r) {
  if (r.druh === 'user') {
    if (jeZamceny(r.o)) return el('span', { class: 'odznacek zamceno', text: 'zamčený' });
    if (!r.o.enabled) return el('span', { class: 'odznacek vypnuto', text: 'vypnutý' });
    if (r.o.must_change_password) {
      return el('span', { class: 'odznacek spravovano', text: 'změna hesla' });
    }
    return el('span', { class: 'odznacek zapnuto', text: 'zapnutý' });
  }
  if (r.druh === 'computer') {
    const viden = r.o.last_seen_at && (Date.now() - new Date(r.o.last_seen_at)) < 86400000;
    return el('span', {
      class: 'odznacek ' + (viden ? 'zapnuto' : 'vypnuto'),
      text: viden ? 'ohlásil se' : 'neohlásil se',
    });
  }
  return el('span', {
    class: 'odznacek ' + (r.o.builtin ? 'spravovano' : 'vypnuto'),
    text: r.o.builtin ? 'vestavěná' : `${r.o.member_count} členů`,
  });
}

function bezDomeny(nazev) {
  return el('div', {},
    el('h2', { class: 'nadpis-stranky', text: nazev }),
    el('div', { class: 'upozorneni warning' },
      el('div', { class: 'text' },
        el('div', { class: 'nazev', text: 'Doména ještě neexistuje' }),
        el('div', { class: 'detail', text:
          'Tenhle nástroj pracuje s objekty domény. Nejdřív povyš server '
          + 'na řadič domény.' }),
        el('button', {
          class: 'odkaz', type: 'button', text: 'Otevřít průvodce →',
          on: { click: () => { location.hash = '#/povyseni'; } },
        }))));
}

// ---------------------------------------------------- dialogy objektů

function dialogNovyUzivatel(ouId, hotovo) {
  const jmeno = el('input', { type: 'text', placeholder: 'jan.novak' });
  const krestni = el('input', { type: 'text' });
  const prijmeni = el('input', { type: 'text' });
  const email = el('input', { type: 'text' });
  const popis = el('input', { type: 'text' });
  const heslo = el('input', { type: 'password', autocomplete: 'new-password' });
  const zmena = el('input', { type: 'checkbox', checked: true });
  const zapnuty = el('input', { type: 'checkbox', checked: true });

  // Z jména a příjmení nabídneme přihlašovací jméno.
  const navrhni = () => {
    if (jmeno.dataset.rucne === '1') return;
    const bezDiakritiky = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '');
    const k = bezDiakritiky(krestni.value.trim().toLowerCase()).replace(/[^a-z0-9]/g, '');
    const p = bezDiakritiky(prijmeni.value.trim().toLowerCase()).replace(/[^a-z0-9]/g, '');
    jmeno.value = [k, p].filter(Boolean).join('.').slice(0, 20);
  };
  krestni.addEventListener('input', navrhni);
  prijmeni.addEventListener('input', navrhni);
  jmeno.addEventListener('input', () => { jmeno.dataset.rucne = '1'; });

  dialog({
    nazev: 'Nový uživatel',
    obsah: el('div', {},
      el('div', { class: 'radek-poli' },
        el('label', { class: 'pole' }, el('span', { text: 'Jméno' }), krestni),
        el('label', { class: 'pole' }, el('span', { text: 'Příjmení' }), prijmeni)),
      el('label', { class: 'pole' },
        el('span', { text: 'Přihlašovací jméno (malá písmena, bez diakritiky)' }), jmeno),
      el('div', { class: 'radek-poli' },
        el('label', { class: 'pole' }, el('span', { text: 'E-mail' }), email),
        el('label', { class: 'pole' }, el('span', { text: 'Popis' }), popis)),
      el('label', { class: 'pole' }, el('span', { text: 'Heslo' }), heslo, siloměr(heslo)),
      el('label', { class: 'zatrzitko' }, zmena,
        el('span', { text: 'Musí si změnit heslo při příštím přihlášení' })),
      el('label', { class: 'zatrzitko' }, zapnuty, el('span', { text: 'Účet je zapnutý' })),
      el('p', { class: 'maly slabe', text:
        'Heslo musí projít zásadou platnou pro cílovou organizační jednotku. '
        + 'Když neprojde, server řekne přesně které pravidlo chybí.' })),
    tlacitka: [{
      text: 'Vytvořit',
      hlavni: true,
      akce: async () => {
        await api('/users', {
          metoda: 'POST',
          telo: {
            sam_account_name: jmeno.value.trim(),
            given_name: krestni.value.trim(),
            surname: prijmeni.value.trim(),
            email: email.value.trim(),
            description: popis.value.trim(),
            ou_id: ouId === 0 ? null : ouId,
            password: heslo.value,
            must_change_password: zmena.checked,
            enabled: zapnuty.checked,
          },
        });
        hlas('Uživatel vytvořen', jmeno.value.trim(), 'uspech');
        hotovo();
      },
    }],
  });
}

function dialogNovaSkupina(ouId, hotovo) {
  const jmeno = el('input', { type: 'text', placeholder: 'Žáci 1.A' });
  const popis = el('input', { type: 'text' });
  const druh = el('select', {},
    el('option', { value: 'security', text: 'Bezpečnostní (dává práva)' }),
    el('option', { value: 'distribution', text: 'Distribuční (jen seznam)' }));

  dialog({
    nazev: 'Nová skupina',
    obsah: el('div', {},
      el('label', { class: 'pole' }, el('span', { text: 'Jméno skupiny' }), jmeno),
      el('label', { class: 'pole' }, el('span', { text: 'Popis' }), popis),
      el('label', { class: 'pole' }, el('span', { text: 'Druh' }), druh),
      el('p', { class: 'maly slabe', text:
        'Přihlašovací jméno skupiny se odvodí z názvu (diakritika se '
        + 'zjednoduší, mezery se změní na pomlčky).' })),
    tlacitka: [{
      text: 'Vytvořit',
      hlavni: true,
      akce: async () => {
        await api('/groups', {
          metoda: 'POST',
          telo: {
            name: jmeno.value.trim(),
            description: popis.value.trim(),
            kind: druh.value,
            ou_id: ouId === 0 ? null : ouId,
          },
        });
        hlas('Skupina vytvořena', jmeno.value.trim(), 'uspech');
        hotovo();
      },
    }],
  });
}

function dialogNovaOu(rodicId, hotovo) {
  const jmeno = el('input', { type: 'text', placeholder: 'Zaci' });
  const popis = el('input', { type: 'text' });
  const chranit = el('input', { type: 'checkbox', checked: true });

  dialog({
    nazev: 'Nová organizační jednotka',
    obsah: el('div', {},
      el('label', { class: 'pole' }, el('span', { text: 'Jméno' }), jmeno),
      el('label', { class: 'pole' }, el('span', { text: 'Popis' }), popis),
      el('label', { class: 'zatrzitko' }, chranit,
        el('span', {}, 'Chránit proti nechtěnému smazání',
          el('span', { class: 'popis', text:
            'Chráněnou OU nelze smazat, dokud ochranu nevypneš.' }))),
      el('p', { class: 'maly slabe', text: rodicId === 0
        ? 'Vytvoří se přímo pod doménou.'
        : 'Vytvoří se jako podřízená vybrané jednotky.' })),
    tlacitka: [{
      text: 'Vytvořit',
      hlavni: true,
      akce: async () => {
        await api('/ous', {
          metoda: 'POST',
          telo: {
            name: jmeno.value.trim(),
            description: popis.value.trim(),
            parent_id: rodicId === 0 ? null : rodicId,
            protected: chranit.checked,
          },
        });
        hlas('Organizační jednotka vytvořena', jmeno.value.trim(), 'uspech');
        await hotovo();
      },
    }],
  });
}

function dialogHeslo(uzivatel, hotovo) {
  const heslo = el('input', { type: 'password', autocomplete: 'new-password' });
  const zmena = el('input', { type: 'checkbox', checked: true });
  const bezHistorie = el('input', { type: 'checkbox' });
  const chyby = el('div', {});

  dialog({
    nazev: `Nastavit heslo — ${uzivatel.sam_account_name}`,
    obsah: el('div', {},
      el('label', { class: 'pole' }, el('span', { text: 'Nové heslo' }), heslo, siloměr(heslo)),
      el('label', { class: 'zatrzitko' }, zmena,
        el('span', { text: 'Musí si změnit heslo při příštím přihlášení' })),
      el('label', { class: 'zatrzitko' }, bezHistorie,
        el('span', {}, 'Nekontrolovat historii hesel',
          el('span', { class: 'popis', text:
            'Pro obnovu zapomenutého hesla. Zásadu složitosti to neobchází.' }))),
      chyby,
      el('p', { class: 'maly slabe', text:
        'Heslo se nikam nevypíše a do auditu se zapíše jen to, že se změnilo.' })),
    tlacitka: [{
      text: 'Nastavit',
      hlavni: true,
      akce: async () => {
        try {
          await api(`/users/${uzivatel.id}/password`, {
            metoda: 'PUT',
            telo: {
              new_password: heslo.value,
              must_change_password: zmena.checked,
              skip_history_check: bezHistorie.checked,
            },
          });
        } catch (e) {
          const seznam = e.detaily?.complaints;
          if (Array.isArray(seznam)) {
            nahrad(chyby, el('div', { class: 'upozorneni error' },
              el('div', { class: 'text' },
                el('div', { class: 'nazev', text: 'Heslo nesplňuje zásady' }),
                el('ul', {}, seznam.map((s) => el('li', { text: popisStiznosti(s) }))))));
            return false;
          }
          throw e;
        }
        hlas('Heslo nastaveno', uzivatel.sam_account_name, 'uspech');
        hotovo();
        return true;
      },
    }],
  });
}

async function dialogClenstvi(uzivatel, hotovo) {
  const [skupiny, moje] = await Promise.all([
    api('/groups?limit=500'),
    api(`/users/${uzivatel.id}/groups`),
  ]);
  const telo = el('div', {});

  const prekresli = async () => {
    const aktualni = await api(`/users/${uzivatel.id}/groups`);
    nahrad(telo, tabulka(['Skupina', 'Členství', ''],
      skupiny.items.map((g) => {
        const je = aktualni.includes(g.name);
        return el('tr', {},
          el('td', {}, ikona('skupina'), ' ', g.name),
          el('td', {}, el('span', {
            class: 'odznacek ' + (je ? 'zapnuto' : 'vypnuto'),
            text: je ? 'je členem' : '—',
          })),
          el('td', {}, el('button', {
            class: 'odkaz', type: 'button', text: je ? 'odebrat' : 'přidat',
            on: {
              click: async () => {
                try {
                  await api(`/groups/${g.id}/members`, {
                    metoda: je ? 'DELETE' : 'POST',
                    telo: { members: [{ kind: 'user', id: uzivatel.id }] },
                  });
                  await prekresli();
                  hotovo();
                } catch (e) { hlasChybu(e); }
              },
            },
          })));
      })));
  };

  dialog({
    nazev: `Členství — ${uzivatel.sam_account_name}`,
    siroky: true,
    obsah: el('div', {},
      el('p', { class: 'maly slabe', text:
        'Členství se počítá i přes vnořené skupiny. Skupina Domain Users '
        + 'se přiřazuje automaticky každému uživateli.' }),
      telo),
    tlacitka: [],
  });
  await prekresli();
  void moje;
}

async function dialogClenoveSkupiny(skupina, hotovo) {
  const telo = el('div', {});
  const pridat = el('select', {});

  const prekresli = async () => {
    const [clenove, uzivatele, podskupiny, pocitace] = await Promise.all([
      api(`/groups/${skupina.id}/members`),
      api('/users?limit=500'),
      api('/groups?limit=500'),
      api('/computers?limit=500'),
    ]);

    nahrad(telo, tabulka(['Člen', 'Typ', ''],
      clenove.map((c) => el('tr', {},
        el('td', {}, ikona(c.kind === 'user' ? 'uzivatel' : c.kind === 'group' ? 'skupina' : 'pocitac'),
          ' ', c.name),
        el('td', { text: nazevDruhu(c.kind) }),
        el('td', {}, el('button', {
          class: 'odkaz', type: 'button', text: 'odebrat',
          on: {
            click: async () => {
              try {
                await api(`/groups/${skupina.id}/members`, {
                  metoda: 'DELETE', telo: { members: [{ kind: c.kind, id: c.id }] },
                });
                await prekresli();
                hotovo();
              } catch (e) { hlasChybu(e); }
            },
          },
        })))),
      { prazdne: 'Skupina je prázdná.' }));

    const jeClen = (kind, id) => clenove.some((c) => c.kind === kind && c.id === id);
    nahrad(pridat,
      el('option', { value: '', text: '— vyber, koho přidat —' }),
      uzivatele.items.filter((u) => !jeClen('user', u.id))
        .map((u) => el('option', { value: `user:${u.id}`, text: `Uživatel: ${u.sam_account_name}` })),
      podskupiny.items.filter((g) => g.id !== skupina.id && !jeClen('group', g.id))
        .map((g) => el('option', { value: `group:${g.id}`, text: `Skupina: ${g.name}` })),
      pocitace.items.filter((p) => !jeClen('computer', p.id))
        .map((p) => el('option', { value: `computer:${p.id}`, text: `Počítač: ${p.name}` })));
  };

  dialog({
    nazev: `Členové — ${skupina.name}`,
    siroky: true,
    obsah: el('div', {},
      telo,
      el('div', { class: 'mezera-nad' },
        el('label', { class: 'pole' }, el('span', { text: 'Přidat člena' }), pridat))),
    tlacitka: [{
      text: 'Přidat',
      hlavni: true,
      akce: async () => {
        if (!pridat.value) return false;
        const [kind, id] = pridat.value.split(':');
        await api(`/groups/${skupina.id}/members`, {
          metoda: 'POST', telo: { members: [{ kind, id: Number(id) }] },
        });
        await prekresli();
        hotovo();
        return false; // dialog necháme otevřený, ať se dá přidat víc
      },
    }],
  });
  await prekresli();
}

function dialogPresun(vybrany, strom, hotovo) {
  const cile = [];
  const projdi = (n) => {
    cile.push({ id: n.ou_id === null ? 0 : n.ou_id, popis: n.ou_id === null ? '(přímo pod doménou)' : n.path });
    n.children.forEach(projdi);
  };
  projdi(strom);

  const vyber = el('select', {}, cile.map((c) => el('option', { value: String(c.id), text: c.popis })));
  const cesta = vybrany.druh === 'user' ? 'users' : vybrany.druh === 'group' ? 'groups' : 'computers';

  dialog({
    nazev: 'Přesunout do jiné organizační jednotky',
    obsah: el('div', {},
      el('p', { text: `Objekt: ${vybrany.druh === 'user' ? vybrany.o.sam_account_name : vybrany.o.name}` }),
      el('label', { class: 'pole' }, el('span', { text: 'Cílová jednotka' }), vyber),
      el('p', { class: 'maly slabe', text:
        'Zásady skupiny se vyhodnocují podle umístění, takže přesun může '
        + 'změnit pravidla, která na objekt platí.' })),
    tlacitka: [{
      text: 'Přesunout',
      hlavni: true,
      akce: async () => {
        const cil = Number(vyber.value);
        await api(`/${cesta}/${vybrany.o.id}/move`, {
          metoda: 'POST', telo: { target_ou_id: cil === 0 ? null : cil },
        });
        hlas('Přesunuto', '', 'uspech');
        await hotovo();
      },
    }],
  });
}

function dialogSmazat(vybrany, hotovo) {
  const jmeno = vybrany.druh === 'user' ? vybrany.o.sam_account_name : vybrany.o.name;
  const cesta = vybrany.druh === 'user' ? 'users' : vybrany.druh === 'group' ? 'groups' : 'computers';
  const vstup = el('input', { type: 'text', class: 'mono' });

  dialog({
    nazev: `Smazat ${nazevDruhu(vybrany.druh).toLowerCase()}`,
    obsah: el('div', {},
      el('p', { text: `Opravdu smazat ${jmeno}? Tohle se nedá vzít zpátky.` }),
      vybrany.druh === 'computer'
        ? el('p', { class: 'maly slabe', text:
            'Počítač se tím odpojí z domény. Na jeho straně zůstane '
            + 'nastavené DNS — vrátí se příkazem ad-client leave.' })
        : null,
      el('label', { class: 'pole' },
        el('span', { text: `Pro potvrzení opiš: ${jmeno}` }), vstup)),
    tlacitka: [{
      text: 'Smazat',
      nebezpecne: true,
      akce: async () => {
        if (vstup.value.trim() !== jmeno) {
          hlas('Jméno nesouhlasí', 'Opiš ho přesně.', 'chyba');
          return false;
        }
        await api(`/${cesta}/${vybrany.o.id}`, { metoda: 'DELETE' });
        hlas('Smazáno', jmeno, 'uspech');
        await hotovo();
        return true;
      },
    }],
  });
}

// =====================================================================
// Správce DNS
// =====================================================================

export async function spravceDns(kontejner) {
  if (!stav.status.roles.dns) {
    nahrad(kontejner,
      el('h2', { class: 'nadpis-stranky', text: 'Správce DNS' }),
      el('div', { class: 'upozorneni warning' },
        el('div', { class: 'text' },
          el('div', { class: 'nazev', text: 'Role DNS není nainstalovaná' }),
          el('div', { class: 'detail', text: 'Zapni ji v průvodci Přidat role a funkce.' }),
          el('button', {
            class: 'odkaz', type: 'button', text: 'Otevřít průvodce →',
            on: { click: () => { location.hash = '#/role'; } },
          }))));
    return;
  }

  let zony = await api('/dns/zones');
  const dnsStav = await api('/dns/status');
  let vybranaZona = zony[0]?.id ?? null;

  const levy = el('div', { class: 'levy-panel' });
  const obsah = el('div', { class: 'obsah-panelu' });
  const nastrojeRadek = el('div', { class: 'panel-nastroju' });

  function vykresliStrom() {
    const skupina = (nazev, druh) => {
      const vlastni = zony.filter((z) => z.kind === druh);
      return el('li', {},
        el('button', { type: 'button', disabled: true },
          ikona('dns'), el('span', { class: 'tucne', text: nazev })),
        el('ul', {}, vlastni.length
          ? vlastni.map((z) => el('li', {},
              el('button', {
                class: z.id === vybranaZona ? 'vybrany' : '',
                type: 'button',
                on: { click: () => { vybranaZona = z.id; prekresli(); } },
              },
                el('span', { text: z.name }),
                z.managed ? el('span', { class: 'pocet', text: '(spravovaná)' }) : null)))
          : el('li', {}, el('button', { type: 'button', disabled: true },
              el('span', { class: 'slabe maly', text: 'žádné zóny' })))));
    };

    nahrad(levy, el('ul', { class: 'strom' },
      el('li', {},
        el('button', { type: 'button', disabled: true },
          ikona('server'), el('span', { class: 'tucne', text: stav.status.hostname })),
        el('ul', {}, skupina('Dopředné zóny', 'forward'), skupina('Reverzní zóny', 'reverse')))));
  }

  async function nacti() {
    if (vybranaZona === null) {
      nahrad(obsah, el('div', { class: 'nacitani', text: 'Žádná zóna. Vytvoř ji vlevo nahoře.' }));
      return;
    }
    const zona = zony.find((z) => z.id === vybranaZona);
    const zaznamy = await api(`/dns/zones/${vybranaZona}/records`);

    const radky = zaznamy.map((z) => el('tr', {},
      el('td', { class: 'mono', text: z.name }),
      el('td', { text: z.type }),
      el('td', { class: 'mono', text: popisZaznamu(z) }),
      el('td', { class: 'cislo', text: String(z.ttl) }),
      el('td', {}, z.managed
        ? el('span', { class: 'odznacek spravovano', text: 'spravovaný' })
        : el('span', { class: 'odznacek vypnuto', text: 'ruční' })),
      el('td', {}, z.managed
        ? el('span', { class: 'maly slabe', text: '—' })
        : el('button', {
            class: 'odkaz', type: 'button', text: 'smazat',
            on: {
              click: async () => {
                try {
                  await api(`/dns/records/${z.id}`, { metoda: 'DELETE' });
                  hlas('Záznam smazán', '', 'uspech');
                  await nacti();
                } catch (e) { hlasChybu(e); }
              },
            },
          }))));

    nahrad(obsah,
      el('div', { class: 'panel-telo' },
        el('dl', { class: 'vlastnosti' },
          el('dt', { text: 'Zóna' }), el('dd', { class: 'mono', text: zona.name }),
          el('dt', { text: 'Druh' }),
          el('dd', { text: zona.kind === 'forward' ? 'dopředná' : 'reverzní' }),
          el('dt', { text: 'Sériové číslo (SOA)' }), el('dd', { text: String(zona.serial) }),
          el('dt', { text: 'Primární server' }), el('dd', { class: 'mono', text: zona.primary_ns }),
          el('dt', { text: 'Kontakt' }), el('dd', { class: 'mono', text: zona.rname }))),
      tabulka(['Jméno', 'Typ', 'Data', 'TTL', 'Původ', ''], radky,
        { prazdne: 'Zóna je prázdná.' }));
  }

  function vykresliNastroje() {
    const zona = zony.find((z) => z.id === vybranaZona);
    nahrad(nastrojeRadek,
      el('button', {
        class: 'tlacitko', type: 'button', text: 'Nová zóna',
        on: { click: () => dialogNovaZona(prekresliCely) },
      }),
      el('button', {
        class: 'tlacitko', type: 'button', text: 'Nový záznam', disabled: !zona,
        on: { click: () => dialogNovyZaznam(zona, nacti) },
      }),
      el('button', {
        class: 'tlacitko nebezpecne', type: 'button', text: 'Smazat zónu',
        disabled: !zona || zona.managed,
        on: {
          click: async () => {
            try {
              await api(`/dns/zones/${zona.id}`, { metoda: 'DELETE' });
              hlas('Zóna smazána', zona.name, 'uspech');
              vybranaZona = null;
              await prekresliCely();
            } catch (e) { hlasChybu(e); }
          },
        },
      }),
      el('span', { class: 'mezera' }),
      zona?.managed
        ? el('span', { class: 'maly slabe', text:
            'Spravovanou zónu vytvořil server při povýšení — nedá se smazat, '
            + 'dokud doména existuje.' })
        : null);
  }

  async function prekresliCely() {
    zony = await api('/dns/zones');
    if (!zony.some((z) => z.id === vybranaZona)) vybranaZona = zony[0]?.id ?? null;
    prekresli();
  }

  function prekresli() {
    vykresliStrom();
    vykresliNastroje();
    nacti().catch(hlasChybu);
  }

  // --- přeposílání a stav ---
  const poleForwardery = el('input', {
    type: 'text', value: (dnsStav.forwarders || []).join(', '),
    placeholder: '1.1.1.1, 8.8.8.8',
  });

  const panelForwarderu = panel('Přeposílání dotazů', el('div', {},
    el('p', { class: 'maly slabe', text:
      'Dotazy na jména mimo naše zóny server přepošle na tyhle adresy. '
      + 'Prázdný seznam znamená, že se takové dotazy odmítnou.' }),
    el('label', { class: 'pole' },
      el('span', { text: 'IP adresy oddělené čárkou (nejvýš čtyři)' }), poleForwardery),
    dnsStav.original_forwarders?.length
      ? el('p', { class: 'maly slabe' },
          el('span', { text: 'Co měl systém nastavené před námi: ' }),
          el('span', { class: 'mono', text: dnsStav.original_forwarders.join(', ') }))
      : null,
    el('div', { class: 'radek-tlacitek' },
      el('button', {
        class: 'tlacitko hlavni', type: 'button', text: 'Uložit',
        on: {
          click: async () => {
            try {
              const seznam = poleForwardery.value.split(',').map((s) => s.trim()).filter(Boolean);
              await api('/dns/forwarders', { metoda: 'PUT', telo: { forwarders: seznam } });
              hlas('Přeposílání uloženo', seznam.join(', ') || 'žádné', 'uspech');
            } catch (e) { hlasChybu(e); }
          },
        },
      }))));

  const panelStavu = panel('Stav DNS serveru', el('div', {},
    el('dl', { class: 'vlastnosti' },
      el('dt', { text: 'Poslouchá' }),
      el('dd', {}, el('span', {
        class: 'odznacek ' + (dnsStav.running ? 'zapnuto' : 'zamceno'),
        text: dnsStav.running ? 'ano' : 'ne',
      })),
      el('dt', { text: 'Adresa' }),
      el('dd', { class: 'mono', text: (dnsStav.listen || []).join(', ') }),
      el('dt', { text: 'Dotazů celkem' }), el('dd', { text: String(dnsStav.queries_total) }),
      el('dt', { text: 'Z našich zón' }),
      el('dd', { text: String(dnsStav.queries_authoritative ?? 0) }),
      el('dt', { text: 'Přeposláno' }), el('dd', { text: String(dnsStav.queries_forwarded) }),
      el('dt', { text: 'Ze zapamatovaných' }),
      el('dd', { text: String(dnsStav.queries_cached ?? 0) }),
      el('dt', { text: 'Neexistující jméno' }),
      el('dd', { text: String(dnsStav.queries_nxdomain ?? 0) }),
      el('dt', { text: 'Odmítnuto' }), el('dd', { text: String(dnsStav.queries_refused) }),
      el('dt', { text: 'V paměti odpovědí' }), el('dd', { text: String(dnsStav.cache_entries) })),
    dnsStav.running
      ? el('p', { class: 'maly slabe', text:
          'Vyzkoušej z jiného stroje: dig @<adresa serveru> dc01.<doména>' })
      : el('div', { class: 'upozorneni warning' },
          el('div', { class: 'text' },
            el('div', { class: 'nazev', text: 'DNS server neposlouchá' }),
            el('div', { class: 'detail', text:
              'Nejčastěji je obsazený port 53 (systemd-resolved) nebo chybí '
              + 'oprávnění na port pod 1024. Podrobnost je v logu serveru.' })))));

  nahrad(kontejner,
    el('h2', { class: 'nadpis-stranky', text: 'Správce DNS' }),
    el('div', { class: 'dva-panely' },
      levy,
      el('div', { class: 'pravy-panel' }, nastrojeRadek, obsah)),
    el('div', { class: 'mrizka mezera-nad' }, panelForwarderu, panelStavu));

  prekresli();
}

function popisZaznamu(z) {
  switch (z.type) {
    case 'A': case 'AAAA': return z.address;
    case 'CNAME': case 'PTR': case 'NS': return z.target;
    case 'MX': return `${z.preference} ${z.target}`;
    case 'SRV': return `${z.priority} ${z.weight} ${z.port} ${z.target}`;
    case 'TXT': return z.text;
    default: return JSON.stringify(z);
  }
}

function dialogNovaZona(hotovo) {
  const druh = el('select', {},
    el('option', { value: 'forward', text: 'Dopředná (jméno → adresa)' }),
    el('option', { value: 'reverse', text: 'Reverzní (adresa → jméno)' }));
  const jmeno = el('input', { type: 'text', placeholder: 'pokus.internal' });
  const sit = el('input', { type: 'text', placeholder: '192.168.56.0/24' });
  const obalJmeno = el('label', { class: 'pole' }, el('span', { text: 'Jméno zóny' }), jmeno);
  const obalSit = el('label', { class: 'pole skryto' },
    el('span', { text: 'Síť v zápisu CIDR (maska /8, /16 nebo /24)' }), sit);

  druh.addEventListener('change', () => {
    obalJmeno.classList.toggle('skryto', druh.value === 'reverse');
    obalSit.classList.toggle('skryto', druh.value !== 'reverse');
  });

  dialog({
    nazev: 'Nová zóna',
    obsah: el('div', {},
      el('label', { class: 'pole' }, el('span', { text: 'Druh zóny' }), druh),
      obalJmeno, obalSit),
    tlacitka: [{
      text: 'Vytvořit',
      hlavni: true,
      akce: async () => {
        await api('/dns/zones', {
          metoda: 'POST',
          telo: druh.value === 'reverse'
            ? { kind: 'reverse', network: sit.value.trim() }
            : { kind: 'forward', name: jmeno.value.trim() },
        });
        hlas('Zóna vytvořena', '', 'uspech');
        await hotovo();
      },
    }],
  });
}

function dialogNovyZaznam(zona, hotovo) {
  const typ = el('select', {},
    ['A', 'AAAA', 'CNAME', 'PTR', 'TXT', 'NS', 'MX', 'SRV']
      .map((t) => el('option', { value: t, text: t })));
  const jmeno = el('input', { type: 'text', value: '@', class: 'mono' });
  const ttl = el('input', { type: 'number', value: '3600', min: '30', max: '604800' });
  const pole = el('div', {});

  const vstupy = {};
  function vykresliPole() {
    const t = typ.value;
    const pridej = (klic, nazev, placeholder = '', cislo = false) => {
      vstupy[klic] = el('input', {
        type: cislo ? 'number' : 'text', placeholder, class: cislo ? '' : 'mono',
        value: cislo ? '0' : '',
      });
      return el('label', { class: 'pole' }, el('span', { text: nazev }), vstupy[klic]);
    };
    for (const k of Object.keys(vstupy)) delete vstupy[k];

    if (t === 'A') nahrad(pole, pridej('address', 'IPv4 adresa', '192.168.56.20'));
    else if (t === 'AAAA') nahrad(pole, pridej('address', 'IPv6 adresa', '2001:db8::1'));
    else if (t === 'TXT') nahrad(pole, pridej('text', 'Text', 'v=ad1'));
    else if (t === 'MX') {
      nahrad(pole, pridej('preference', 'Priorita', '', true),
        pridej('target', 'Cílové jméno (plné)', 'mail.skola.internal'));
    } else if (t === 'SRV') {
      nahrad(pole, pridej('priority', 'Priorita', '', true),
        pridej('weight', 'Váha', '', true),
        pridej('port', 'Port', '', true),
        pridej('target', 'Cílové jméno (plné)', 'dc01.skola.internal'));
    } else nahrad(pole, pridej('target', 'Cílové jméno (plné)', 'dc01.skola.internal'));
  }
  typ.addEventListener('change', vykresliPole);
  vykresliPole();

  dialog({
    nazev: `Nový záznam v zóně ${zona.name}`,
    obsah: el('div', {},
      el('div', { class: 'radek-poli' },
        el('label', { class: 'pole' },
          el('span', { text: 'Jméno (relativně k zóně, @ = vrchol)' }), jmeno),
        el('label', { class: 'pole' }, el('span', { text: 'Typ' }), typ),
        el('label', { class: 'pole' }, el('span', { text: 'TTL (sekundy)' }), ttl)),
      pole,
      el('p', { class: 'maly slabe', text:
        'Cílová jména musí být plná, včetně domény. CNAME nemůže být na '
        + 'jméně, kde už je jiný záznam.' })),
    tlacitka: [{
      text: 'Vytvořit',
      hlavni: true,
      akce: async () => {
        const data = { type: typ.value };
        for (const [klic, vstup] of Object.entries(vstupy)) {
          data[klic] = ['preference', 'priority', 'weight', 'port'].includes(klic)
            ? Number(vstup.value) : vstup.value.trim();
        }
        await api(`/dns/zones/${zona.id}/records`, {
          metoda: 'POST',
          telo: { name: jmeno.value.trim() || '@', ttl: Number(ttl.value), ...data },
        });
        hlas('Záznam vytvořen', '', 'uspech');
        await hotovo();
      },
    }],
  });
}

// =====================================================================
// Správa zásad skupiny
// =====================================================================

export async function spravaZasad(kontejner) {
  if (stav.status.stage !== 'domain_controller') {
    nahrad(kontejner, bezDomeny('Správa zásad skupiny'));
    return;
  }

  let zasady = await api('/gpos?limit=200');
  let odkazy = await api('/gpos/links');
  const ou = await api('/ous');
  let vybrana = zasady.items[0]?.id ?? null;

  const levy = el('div', { class: 'levy-panel' });
  const obsah = el('div', { class: 'obsah-panelu' });
  const nastrojeRadek = el('div', { class: 'panel-nastroju' });

  function vykresliStrom() {
    nahrad(levy, el('ul', { class: 'strom' },
      el('li', {},
        el('button', { type: 'button', disabled: true },
          ikona('domena'), el('span', { class: 'tucne', text: stav.status.domain.dns_name })),
        el('ul', {}, zasady.items.length
          ? zasady.items.map((z) => el('li', {},
              el('button', {
                class: z.id === vybrana ? 'vybrany' : '',
                type: 'button',
                on: { click: () => { vybrana = z.id; prekresli(); } },
              },
                ikona('zasada'),
                el('span', { text: z.name }),
                z.enabled ? null : el('span', { class: 'pocet', text: '(vypnutá)' }))))
          : el('li', {}, el('button', { type: 'button', disabled: true },
              el('span', { class: 'slabe maly', text: 'žádné zásady' })))))));
  }

  function popisCile(cil) {
    if (cil.scope === 'domain') return 'celá doména';
    const nalezena = ou.find((o) => o.id === cil.ou_id);
    return nalezena ? nalezena.path : `OU ${cil.ou_id}`;
  }

  function vykresliObsah() {
    if (vybrana === null) {
      nahrad(obsah, el('div', { class: 'nacitani', text:
        'Zatím není žádná zásada. Vytvoř ji tlačítkem Nová zásada.' }));
      return;
    }
    const z = zasady.items.find((x) => x.id === vybrana);
    const mojeOdkazy = odkazy.filter((o) => o.gpo_id === z.id);

    nahrad(obsah,
      el('div', { class: 'panel-telo' },
        el('dl', { class: 'vlastnosti' },
          el('dt', { text: 'Jméno' }), el('dd', { text: z.name }),
          el('dt', { text: 'Popis' }), el('dd', { text: z.description || '—' }),
          el('dt', { text: 'Stav' }),
          el('dd', {}, el('span', {
            class: 'odznacek ' + (z.enabled ? 'zapnuto' : 'vypnuto'),
            text: z.enabled ? 'zapnutá' : 'vypnutá',
          })),
          el('dt', { text: 'Identifikátor' }), el('dd', { class: 'mono', text: z.guid }),
          el('dt', { text: 'Změněna' }), el('dd', { text: datum(z.modified_at) }))),

      panel('Co zásada nastavuje', el('div', {}, prehledNastaveni(z.settings)), { bezRamu: false }),

      panel('Připojení', el('div', {},
        tabulka(['Kam', 'Pořadí', 'Vynuceno', 'Stav', ''],
          mojeOdkazy.map((o) => el('tr', {},
            el('td', { text: popisCile(o.target) }),
            el('td', { class: 'cislo', text: String(o.order) }),
            el('td', { text: o.enforced ? 'ano' : 'ne' }),
            el('td', { text: o.enabled ? 'zapnuté' : 'vypnuté' }),
            el('td', {}, el('button', {
              class: 'odkaz', type: 'button', text: 'odpojit',
              on: {
                click: async () => {
                  try {
                    await api(`/gpos/links/${o.id}`, { metoda: 'DELETE' });
                    hlas('Odpojeno', '', 'uspech');
                    await prekresliCely();
                  } catch (e) { hlasChybu(e); }
                },
              },
            })))),
          { prazdne: 'Zásada není nikam připojená, takže na nikoho neplatí.' }),
        el('div', { class: 'radek-tlacitek' },
          el('button', {
            class: 'tlacitko', type: 'button', text: 'Připojit k…',
            on: { click: () => dialogPripojit(z, ou, prekresliCely) },
          }))), { bezRamu: true }),

      panel('Výsledná sada zásad', vysledneZasady(ou)));
  }

  function prehledNastaveni(s) {
    const casti = [];
    if (s.password) {
      const p = s.password;
      casti.push(radekNastaveni('Pravidla hesel', [
        `nejméně ${p.min_length} znaků`,
        p.require_uppercase ? 'velké písmeno' : null,
        p.require_lowercase ? 'malé písmeno' : null,
        p.require_digit ? 'číslice' : null,
        p.require_symbol ? 'symbol' : null,
        p.forbid_username ? 'nesmí obsahovat jméno' : null,
        p.max_age_days ? `platnost ${p.max_age_days} dní` : 'bez vypršení',
        p.history_length ? `historie ${p.history_length} hesel` : 'bez historie',
      ].filter(Boolean).join(', ')));
    }
    if (s.lockout) {
      const l = s.lockout;
      casti.push(radekNastaveni('Zamykání účtu', l.threshold === 0
        ? 'vypnuté'
        : `po ${l.threshold} chybách v ${l.window_minutes} min zamknout na ${l.duration_minutes} min`));
    }
    if (s.welcome) {
      casti.push(radekNastaveni('Uvítací zpráva', s.welcome.enabled
        ? `„${s.welcome.title}“`
        : 'vypnutá'));
    }
    if (s.wallpaper) {
      casti.push(radekNastaveni('Tapeta', s.wallpaper.enabled ? 'zapnutá' : 'vypnutá'));
    }
    if (casti.length === 0) {
      casti.push(el('p', { class: 'slabe', text:
        'Zásada nic nenastavuje — hodnoty se vezmou z nadřazené úrovně.' }));
    }
    return casti;
  }

  function radekNastaveni(nazev, text) {
    return el('div', { class: 'upozorneni info' },
      el('div', { class: 'text' },
        el('div', { class: 'nazev', text: nazev }),
        el('div', { class: 'detail', text })));
  }

  function vysledneZasady(seznamOu) {
    const vyber = el('select', {},
      el('option', { value: '', text: 'celá doména (bez OU)' }),
      seznamOu.map((o) => el('option', { value: String(o.id), text: o.path })));
    const vystup = el('div', {});

    const nacti = async () => {
      const q = vyber.value ? `?ou_id=${vyber.value}` : '';
      const data = await api('/gpos/effective' + q);
      const p = data.policy;
      nahrad(vystup,
        el('dl', { class: 'vlastnosti' },
          el('dt', { text: 'Minimální délka hesla' }), el('dd', { text: String(p.password.min_length) }),
          el('dt', { text: 'Složitost' }),
          el('dd', { text: [
            p.password.require_uppercase ? 'velké' : null,
            p.password.require_lowercase ? 'malé' : null,
            p.password.require_digit ? 'číslice' : null,
            p.password.require_symbol ? 'symbol' : null,
          ].filter(Boolean).join(', ') || 'bez požadavků' }),
          el('dt', { text: 'Historie hesel' }), el('dd', { text: String(p.password.history_length) }),
          el('dt', { text: 'Platnost hesla' }),
          el('dd', { text: p.password.max_age_days ? `${p.password.max_age_days} dní` : 'neomezená' }),
          el('dt', { text: 'Zamykání' }),
          el('dd', { text: p.lockout.threshold === 0 ? 'vypnuté'
            : `${p.lockout.threshold} chyb / ${p.lockout.window_minutes} min → ${p.lockout.duration_minutes} min` }),
          el('dt', { text: 'Uvítací zpráva' }),
          el('dd', { text: p.welcome.enabled ? p.welcome.title || '(bez titulku)' : 'vypnutá' }),
          el('dt', { text: 'Tapeta' }), el('dd', { text: p.wallpaper.enabled ? 'zapnutá' : 'vypnutá' }),
          el('dt', { text: 'Sériové číslo' }), el('dd', { text: String(data.serial) })),
        el('p', { class: 'maly slabe', text: p.applied.length
          ? 'Použité zásady v pořadí: ' + p.applied
              .map((a) => a.name + (a.enforced ? ' (vynucená)' : '')).join(' → ')
          : 'Žádná zásada se nepoužila, platí výchozí hodnoty serveru.' }));
    };
    vyber.addEventListener('change', () => nacti().catch(hlasChybu));
    nacti().catch(hlasChybu);

    return el('div', {},
      el('p', { class: 'maly slabe', text:
        'Takhle vypadají pravidla po vyhodnocení všech připojených zásad. '
        + 'Blíž k objektu přebíjí, vynucená zásada přebíjí vše.' }),
      el('label', { class: 'pole' }, el('span', { text: 'Pro umístění' }), vyber),
      vystup);
  }

  function vykresliNastroje() {
    const z = zasady.items.find((x) => x.id === vybrana);
    nahrad(nastrojeRadek,
      el('button', {
        class: 'tlacitko', type: 'button', text: 'Nová zásada',
        on: { click: () => dialogZasada(null, prekresliCely) },
      }),
      el('button', {
        class: 'tlacitko', type: 'button', text: 'Upravit', disabled: !z,
        on: { click: () => dialogZasada(z, prekresliCely) },
      }),
      el('button', {
        class: 'tlacitko', type: 'button', disabled: !z,
        text: z?.enabled ? 'Vypnout' : 'Zapnout',
        on: {
          click: async () => {
            try {
              await api(`/gpos/${z.id}`, { metoda: 'PATCH', telo: { enabled: !z.enabled } });
              await prekresliCely();
            } catch (e) { hlasChybu(e); }
          },
        },
      }),
      el('button', {
        class: 'tlacitko nebezpecne', type: 'button', text: 'Smazat', disabled: !z,
        on: {
          click: async () => {
            try {
              await api(`/gpos/${z.id}`, { metoda: 'DELETE' });
              hlas('Zásada smazána', z.name, 'uspech');
              vybrana = null;
              await prekresliCely();
            } catch (e) { hlasChybu(e); }
          },
        },
      }));
  }

  async function prekresliCely() {
    zasady = await api('/gpos?limit=200');
    odkazy = await api('/gpos/links');
    if (!zasady.items.some((z) => z.id === vybrana)) vybrana = zasady.items[0]?.id ?? null;
    prekresli();
  }

  function prekresli() {
    vykresliStrom();
    vykresliNastroje();
    vykresliObsah();
  }

  nahrad(kontejner,
    el('h2', { class: 'nadpis-stranky', text: 'Správa zásad skupiny' }),
    el('p', { class: 'maly slabe', text:
      'Zásada je sada hodnot, nikdy ne příkaz ke spuštění. Server klientovi '
      + 'posílá jen tyhle položky a klient si je po přijetí znovu zkontroluje.' }),
    el('div', { class: 'dva-panely' },
      levy,
      el('div', { class: 'pravy-panel' }, nastrojeRadek, obsah)));

  prekresli();
}

function dialogPripojit(zasada, seznamOu, hotovo) {
  const kam = el('select', {},
    el('option', { value: 'domain', text: 'Celá doména' }),
    seznamOu.map((o) => el('option', { value: String(o.id), text: `OU ${o.path}` })));
  const vynuceno = el('input', { type: 'checkbox' });

  dialog({
    nazev: `Připojit zásadu ${zasada.name}`,
    obsah: el('div', {},
      el('label', { class: 'pole' }, el('span', { text: 'Kam připojit' }), kam),
      el('label', { class: 'zatrzitko' }, vynuceno,
        el('span', {}, 'Vynuceno',
          el('span', { class: 'popis', text:
            'Vynucená zásada přebije i zásady z nižších organizačních jednotek.' }))),
      el('p', { class: 'maly slabe', text:
        'Zásada platí na objekty v daném umístění a ve všech jeho podřízených '
        + 'jednotkách.' })),
    tlacitka: [{
      text: 'Připojit',
      hlavni: true,
      akce: async () => {
        await api(`/gpos/${zasada.id}/links`, {
          metoda: 'POST',
          telo: {
            target: kam.value === 'domain'
              ? { scope: 'domain' }
              : { scope: 'ou', ou_id: Number(kam.value) },
            enforced: vynuceno.checked,
            enabled: true,
          },
        });
        hlas('Zásada připojena', zasada.name, 'uspech');
        await hotovo();
      },
    }],
  });
}

function dialogZasada(zasada, hotovo) {
  const jeNova = zasada === null;
  const s = zasada?.settings || {};

  const jmeno = el('input', { type: 'text', value: zasada?.name || '', placeholder: 'Silná hesla' });
  const popis = el('input', { type: 'text', value: zasada?.description || '' });

  // --- hesla ---
  const zapHesla = el('input', { type: 'checkbox', checked: Boolean(s.password) });
  const p = s.password || {
    min_length: 10, require_uppercase: true, require_lowercase: true,
    require_digit: true, require_symbol: false, max_age_days: 0, min_age_days: 0,
    history_length: 3, forbid_username: true,
  };
  const minDelka = el('input', { type: 'number', value: String(p.min_length), min: '4', max: '128' });
  const velke = el('input', { type: 'checkbox', checked: p.require_uppercase });
  const male = el('input', { type: 'checkbox', checked: p.require_lowercase });
  const cislice = el('input', { type: 'checkbox', checked: p.require_digit });
  const symbol = el('input', { type: 'checkbox', checked: p.require_symbol });
  const bezJmena = el('input', { type: 'checkbox', checked: p.forbid_username });
  const platnost = el('input', { type: 'number', value: String(p.max_age_days), min: '0', max: '3650' });
  const minVek = el('input', { type: 'number', value: String(p.min_age_days), min: '0', max: '365' });
  const historie = el('input', { type: 'number', value: String(p.history_length), min: '0', max: '24' });

  // --- zamykání ---
  const zapZamykani = el('input', { type: 'checkbox', checked: Boolean(s.lockout) });
  const l = s.lockout || { threshold: 5, window_minutes: 15, duration_minutes: 15 };
  const pocetPokusu = el('input', { type: 'number', value: String(l.threshold), min: '0', max: '100' });
  const okno = el('input', { type: 'number', value: String(l.window_minutes), min: '1', max: '1440' });
  const doba = el('input', { type: 'number', value: String(l.duration_minutes), min: '1', max: '10080' });

  // --- uvítací zpráva ---
  const zapZprava = el('input', { type: 'checkbox', checked: Boolean(s.welcome) });
  const w = s.welcome || { enabled: true, title: '', body: '' };
  const zapnutaZprava = el('input', { type: 'checkbox', checked: w.enabled });
  const titulek = el('input', { type: 'text', value: w.title, maxlength: '120' });
  const text = el('textarea', { maxlength: '2000' });
  text.value = w.body;

  const skupina = (zatrzitko, nazev, obsahPoli, popisek) => {
    const obal = el('div', { class: 'panel' },
      el('h3', {}, el('label', { class: 'zatrzitko' }, zatrzitko, el('span', { text: nazev }))),
      el('div', { class: 'panel-telo' }, obsahPoli,
        popisek ? el('p', { class: 'maly slabe', text: popisek }) : null));
    const prepni = () => {
      for (const vstup of obal.querySelectorAll('.panel-telo input, .panel-telo textarea')) {
        vstup.disabled = !zatrzitko.checked;
      }
    };
    zatrzitko.addEventListener('change', prepni);
    prepni();
    return obal;
  };

  dialog({
    nazev: jeNova ? 'Nová zásada skupiny' : `Upravit zásadu — ${zasada.name}`,
    siroky: true,
    obsah: el('div', {},
      el('div', { class: 'radek-poli' },
        el('label', { class: 'pole' }, el('span', { text: 'Jméno zásady' }), jmeno),
        el('label', { class: 'pole' }, el('span', { text: 'Popis' }), popis)),

      skupina(zapHesla, 'Pravidla hesel', el('div', {},
        el('div', { class: 'radek-poli' },
          el('label', { class: 'pole' }, el('span', { text: 'Minimální délka' }), minDelka),
          el('label', { class: 'pole' }, el('span', { text: 'Platnost ve dnech (0 = neomezená)' }), platnost),
          el('label', { class: 'pole' }, el('span', { text: 'Nejdřív měnit po dnech' }), minVek),
          el('label', { class: 'pole' }, el('span', { text: 'Pamatovat posledních hesel' }), historie)),
        el('label', { class: 'zatrzitko' }, velke, el('span', { text: 'Vyžadovat velké písmeno' })),
        el('label', { class: 'zatrzitko' }, male, el('span', { text: 'Vyžadovat malé písmeno' })),
        el('label', { class: 'zatrzitko' }, cislice, el('span', { text: 'Vyžadovat číslici' })),
        el('label', { class: 'zatrzitko' }, symbol, el('span', { text: 'Vyžadovat symbol' })),
        el('label', { class: 'zatrzitko' }, bezJmena,
          el('span', { text: 'Heslo nesmí obsahovat přihlašovací jméno' }))),
        'Nezatržená skupina znamená „tato zásada o tom nerozhoduje“ — hodnota se vezme z nadřazené úrovně.'),

      skupina(zapZamykani, 'Zamykání účtu', el('div', { class: 'radek-poli' },
        el('label', { class: 'pole' }, el('span', { text: 'Počet chyb (0 = nezamykat)' }), pocetPokusu),
        el('label', { class: 'pole' }, el('span', { text: 'Okno v minutách' }), okno),
        el('label', { class: 'pole' }, el('span', { text: 'Zamknout na minut' }), doba))),

      skupina(zapZprava, 'Uvítací zpráva', el('div', {},
        el('label', { class: 'zatrzitko' }, zapnutaZprava,
          el('span', { text: 'Zprávu zobrazovat' })),
        el('label', { class: 'pole' }, el('span', { text: 'Titulek' }), titulek),
        el('label', { class: 'pole' }, el('span', { text: 'Text' }), text)),
        'Čistý text. Řídicí znaky server odmítne, aby se nedal podvrhnout výpis v klientovi.'),

      el('div', { class: 'panel' },
        el('h3', { text: 'Tapeta' }),
        el('div', { class: 'panel-telo' },
          el('p', { class: 'slabe', text:
            'Nahrávání obrázku a jeho rozesílání klientům přijde ve fázi 5. '
            + 'Struktura zásady je hotová, jen chybí nahrání souboru.' })))),
    tlacitka: [{
      text: jeNova ? 'Vytvořit' : 'Uložit',
      hlavni: true,
      akce: async () => {
        const nastaveni = {};
        if (zapHesla.checked) {
          nastaveni.password = {
            min_length: Number(minDelka.value),
            require_uppercase: velke.checked,
            require_lowercase: male.checked,
            require_digit: cislice.checked,
            require_symbol: symbol.checked,
            max_age_days: Number(platnost.value),
            min_age_days: Number(minVek.value),
            history_length: Number(historie.value),
            forbid_username: bezJmena.checked,
          };
        }
        if (zapZamykani.checked) {
          nastaveni.lockout = {
            threshold: Number(pocetPokusu.value),
            window_minutes: Number(okno.value),
            duration_minutes: Number(doba.value),
          };
        }
        if (zapZprava.checked) {
          nastaveni.welcome = {
            enabled: zapnutaZprava.checked,
            title: titulek.value,
            body: text.value,
          };
        }

        if (jeNova) {
          await api('/gpos', {
            metoda: 'POST',
            telo: {
              name: jmeno.value.trim(),
              description: popis.value.trim(),
              settings: nastaveni,
              enabled: true,
            },
          });
          hlas('Zásada vytvořena', jmeno.value.trim(), 'uspech');
        } else {
          await api(`/gpos/${zasada.id}`, {
            metoda: 'PATCH',
            telo: {
              name: jmeno.value.trim(),
              description: popis.value.trim(),
              settings: nastaveni,
            },
          });
          hlas('Zásada uložena', jmeno.value.trim(), 'uspech');
        }
        await hotovo();
      },
    }],
  });
}
