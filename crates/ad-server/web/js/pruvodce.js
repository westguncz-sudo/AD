// Rám průvodce: vlevo seznam kroků, vpravo obsah, dole tlačítka.
// Stejný postup jako průvodci ve Správci serveru — proklikáš se kroky
// a na konci je stránka s výsledkem.

import { el, hlasChybu, nahrad } from './jadro.js';

/**
 * @param {Element} kontejner kam se průvodce vykreslí
 * @param {object} nastaveni
 *   nazev, cil, data, kroky: [{ nazev, vykresli(data, prekresli), overit(data),
 *   dalsiText, akce(data) }]
 */
export function pruvodce(kontejner, { nazev, cil, data, kroky }) {
  let index = 0;
  let pracuje = false;

  function vykresli() {
    const krok = kroky[index];
    const seznamKroku = el('div', { class: 'pruvodce-kroky' },
      kroky.map((k, i) => el('div', {
        class: i === index ? 'aktivni' : i < index ? 'hotovy' : '',
        text: k.nazev,
      })));

    const obsahKroku = el('div', { class: 'pruvodce-obsah' }, krok.vykresli(data, vykresli));

    const tlacitka = el('div', { class: 'radek-tlacitek' });
    if (index > 0 && !krok.konec) {
      tlacitka.append(el('button', {
        class: 'tlacitko', type: 'button', text: '< Předchozí', disabled: pracuje,
        on: { click: () => { index -= 1; vykresli(); } },
      }));
    }
    if (index < kroky.length - 1) {
      tlacitka.append(el('button', {
        class: 'tlacitko hlavni', type: 'button',
        text: krok.dalsiText || 'Další >',
        disabled: pracuje || (krok.dalsiMozne ? !krok.dalsiMozne(data) : false),
        on: {
          click: async () => {
            const chyba = krok.overit?.(data);
            if (chyba) { hlasChybu(Object.assign(new Error(chyba), { kod: 'vstup' })); return; }
            if (krok.akce) {
              pracuje = true;
              vykresli();
              try {
                await krok.akce(data);
              } catch (e) {
                pracuje = false;
                hlasChybu(e);
                vykresli();
                return;
              }
              pracuje = false;
            }
            index += 1;
            vykresli();
          },
        },
      }));
    }
    if (krok.zrusit !== false) {
      tlacitka.append(el('button', {
        class: 'tlacitko', type: 'button', text: 'Zrušit', disabled: pracuje,
        on: { click: () => { location.hash = '#/prehled'; } },
      }));
    }

    nahrad(kontejner,
      el('h2', { class: 'nadpis-stranky', text: nazev }),
      el('div', { class: 'pruvodce' },
        el('div', { class: 'pruvodce-hlavicka' },
          el('h3', { text: krok.nazev }),
          cil ? el('div', { class: 'cil', text: cil }) : null),
        el('div', { class: 'pruvodce-telo' }, seznamKroku, obsahKroku),
        tlacitka));
  }

  vykresli();
}

/** Posune průvodce na konec (stránka s výsledkem). */
export function stranka(nadpis, popis, ...obsah) {
  return el('div', {},
    el('h4', { text: nadpis }),
    popis ? el('p', { text: popis }) : null,
    obsah);
}
