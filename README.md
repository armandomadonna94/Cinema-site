# Cinema Lumière – area amministrativa

Server Node.js **senza dipendenze** (serve Node 22.13 o più recente) con database SQLite integrato.

## Avvio (Windows, Mac e Linux)

1. Installa Node.js (versione LTS, 22.13 o più recente) da https://nodejs.org
2. Apri il terminale **dentro la cartella `cinema-admin`** (su Windows: apri la cartella, clic sulla barra del percorso, scrivi `cmd` e premi Invio).
3. Scrivi `node server.js` e premi Invio.
4. Al **primo avvio** ti chiede email e password del proprietario (password di almeno 12 caratteri, salvata solo come hash).
5. Lascia la finestra aperta: finché è aperta il sito funziona. Poi apri nel browser:

- Sito pubblico: http://127.0.0.1:3000
- Login proprietario: http://127.0.0.1:3000/admin/login
- Pannello film: http://127.0.0.1:3000/admin

## Variabili d'ambiente

| Variabile | Significato |
|---|---|
| `PORT` / `HOST` | porta (3000) e indirizzo (127.0.0.1) |
| `COOKIE_SECURE=1` | **obbligatoria in produzione con HTTPS** |
| `TRUST_PROXY=1` | solo se sei dietro un reverse proxy fidato (Nginx, Caddy) |
| `DATA_DIR` | dove salvare database e locandine (default `./data`) |

## Pubblicarlo online
Mettilo su un server/VPS (o servizi come Render, Railway, Fly.io con un disco persistente) dietro HTTPS
(Caddy o Nginx), con `HOST=127.0.0.1`, `COOKIE_SECURE=1` e `TRUST_PROXY=1`. Fai backup della cartella `data/`.

## Collegare il tuo sito di prenotazione
L'API pubblica è `GET /api/films` e restituisce **solo** i film pubblicati:
`[{ id, title, genre, duration, description, poster, times: ["17:30", ...] }]`.
Nel tuo file del sito sostituisci l'array `FILMS` con:

```js
let FILMS = [];
fetch("/api/films").then(r => r.json()).then(list => {
  FILMS = list.map(f => ({ id: f.id, title: f.title, genre: f.genre, dur: f.duration + " min",
                           times: f.times, poster: f.poster, c: ["#3a1c71", "#d76d77"] }));
  renderFilms();
});
```
(e nel disegno della locandina usa `<img src="${f.poster}">` quando `f.poster` esiste).

### Prezzi
Ogni film arriva con `prices: { front, mid, back }` (file A–B, C–D, E–F), già calcolati: prezzo personalizzato del film se
esiste, altrimenti quello standard. Nel tuo sito collega la mappa dei prezzi per fila al film scelto:

```js
const P = state.film.prices;
const PRICE = { A: P.front, B: P.front, C: P.mid, D: P.mid, E: P.back, F: P.back };
```
Dal pannello `/admin` il proprietario cambia i **prezzi standard** e, per ogni film, può impostare prezzi propri
(le zone lasciate vuote usano lo standard). Le modifiche valgono subito per le nuove prenotazioni.
Quando collegherai il pagamento vero, il server dovrà **ricalcolare il totale con questi prezzi** e non fidarsi del totale
inviato dal browser.
Il sito e il server devono stare sullo stesso dominio.

## Cambiare la password
```bash
ADMIN_EMAIL="tu@tuocinema.it" NEW_PASSWORD="nuova-password-lunga" node set-password.js
```

## Con Docker (Render, Railway, Fly.io...)
Il `Dockerfile` è già pronto. Imposta `ADMIN_EMAIL` e `ADMIN_PASSWORD` come variabili segrete nel pannello del servizio
(solo al primo avvio) e collega un **disco persistente** montato su `/data`, altrimenti database e locandine si cancellano a ogni riavvio.

## Se qualcosa non funziona
- **Non apri file `.html` con doppio clic:** il sito funziona solo se il server è acceso e lo apri da `http://127.0.0.1:3000`.
- **`ERR_CONNECTION_REFUSED`:** il server non è acceso, oppure la finestra del terminale è stata chiusa.
- **Errore su `node:sqlite`:** Node.js è troppo vecchio, aggiornalo.
- **Login che torna sempre alla pagina di accesso:** hai impostato `COOKIE_SECURE=1` ma stai usando `http://` invece di HTTPS. In locale non impostarla.
- **Dopo 5 password sbagliate** il login si blocca 15 minuti: riavvia il server per sbloccarlo.
- **Password dimenticata:** vedi "Cambiare la password" qui sotto.
- Il pannello admin esiste solo su questo server, non sulla pagina dimostrativa di Claude.
