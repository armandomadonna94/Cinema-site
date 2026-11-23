"use strict";
/*
 * Cinema Lumière – server con area amministrativa.
 * Nessuna dipendenza esterna: richiede solo Node.js >= 22.13 (usa il modulo integrato node:sqlite).
 */
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { promisify } = require("node:util");
let DatabaseSync;
try { ({ DatabaseSync } = require("node:sqlite")); }
catch {
  console.error("Questa versione di Node.js (" + process.version + ") è troppo vecchia: serve Node.js 22.13 o più recente.\nScaricalo da https://nodejs.org (versione LTS) e riprova.");
  process.exit(1);
}
const scrypt = promisify(crypto.scrypt);

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "127.0.0.1";
const SECURE = process.env.COOKIE_SECURE === "1";      // metti 1 quando il sito è servito in HTTPS
const TRUST_PROXY = process.env.TRUST_PROXY === "1";   // metti 1 solo dietro un reverse proxy fidato
const SESSION_MS = 8 * 3600 * 1000;
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, "public");
const VIEWS = path.join(ROOT, "views");
const DATA = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, "data");
const UPLOADS = path.join(DATA, "uploads");
fs.mkdirSync(UPLOADS, { recursive: true });

/* ---------- Database ---------- */
const db = new DatabaseSync(path.join(DATA, "cinema.db"));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL,
    hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    expires INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS films (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    genre TEXT NOT NULL DEFAULT '',
    duration INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    poster TEXT NOT NULL DEFAULT '',
    times TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS films_status ON films(status);
`);

if (!db.prepare("PRAGMA table_info(films)").all().some(c => c.name === "prices")) db.exec("ALTER TABLE films ADD COLUMN prices TEXT");
db.exec("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)");

/* ---------- Utilità ---------- */
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const hashPw = async (pw, salt) => (await scrypt(pw, salt, 64)).toString("hex");
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const POSTER_RE = /^\/uploads\/[a-f0-9]{32}\.(png|jpg|webp)$/;

/* Prezzi per zona della sala: front = file A–B, mid = file C–D, back = file E–F */
const ZONES = ["front", "mid", "back"];
const ZONE_LABEL = { front: "file A–B", mid: "file C–D", back: "file E–F" };
const FALLBACK_PRICES = { front: 8, mid: 10, back: 12 };
function defaultPrices() {
  const r = db.prepare("SELECT value FROM settings WHERE key = 'prices'").get();
  return r ? { ...FALLBACK_PRICES, ...JSON.parse(r.value) } : { ...FALLBACK_PRICES };
}
function parsePrices(input, all) {
  const out = {}, err = [], src = input && typeof input === "object" ? input : {};
  for (const z of ZONES) {
    const raw = src[z];
    if (raw === undefined || raw === null || raw === "") { if (all) err.push("Prezzo " + ZONE_LABEL[z] + " mancante"); continue; }
    const v = Number(String(raw).replace(",", "."));
    if (!Number.isFinite(v) || v < 0 || v > 500 || Math.round(v * 100) / 100 !== v) err.push("Prezzo " + ZONE_LABEL[z] + ": importo da 0 a 500 con al massimo 2 decimali");
    else out[z] = v;
  }
  return { out, err };
}

const SEC_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "same-origin",
  "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
};
function send(res, code, type, body, extra = {}) {
  res.writeHead(code, { "Content-Type": type, ...SEC_HEADERS, ...extra });
  res.end(body);
}
const json = (res, code, obj, extra = {}) => send(res, code, "application/json; charset=utf-8", JSON.stringify(obj), { "Cache-Control": "no-store", ...extra });
const redirect = (res, to) => send(res, 302, "text/plain; charset=utf-8", "", { Location: to });

function readJson(req, limit = 3_500_000) {
  return new Promise((resolve, reject) => {
    if (!/^application\/json\b/i.test(req.headers["content-type"] || "")) return reject(httpErr(415, "Content-Type deve essere application/json"));
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > limit) { reject(httpErr(413, "Richiesta troppo grande")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); } catch { reject(httpErr(400, "JSON non valido")); } });
    req.on("error", reject);
  });
}

function getCookie(req, name) {
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
function sessionAdmin(req) {
  const t = getCookie(req, "sid");
  if (!t) return null;
  return db.prepare("SELECT a.id, a.email FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = ? AND s.expires > ?").get(sha(t), Date.now()) || null;
}
const cookie = (value, maxAge) => `sid=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${SECURE ? "; Secure" : ""}`;

/* ---------- Anti brute-force sul login ---------- */
const attempts = new Map();
const clientIp = req => TRUST_PROXY ? ((req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress) : req.socket.remoteAddress;
function tooMany(ip) {
  const now = Date.now(), list = (attempts.get(ip) || []).filter(t => now - t < 15 * 60 * 1000);
  attempts.set(ip, list);
  return list.length >= 5;
}
const noteFailure = ip => attempts.set(ip, [...(attempts.get(ip) || []), Date.now()]);

/* ---------- Film: validazione e conversione ---------- */
function clean(b) {
  const err = [], out = {};
  const text = (k, min, max, label) => {
    const v = typeof b[k] === "string" ? b[k].trim() : "";
    if (v.length < min || v.length > max) err.push(`${label}: da ${min} a ${max} caratteri`);
    return v;
  };
  out.title = text("title", 1, 120, "Titolo");
  out.genre = text("genre", 0, 40, "Genere");
  out.description = text("description", 0, 1500, "Descrizione");
  const dur = Number(b.duration);
  if (!Number.isInteger(dur) || dur < 1 || dur > 600) err.push("Durata: minuti da 1 a 600");
  out.duration = dur;
  const times = [...new Set((Array.isArray(b.times) ? b.times : []).map(x => String(x).trim()))].sort();
  if (!times.length || times.length > 12 || !times.every(x => /^([01]\d|2[0-3]):[0-5]\d$/.test(x))) err.push("Orari: da 1 a 12 orari nel formato HH:MM");
  out.times = times;
  if (b.status !== undefined && !["draft", "published"].includes(b.status)) err.push("Stato non valido");
  out.status = b.status === "published" ? "published" : "draft";
  const pr = parsePrices(b.prices, false);   // zone lasciate vuote = prezzo standard
  err.push(...pr.err); out.prices = pr.out;
  return { out, err };
}

function resolvePoster(body, current) {
  if (typeof body.posterData === "string" && body.posterData) {
    const m = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(body.posterData);
    if (!m) throw httpErr(400, "Locandina non valida (usa PNG, JPG o WEBP)");
    const buf = Buffer.from(m[2], "base64");
    if (buf.length > 2_000_000) throw httpErr(400, "Locandina troppo pesante (massimo 2 MB)");
    const head = buf.subarray(0, 12);
    const okMagic = m[1] === "png" ? head.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))
      : m[1] === "jpeg" ? head.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))
      : head.subarray(0, 4).toString("latin1") === "RIFF" && head.subarray(8, 12).toString("latin1") === "WEBP";
    if (!okMagic) throw httpErr(400, "Il file non è un'immagine valida");
    const name = crypto.randomBytes(16).toString("hex") + "." + (m[1] === "jpeg" ? "jpg" : m[1]);
    fs.writeFileSync(path.join(UPLOADS, name), buf);
    return "/uploads/" + name;
  }
  return body.poster === "" ? "" : (current || "");
}
function dropPoster(oldPath, newPath) {
  if (oldPath && oldPath !== newPath && POSTER_RE.test(oldPath)) fs.rm(path.join(UPLOADS, path.basename(oldPath)), { force: true }, () => {});
}
const toPublic = (r, defs) => ({ id: r.id, title: r.title, genre: r.genre, duration: r.duration, description: r.description, poster: r.poster || null, times: JSON.parse(r.times), prices: { ...defs, ...JSON.parse(r.prices || "{}") } });
const toAdmin = (r, defs) => ({ ...toPublic(r, defs), custom_prices: JSON.parse(r.prices || "{}"), status: r.status, updated_at: r.updated_at });

/* ---------- API amministrativa (richiede sessione valida) ---------- */
async function adminApi(req, res, p, admin) {
  const m = /^\/api\/admin\/films(?:\/(\d+))?(\/status)?$/.exec(p);
  if (p === "/api/admin/me" && req.method === "GET") return json(res, 200, { email: admin.email });
  if (p === "/api/admin/prices") {
    if (req.method === "GET") return json(res, 200, defaultPrices());
    if (req.method === "PUT") {
      const { out, err } = parsePrices(await readJson(req, 2000), true);
      if (err.length) return json(res, 400, { error: err.join(" · ") });
      db.prepare("INSERT INTO settings (key, value) VALUES ('prices', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(JSON.stringify(out));
      return json(res, 200, out);
    }
    return json(res, 405, { error: "Metodo non consentito" });
  }
  if (!m) return json(res, 404, { error: "Non trovato" });
  const id = m[1] ? Number(m[1]) : null;

  if (!id && req.method === "GET") {
    const defs = defaultPrices();
    return json(res, 200, db.prepare("SELECT * FROM films ORDER BY updated_at DESC").all().map(r => toAdmin(r, defs)));
  }
  if (!id && req.method === "POST") {
    const body = await readJson(req), { out, err } = clean(body);
    if (err.length) return json(res, 400, { error: err.join(" · ") });
    const poster = resolvePoster(body, "");
    const now = Date.now();
    const r = db.prepare("INSERT INTO films (title, genre, duration, description, poster, times, prices, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
      .run(out.title, out.genre, out.duration, out.description, poster, JSON.stringify(out.times), JSON.stringify(out.prices), out.status, now, now);
    return json(res, 201, toAdmin(db.prepare("SELECT * FROM films WHERE id = ?").get(r.lastInsertRowid), defaultPrices()));
  }
  if (id) {
    const row = db.prepare("SELECT * FROM films WHERE id = ?").get(id);
    if (!row) return json(res, 404, { error: "Film non trovato" });
    if (m[2] && req.method === "PATCH") {
      const b = await readJson(req, 1000);
      if (!["draft", "published"].includes(b.status)) return json(res, 400, { error: "Stato non valido" });
      db.prepare("UPDATE films SET status = ?, updated_at = ? WHERE id = ?").run(b.status, Date.now(), id);
      return json(res, 200, toAdmin(db.prepare("SELECT * FROM films WHERE id = ?").get(id), defaultPrices()));
    }
    if (!m[2] && req.method === "PUT") {
      const body = await readJson(req), { out, err } = clean(body);
      if (err.length) return json(res, 400, { error: err.join(" · ") });
      const poster = resolvePoster(body, row.poster);
      db.prepare("UPDATE films SET title=?, genre=?, duration=?, description=?, poster=?, times=?, prices=?, status=?, updated_at=? WHERE id=?")
        .run(out.title, out.genre, out.duration, out.description, poster, JSON.stringify(out.times), JSON.stringify(out.prices), out.status, Date.now(), id);
      dropPoster(row.poster, poster);
      return json(res, 200, toAdmin(db.prepare("SELECT * FROM films WHERE id = ?").get(id), defaultPrices()));
    }
    if (!m[2] && req.method === "DELETE") {
      db.prepare("DELETE FROM films WHERE id = ?").run(id);
      dropPoster(row.poster, "");
      return json(res, 200, { ok: true });
    }
  }
  return json(res, 405, { error: "Metodo non consentito" });
}

/* ---------- File statici ---------- */
const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".svg": "image/svg+xml", ".ico": "image/x-icon" };
function serveFile(res, file, cache) {
  fs.readFile(file, (e, buf) => {
    if (e) return send(res, 404, "text/plain; charset=utf-8", "Non trovato");
    send(res, 200, MIME[path.extname(file)] || "application/octet-stream", buf, { "Cache-Control": cache });
  });
}

/* ---------- Router ---------- */
async function handle(req, res) {
  const p = new URL(req.url, "http://localhost").pathname;
  const isRead = req.method === "GET" || req.method === "HEAD";

  if (!isRead) {
    const origin = req.headers.origin;
    if (origin) {
      let same = false;
      try { same = new URL(origin).host === req.headers.host; } catch {}
      if (!same) return json(res, 403, { error: "Origine non consentita" });
    }
  }

  // API pubblica: SOLO i film pubblicati (il filtro è nella query SQL, non nel browser)
  if (p === "/api/films" && isRead) {
    const defs = defaultPrices();
    return json(res, 200, db.prepare("SELECT * FROM films WHERE status = 'published' ORDER BY title COLLATE NOCASE").all().map(r => toPublic(r, defs)));
  }

  if (p === "/api/login" && req.method === "POST") {
    const ip = clientIp(req);
    if (tooMany(ip)) return json(res, 429, { error: "Troppi tentativi. Riprova tra 15 minuti." });
    const b = await readJson(req, 10_000);
    const email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "").slice(0, 200);
    const row = db.prepare("SELECT * FROM admins WHERE email = ?").get(email);
    const calc = Buffer.from(await hashPw(pw, row ? row.salt : "0".repeat(32)), "hex");
    if (!row || !crypto.timingSafeEqual(calc, Buffer.from(row.hash, "hex"))) {
      noteFailure(ip);
      return json(res, 401, { error: "Credenziali non corrette" });
    }
    attempts.delete(ip);
    db.prepare("DELETE FROM sessions WHERE expires < ?").run(Date.now());
    const token = crypto.randomBytes(32).toString("base64url");
    db.prepare("INSERT INTO sessions (token_hash, admin_id, expires) VALUES (?,?,?)").run(sha(token), row.id, Date.now() + SESSION_MS);
    return json(res, 200, { ok: true }, { "Set-Cookie": cookie(token, SESSION_MS / 1000) });
  }
  if (p === "/api/logout" && req.method === "POST") {
    const t = getCookie(req, "sid");
    if (t) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(sha(t));
    return json(res, 200, { ok: true }, { "Set-Cookie": cookie("", 0) });
  }
  if (p.startsWith("/api/admin/")) {
    const admin = sessionAdmin(req);
    if (!admin) return json(res, 401, { error: "Non autenticato" });
    return adminApi(req, res, p, admin);
  }

  // Pagine amministrative: la dashboard viene consegnata solo con sessione valida
  if (p === "/admin/login") return sessionAdmin(req) ? redirect(res, "/admin") : serveFile(res, path.join(VIEWS, "login.html"), "no-store");
  if (p === "/admin" || p === "/admin/") return sessionAdmin(req) ? serveFile(res, path.join(VIEWS, "dashboard.html"), "no-store") : redirect(res, "/admin/login");

  if (p.startsWith("/uploads/") && isRead) {
    if (!POSTER_RE.test(p)) return send(res, 404, "text/plain; charset=utf-8", "Non trovato");
    return serveFile(res, path.join(UPLOADS, path.basename(p)), "public, max-age=86400");
  }

  if (!isRead) return json(res, 404, { error: "Non trovato" });
  let rel;
  try { rel = decodeURIComponent(p); } catch { return send(res, 400, "text/plain; charset=utf-8", "Richiesta non valida"); }
  if (rel.includes("\0")) return send(res, 400, "text/plain; charset=utf-8", "Richiesta non valida");
  if (rel.endsWith("/")) rel += "index.html";
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep)) return send(res, 404, "text/plain; charset=utf-8", "Non trovato");
  return serveFile(res, file, "no-cache");
}

/* ---------- Avvio ---------- */
async function bootstrap() {
  if (db.prepare("SELECT COUNT(*) AS n FROM admins").get().n > 0) return;
  let email = (process.env.ADMIN_EMAIL || "").trim().toLowerCase(), pw = process.env.ADMIN_PASSWORD || "";
  if ((!email || !pw) && process.stdin.isTTY) {
    // Avvio da terminale senza variabili: chiedo i dati a voce (funziona anche su Windows)
    const rl = require("node:readline/promises").createInterface({ input: process.stdin, output: process.stdout });
    console.log("Primo avvio: creiamo l'account del proprietario.");
    while (!/^\S+@\S+\.\S+$/.test(email)) email = (await rl.question("Email del proprietario: ")).trim().toLowerCase();
    while (pw.length < 12) pw = await rl.question("Scegli una password (almeno 12 caratteri): ");
    rl.close();
  }
  if (!email || pw.length < 12) {
    console.error("Primo avvio: imposta ADMIN_EMAIL e ADMIN_PASSWORD (almeno 12 caratteri) per creare l'account del proprietario.");
    process.exit(1);
  }
  const salt = crypto.randomBytes(16).toString("hex");
  db.prepare("INSERT INTO admins (email, salt, hash) VALUES (?,?,?)").run(email, salt, await hashPw(pw, salt));
  console.log("Account proprietario creato per " + email + ". Puoi rimuovere ADMIN_PASSWORD dall'ambiente.");
}

bootstrap().then(() => {
  http.createServer((req, res) => {
    handle(req, res).catch(e => {
      if (res.headersSent) return res.end();
      if (e && e.status) return json(res, e.status, { error: e.message });
      console.error(e);
      json(res, 500, { error: "Errore interno del server" });
    });
  }).listen(PORT, HOST, () => console.log(`Cinema Lumière in ascolto su http://${HOST}:${PORT}  (area admin: /admin)`));
});
