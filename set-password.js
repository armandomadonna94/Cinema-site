"use strict";
/* Cambia la password del proprietario:
   ADMIN_EMAIL="tu@tuocinema.it" NEW_PASSWORD="nuova-password-lunga" node set-password.js */
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");
const email = (process.env.ADMIN_EMAIL || "").trim().toLowerCase(), pw = process.env.NEW_PASSWORD || "";
if (!email || pw.length < 12) { console.error("Imposta ADMIN_EMAIL e NEW_PASSWORD (almeno 12 caratteri)."); process.exit(1); }
const data = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, "data");
const db = new DatabaseSync(path.join(data, "cinema.db"));
const row = db.prepare("SELECT id FROM admins WHERE email = ?").get(email);
if (!row) { console.error("Nessun account con questa email."); process.exit(1); }
const salt = crypto.randomBytes(16).toString("hex");
const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
db.prepare("UPDATE admins SET salt = ?, hash = ? WHERE id = ?").run(salt, hash, row.id);
db.prepare("DELETE FROM sessions WHERE admin_id = ?").run(row.id);
console.log("Password aggiornata. Tutte le sessioni aperte sono state chiuse.");
