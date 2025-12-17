import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import Database from "better-sqlite3";

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const REG_ENABLED = String(process.env.REGISTRATION_ENABLED || "false").toLowerCase() === "true";
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS || 2);

const db = new Database("data.sqlite");

// Tabellen korrekt als SQL-Strings anlegen
db.prepare(CREATE TABLE IF NOT EXISTS customers(   id INTEGER PRIMARY KEY AUTOINCREMENT,   copy_id TEXT UNIQUE,   token TEXT,   name TEXT,   email TEXT,   blocked INTEGER DEFAULT 0,   created_at DATETIME DEFAULT CURRENT_TIMESTAMP )).run();

db.prepare(CREATE TABLE IF NOT EXISTS events(   id INTEGER PRIMARY KEY AUTOINCREMENT,   copy_id TEXT,   seq INTEGER,   payload TEXT,   created_at DATETIME DEFAULT CURRENT_TIMESTAMP )).run();

app.use(express.json());
app.use(cors());
app.use(helmet());
app.use(morgan("tiny"));

const genId = () => "KND-" + Math.floor(100000 + Math.random() * 900000);
const genToken = () => Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);

const requireAdmin = (req, res, next) => {
const pass = req.headers["x-admin-pass"] || req.query.pass;
if (ADMIN_PASSWORD && pass === ADMIN_PASSWORD) return next();
res.status(401).json({ error: "unauthorized" });
};

const requireCustomer = (req, res, next) => {
const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
const copyId = req.headers["x-copy-id"] || req.query.copy_id;
if (!token || !copyId) return res.status(400).json({ error: "missing token or copy_id" });
const row = db.prepare("SELECT * FROM customers WHERE copy_id=? AND token=?").get(copyId, token);
if (!row || row.blocked) return res.status(401).json({ error: "invalid or blocked" });
next();
};

app.get("/health", (_, res) => res.json({ ok: true }));

app.post("/register", (req, res) => {
if (!REG_ENABLED) return res.status(403).json({ error: "registration disabled" });
const { name = "", email = "" } = req.body || {};
const copy_id = genId();
const token = genToken();
db.prepare("INSERT INTO customers(copy_id,token,name,email) VALUES(?,?,?,?)").run(copy_id, token, name, email);
res.json({ copy_id, token });
});

app.get("/admin/customers", requireAdmin, (req, res) => {
const rows = db
.prepare("SELECT id,copy_id,name,email,blocked,created_at FROM customers ORDER BY id DESC")
.all();
res.json(rows);
});

app.post("/admin/customers", requireAdmin, (req, res) => {
const { name = "", email = "" } = req.body || {};
const copy_id = genId();
const token = genToken();
db.prepare("INSERT INTO customers(copy_id,token,name,email) VALUES(?,?,?,?)").run(copy_id, token, name, email);
res.json({ copy_id, token });
});

app.post("/admin/customers/:copy_id/block", requireAdmin, (req, res) => {
db.prepare("UPDATE customers SET blocked=1 WHERE copy_id=?").run(req.params.copy_id);
res.json({ ok: true });
});

app.post("/admin/customers/:copy_id/reset", requireAdmin, (req, res) => {
const token = genToken();
db.prepare("UPDATE customers SET token=? WHERE copy_id=?").run(token, req.params.copy_id);
res.json({ copy_id: req.params.copy_id, token });
});

app.post("/events", requireCustomer, (req, res) => {
const copy_id = req.headers["x-copy-id"] || req.query.copy_id;
const { seq = 0, ...rest } = req.body || {};
db.prepare("INSERT INTO events(copy_id,seq,payload) VALUES(?,?,?)").run(
copy_id,
Number(seq),
JSON.stringify(rest)
);
res.json({ ok: true });
});

app.get("/events", requireCustomer, (req, res) => {
const copy_id = req.headers["x-copy-id"] || req.query.copy_id;
const since = Number(req.query.since || 0);
const rows = db
.prepare("SELECT seq,payload,created_at FROM events WHERE copy_id=? AND seq>=? ORDER BY seq ASC")
.all(copy_id, since);
res.json(rows.map(r => ({ seq: r.seq, ...JSON.parse(r.payload), created_at: r.created_at })));
});

app.listen(PORT, () => console.log(Server on ${PORT}));