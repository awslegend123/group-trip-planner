// Group trip planner: login, SQLite storage and itinerary generation with Claude.
// Run with `node server.js` (Node 22.13+). Data lives in trip.db next to this file.
import http from "node:http";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import Anthropic from "@anthropic-ai/sdk";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 3000;
const SESSION_DAYS = 30;

/* ---------- database ---------- */
const db = new DatabaseSync(path.join(DIR, "trip.db"));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    is_organizer INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS prefs (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);

const kvGet = key => {
  const row = db.prepare("SELECT value FROM kv WHERE key = ?").get(key);
  return row ? JSON.parse(row.value) : null;
};
const kvSet = (key, value) =>
  db.prepare("INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .run(key, JSON.stringify(value));

if (!kvGet("invite_code")) kvSet("invite_code", crypto.randomBytes(4).toString("hex").toUpperCase());
const userCount = () => db.prepare("SELECT COUNT(*) AS n FROM users").get().n;

/* ---------- passwords and sessions ---------- */
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString("hex") };
}
function checkPassword(password, user) {
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.pass_hash, "hex"));
}
function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)")
    .run(token, userId, Date.now() + SESSION_DAYS * 864e5);
  return token;
}
function sessionUser(req) {
  const m = /(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie || "");
  if (!m) return null;
  const row = db.prepare(`SELECT u.id, u.username, u.display_name, u.is_organizer, s.expires_at
    FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`).get(m[1]);
  if (!row || row.expires_at < Date.now()) return null;
  return { ...row, token: m[1] };
}
const sessionCookie = (token, maxAge) =>
  `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;

// Slow down password guessing: 8 failed logins per username+IP per 15 minutes.
const failures = new Map();
function tooManyFailures(key) {
  const f = failures.get(key);
  if (!f || f.until < Date.now()) return false;
  return f.count >= 8;
}
function recordFailure(key) {
  const f = failures.get(key);
  if (!f || f.until < Date.now()) failures.set(key, { count: 1, until: Date.now() + 15 * 60e3 });
  else f.count++;
}

/* ---------- input cleaning ---------- */
const clean = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const clampInt = (v, lo, hi, d) => (Number.isFinite(+v) ? Math.max(lo, Math.min(hi, Math.round(+v))) : d);
const INTEREST_KEYS = ["food", "markets", "cafes", "scenery", "hiking", "nature", "water", "culture",
  "museums", "souvenirs", "photo", "adventure", "nightlife", "relax"];
const INTEREST_LABELS = ["Food & local eats", "Markets & street food", "Cafés & desserts", "Scenery & viewpoints",
  "Hiking & trails", "Parks & wildlife", "Beaches & water", "History & culture", "Museums & art",
  "Souvenirs & shopping", "Photo spots", "Adventure activities", "Nightlife & bars", "Spa & downtime"];
const LEVELS = ["Skip", "Fine", "Like", "Love"];
const PACES = ["Relaxed", "Balanced", "Packed"];
const BUDGETS = ["Save", "Mid", "Splurge"];

function cleanPrefs(b) {
  const interests = {};
  for (const k of INTEREST_KEYS) interests[k] = clampInt(b?.interests?.[k], 0, 3, 1);
  return {
    interests,
    pace: clampInt(b?.pace, 0, 2, 1),
    budget: clampInt(b?.budget, 0, 2, 1),
    mustDo: clean(b?.mustDo, 600),
    avoid: clean(b?.avoid, 600),
    dietary: clean(b?.dietary, 200),
    mobility: clean(b?.mobility, 200),
  };
}
function cleanSettings(b) {
  const dests = Array.isArray(b?.destinations) ? b.destinations.slice(0, 15) : [];
  return {
    name: clean(b?.name, 80),
    startDate: /^\d{4}-\d{2}-\d{2}$/.test(b?.startDate || "") ? b.startDate : null,
    days: clampInt(b?.days, 1, 30, 7),
    groupSize: clampInt(b?.groupSize, 1, 30, 10),
    destinations: dests
      .map(d => ({ name: clean(d?.name, 80), nights: d?.nights === null || d?.nights === "" ? null : clampInt(d?.nights, 0, 30, null) }))
      .filter(d => d.name),
    budget: clean(b?.budget, 20),
    notes: clean(b?.notes, 1000),
  };
}

/* ---------- itinerary generation ---------- */
let generating = null; // { by, startedAt } while a plan is being built

function buildPrompt(settings, travellers) {
  return `You are planning a group trip for friends. Build the best day-by-day itinerary for the whole group from the trip details and each traveller's preferences below.

Rules:
- Exactly ${settings.days} days. Visit the destinations in the given order; honour nights where given, otherwise split days sensibly. Include travel between destinations as items with realistic times.
- Weight interests: Love = strong, Like = moderate, Fine = neutral, Skip = avoid planning around it. Favour what many people love, but make sure every traveller gets at least one highlight they love, and honour must-dos where feasible.
- Respect dietary needs and mobility notes for shared activities. Match the group's typical pace.
- Where preferences clearly diverge, use a split slot: one item with 2 "options", each listing who would pick it, then regroup.
- 4 to 6 items per day, morning to evening, including meals at specific named places or dishes typical of the area.
- Use real, specific places (landmarks, neighbourhoods, trails, restaurants, markets). For each destination also give 4 to 6 "nearby" local spots or lesser-known landmarks not already in the schedule.
- Keep each "detail" to one sentence.

TRIP:
${JSON.stringify({
    name: settings.name, lengthDays: settings.days, startDate: settings.startDate, groupSize: settings.groupSize,
    destinationsInOrder: settings.destinations, groupBudget: settings.budget || "not decided", notes: settings.notes,
  }, null, 1)}

TRAVELLERS (${travellers.length} of ${settings.groupSize} have answered):
${JSON.stringify(travellers, null, 1)}

Reply with only JSON in exactly this shape, no other text:
{"title":"short catchy trip title","overview":"2-3 sentences on the shape of the trip and why it fits this group",
"days":[{"day":1,"destination":"city","theme":"short theme","items":[{"time":"09:00","title":"","place":"specific place name","type":"one of: food, scenery, hiking, nature, water, culture, museum, shopping, nightlife, relax, adventure, travel, free time","detail":"one sentence","for":["traveller names this especially pleases"],"options":[{"title":"","detail":"","for":["names"]}]}]}],
"nearby":[{"destination":"city","spots":[{"name":"","kind":"food|scenery|culture|shopping|nature|hiking|other","why":"one sentence"}]}],
"fairness":[{"name":"traveller name","highlights":"which moments are for them"}],
"tips":["short practical tips for this group and these places"]}
Omit "options" on items that are not split slots.`;
}

function parseJsonReply(text) {
  try { return JSON.parse(text); } catch {}
  const fence = /```(?:json)?\s*([\s\S]*?)```/.exec(text);
  if (fence) { try { return JSON.parse(fence[1]); } catch {} }
  const a = text.indexOf("{"), b = text.lastIndexOf("}");
  if (a >= 0 && b > a) { try { return JSON.parse(text.slice(a, b + 1)); } catch {} }
  return null;
}

// Runs the official Claude Code CLI in print mode, signed in with the organiser's claude.ai plan.
// All tools are disabled, so it can only read the prompt and reply with text.
const CLAUDE_TIMEOUT_MS = 10 * 60e3;
function askClaudeCode(prompt) {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "trip-planner-"));
  const env = { ...process.env };
  delete env.ANTHROPIC_API_KEY; // otherwise Claude Code would bill the API instead of the plan
  delete env.ANTHROPIC_AUTH_TOKEN;
  // A shell is needed on Windows to run the npm `claude.cmd` shim. The command line is a fixed
  // string with no user input in it; the prompt goes in on stdin.
  const command = 'claude -p --output-format json --tools "" --model claude-opus-5-5 --no-session-persistence';
  return new Promise((resolve, reject) => {
    const child = spawn(command, { cwd: workdir, env, shell: true, windowsHide: true });
    let out = "", err = "";
    const timer = setTimeout(() => child.kill(), CLAUDE_TIMEOUT_MS);
    child.stdout.on("data", d => (out += d));
    child.stderr.on("data", d => (err += d));
    child.on("error", () => reject(new UserError(503, "Claude Code isn't installed on the computer running the planner. See README.md.")));
    child.on("close", code => {
      clearTimeout(timer);
      fs.rm(workdir, { recursive: true, force: true }, () => {});
      let result = null;
      try { result = JSON.parse(out); } catch {}
      if (result && !result.is_error && typeof result.result === "string") return resolve(result.result);
      const detail = `${result?.result || ""} ${err}`.toLowerCase();
      console.error("Claude Code build failed:", code, (result?.result || err || out).slice(0, 500));
      if (code === 9009 || /not recognized|not found/.test(detail)) return reject(new UserError(503, "Claude Code isn't installed on the computer running the planner. See README.md."));
      if (/log ?in|auth|credential|unauthori/.test(detail)) return reject(new UserError(503, "Claude Code isn't signed in. On the planner computer, run `claude` once and sign in with your Claude account."));
      if (/limit|rate|usage|overloaded/.test(detail)) return reject(new UserError(429, "Your Claude plan's usage limit was reached or Claude is busy. Try again later."));
      reject(new UserError(502, "Claude couldn't finish the itinerary. Press Build again."));
    });
    child.stdin.end(prompt);
  });
}

async function askApi(prompt) {
  let client;
  try { client = new Anthropic(); }
  catch { throw new UserError(503, "No Anthropic API key is set on the computer running the planner. See README.md."); }
  let message;
  try {
    const stream = client.beta.messages.stream({
      model: "claude-opus-5-5",
      max_tokens: 64000,
      betas: ["server-side-fallback-2026-07-01"],
      fallbacks: "default",
      output_config: { effort: "high" },
      messages: [{ role: "user", content: prompt }],
    });
    message = await stream.finalMessage();
  } catch (err) {
    if (err instanceof Anthropic.AuthenticationError) throw new UserError(503, "The Anthropic API key was rejected. Check the key on the computer running the planner.");
    if (err instanceof Anthropic.RateLimitError) throw new UserError(429, "Claude is busy or the API usage limit was reached. Try again in a minute.");
    if (err instanceof Anthropic.APIConnectionError) throw new UserError(502, "Couldn't reach Claude. Check the internet connection on the computer running the planner.");
    if (err instanceof Anthropic.APIError) throw new UserError(502, `Claude returned an error (${err.status ?? "unknown"}). Try again.`);
    throw new UserError(503, "No Anthropic API key is set on the computer running the planner. See README.md.");
  }
  if (message.stop_reason === "refusal") throw new UserError(422, "Claude declined to plan with these inputs. Check the notes and must-dos for anything unusual.");
  return message.content.filter(b => b.type === "text").map(b => b.text).join("");
}

async function generateItinerary(user) {
  const settings = kvGet("settings");
  if (!settings?.destinations?.length) throw new UserError(400, "Add at least one destination in Trip details first.");
  const rows = db.prepare("SELECT p.data, u.display_name FROM prefs p JOIN users u ON u.id = p.user_id").all();
  if (!rows.length) throw new UserError(400, "Nobody has saved preferences yet.");
  const travellers = rows.map(r => {
    const p = JSON.parse(r.data);
    return {
      name: r.display_name,
      interests: Object.fromEntries(INTEREST_KEYS.map((k, i) => [INTEREST_LABELS[i], LEVELS[p.interests[k]]])),
      pace: PACES[p.pace], spending: BUDGETS[p.budget],
      mustDo: p.mustDo, avoid: p.avoid, dietary: p.dietary, mobility: p.mobility,
    };
  });

  // Set PLANNER_ENGINE=api (with ANTHROPIC_API_KEY) to bill builds to the API instead of the
  // claude.ai plan that Claude Code is signed in with.
  const prompt = buildPrompt(settings, travellers);
  const text = process.env.PLANNER_ENGINE === "api" ? await askApi(prompt) : await askClaudeCode(prompt);
  const plan = parseJsonReply(text);
  if (!plan || !Array.isArray(plan.days) || !plan.days.length) throw new UserError(502, "The plan came back garbled. Press Build again.");

  const itinerary = { plan, generatedAt: new Date().toISOString(), generatedBy: user.display_name, responses: rows.length };
  kvSet("itinerary", itinerary);
  return itinerary;
}

/* ---------- HTTP ---------- */
class UserError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
function send(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(JSON.stringify(body));
}
async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > 100_000) throw new UserError(413, "Request too large.");
    chunks.push(c);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); }
  catch { throw new UserError(400, "Malformed request."); }
}

function stateFor(user) {
  const prefs = db.prepare(`SELECT p.user_id, p.data, p.updated_at, u.display_name
    FROM prefs p JOIN users u ON u.id = p.user_id ORDER BY u.created_at`).all()
    .map(r => ({ id: r.user_id, name: r.display_name, updatedAt: r.updated_at, ...JSON.parse(r.data) }));
  const out = {
    me: { id: user.id, name: user.display_name, username: user.username, isOrganizer: !!user.is_organizer },
    settings: kvGet("settings"),
    prefs,
    itinerary: kvGet("itinerary"),
    generating,
    members: db.prepare("SELECT id, username, display_name AS name, is_organizer AS isOrganizer FROM users ORDER BY created_at").all()
      .map(m => ({ ...m, isOrganizer: !!m.isOrganizer })),
  };
  if (user.is_organizer) out.inviteCode = kvGet("invite_code");
  return out;
}

const routes = {
  "GET /api/session": async (req, res, user) =>
    send(res, 200, { user: user ? { name: user.display_name } : null, firstAccount: userCount() === 0 }),

  "POST /api/register": async (req, res) => {
    const b = await readJson(req);
    const username = clean(b.username, 32).toLowerCase();
    const displayName = clean(b.displayName, 40);
    const password = typeof b.password === "string" ? b.password : "";
    const first = userCount() === 0;
    if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw new UserError(400, "Usernames are 3 to 32 letters, numbers, dots, dashes or underscores.");
    if (!displayName) throw new UserError(400, "Add the name the group should see.");
    if (password.length < 8) throw new UserError(400, "Passwords need at least 8 characters.");
    if (first && !isLocal(req)) throw new UserError(403, "The organiser account has to be created on the computer running the planner. Open http://localhost:" + PORT + " there first.");
    if (!first && clean(b.code, 20).toUpperCase() !== kvGet("invite_code")) throw new UserError(403, "That group code doesn't match. Ask the organiser for it.");
    if (db.prepare("SELECT 1 FROM users WHERE username = ?").get(username)) throw new UserError(409, "That username is taken.");
    const { salt, hash } = hashPassword(password);
    const { lastInsertRowid } = db.prepare(`INSERT INTO users (username, display_name, pass_hash, salt, is_organizer, created_at)
      VALUES (?, ?, ?, ?, ?, ?)`).run(username, displayName, hash, salt, first ? 1 : 0, new Date().toISOString());
    const token = createSession(Number(lastInsertRowid));
    send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(token, SESSION_DAYS * 86400) });
  },

  "POST /api/login": async (req, res) => {
    const b = await readJson(req);
    const username = clean(b.username, 32).toLowerCase();
    const key = `${username}|${clientIp(req)}`;
    if (tooManyFailures(key)) throw new UserError(429, "Too many attempts. Wait 15 minutes and try again.");
    const u = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!u || !checkPassword(typeof b.password === "string" ? b.password : "", u)) {
      recordFailure(key);
      throw new UserError(401, "Username or password is wrong.");
    }
    failures.delete(key);
    const token = createSession(u.id);
    send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(token, SESSION_DAYS * 86400) });
  },

  "POST /api/logout": async (req, res, user) => {
    if (user) db.prepare("DELETE FROM sessions WHERE token = ?").run(user.token);
    send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie("", 0) });
  },

  "GET /api/state": async (req, res, user) => send(res, 200, stateFor(need(user))),

  "PUT /api/prefs": async (req, res, user) => {
    need(user);
    const data = cleanPrefs(await readJson(req));
    db.prepare(`INSERT INTO prefs (user_id, data, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`)
      .run(user.id, JSON.stringify(data), new Date().toISOString());
    send(res, 200, stateFor(user));
  },

  "PUT /api/settings": async (req, res, user) => {
    need(user);
    kvSet("settings", { ...cleanSettings(await readJson(req)), updatedAt: new Date().toISOString() });
    send(res, 200, stateFor(user));
  },

  "PUT /api/me": async (req, res, user) => {
    need(user);
    const name = clean((await readJson(req)).displayName, 40);
    if (!name) throw new UserError(400, "Add the name the group should see.");
    db.prepare("UPDATE users SET display_name = ? WHERE id = ?").run(name, user.id);
    send(res, 200, stateFor({ ...user, display_name: name }));
  },

  "POST /api/itinerary": async (req, res, user) => {
    need(user);
    if (generating) throw new UserError(409, `${generating.by} is already building the itinerary. It will appear here when it's done.`);
    generating = { by: user.display_name, startedAt: new Date().toISOString() };
    try { await generateItinerary(user); }
    finally { generating = null; }
    send(res, 200, stateFor(user));
  },

  // Organiser only: set a temporary password for someone who forgot theirs.
  "POST /api/reset-password": async (req, res, user) => {
    need(user);
    if (!user.is_organizer) throw new UserError(403, "Only the organiser can reset passwords.");
    const target = db.prepare("SELECT id FROM users WHERE id = ?").get(Number((await readJson(req)).userId));
    if (!target) throw new UserError(404, "That person no longer exists.");
    const temp = crypto.randomBytes(5).toString("hex");
    const { salt, hash } = hashPassword(temp);
    db.prepare("UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?").run(hash, salt, target.id);
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(target.id);
    send(res, 200, { tempPassword: temp });
  },

  "POST /api/password": async (req, res, user) => {
    need(user);
    const b = await readJson(req);
    const full = db.prepare("SELECT * FROM users WHERE id = ?").get(user.id);
    if (!checkPassword(typeof b.current === "string" ? b.current : "", full)) throw new UserError(401, "Your current password is wrong.");
    if (typeof b.next !== "string" || b.next.length < 8) throw new UserError(400, "New passwords need at least 8 characters.");
    const { salt, hash } = hashPassword(b.next);
    db.prepare("UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?").run(hash, salt, user.id);
    send(res, 200, { ok: true });
  },
};

// A tunnel (cloudflared) connects from 127.0.0.1 too, but it adds forwarding headers.
const PROXY_HEADERS = ["cf-connecting-ip", "x-forwarded-for", "x-real-ip"];
function isLocal(req) {
  const addr = req.socket.remoteAddress || "";
  const loopback = addr === "127.0.0.1" || addr === "::1" || addr === "::ffff:127.0.0.1";
  return loopback && !PROXY_HEADERS.some(h => req.headers[h]);
}
function clientIp(req) {
  return String(req.headers["cf-connecting-ip"] || req.socket.remoteAddress || "");
}

function need(user) {
  if (!user) throw new UserError(401, "Please sign in.");
  return user;
}

const INDEX = path.join(DIR, "public", "index.html");
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  try {
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      return fs.createReadStream(INDEX).pipe(res);
    }
    const handler = routes[`${req.method} ${url.pathname}`];
    if (!handler) return send(res, 404, { error: "Not found." });
    // Reject cross-site form posts: state-changing calls must come from this page as JSON.
    if (req.method !== "GET" && !String(req.headers["content-type"] || "").startsWith("application/json"))
      return send(res, 415, { error: "Expected JSON." });
    await handler(req, res, sessionUser(req));
  } catch (err) {
    if (err instanceof UserError) return send(res, err.status, { error: err.message });
    console.error(err);
    send(res, 500, { error: "Something went wrong on the server." });
  }
});
server.requestTimeout = 0; // itinerary builds can take a few minutes

db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(Date.now());
server.listen(PORT, "0.0.0.0", () => {
  // Skip virtual adapters (WSL, Hyper-V, Docker, VMs) so only the real Wi-Fi/Ethernet address shows.
  const lan = Object.entries(os.networkInterfaces())
    .filter(([name]) => !/vEthernet|WSL|Hyper-V|Docker|VirtualBox|VMware|Loopback/i.test(name))
    .flatMap(([, list]) => list)
    .filter(i => i && i.family === "IPv4" && !i.internal).map(i => `http://${i.address}:${PORT}`);
  console.log(`\nTrip planner running.`);
  console.log(`  On this computer:   http://localhost:${PORT}`);
  for (const u of lan) console.log(`  On your Wi-Fi:      ${u}`);
  console.log(`  Group code:         ${kvGet("invite_code")}  (friends need this to create an account)`);
  console.log(process.env.PLANNER_ENGINE === "api"
    ? "  Itineraries:        built with the Anthropic API (ANTHROPIC_API_KEY)"
    : "  Itineraries:        built with Claude Code, using your Claude plan");
  console.log("");
});
