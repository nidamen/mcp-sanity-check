#!/usr/bin/env node
// mcp-sanity-check: scan a repo's tracked files for owner identifiers and secrets.
// Dependency-light: plain Node + regex, ESM. Exit 1 on any hit, 0 if clean.
//
// Usage:
//   mcp-sanity-check [--path <dir>] [--staged] [--json] [--quiet]
//
// Flags:
//   --path <dir>   Directory to scan (default: cwd).
//   --staged       Scan only staged changes (added/changed lines), for pre-commit/pre-push.
//   --range <a..b> Scan only lines added in commit range a..b (for pre-push hook).
//   --json         Emit machine-readable JSON report instead of human text.
//   --quiet        Suppress the per-hit lines; only print the summary.
//   --no-color     Disable ANSI color.
//
// A scanned repo can tune behavior with an optional .sanity-patterns.json at its root:
//   { "identifiers": ["extra-owner-string", ...], "allow": ["substring-to-ignore", ...] }
// `identifiers` are ADDED to the baked-in defaults. `allow` substrings whitelist a line
// (if the matched line contains any allow-substring, that hit is dropped).

import { execFileSync } from "node:child_process";
import { readFileSync, statSync, readdirSync, existsSync } from "node:fs";
import { join, resolve, relative, sep } from "node:path";
import { homedir } from "node:os";

// ----------------------------------------------------------------------------
// OWNER IDENTIFIERS. The PUBLIC tool ships with NONE baked in, so this file can
// itself live in a public repo without leaking anyone's data. Your specific
// strings (emails, account ids, home IPs, device names) are loaded at runtime
// from a PRIVATE source that is never committed:
//   1. $MCP_SANITY_IDENTIFIERS  -> path to JSON {"identifiers":[...]}
//   2. ~/.config/mcp-sanity/identifiers.json   (default private config)
//   3. a scanned repo's own .sanity-patterns.json "identifiers" (repo-local extras)
// The local pre-push hook (on your machine, where the private config lives) is the
// decisive gate for YOUR specifics. The public CI, which does NOT have your list,
// relies on the GENERIC_PII + SECRET patterns below as a backstop.
// ----------------------------------------------------------------------------
const DEFAULT_IDENTIFIERS = [];

function loadOwnerIdentifiers() {
  const candidates = [];
  if (process.env.MCP_SANITY_IDENTIFIERS) candidates.push(process.env.MCP_SANITY_IDENTIFIERS);
  candidates.push(join(homedir(), ".config", "mcp-sanity", "identifiers.json"));
  for (const p of candidates) {
    try {
      if (p && existsSync(p)) {
        const cfg = JSON.parse(readFileSync(p, "utf8"));
        if (Array.isArray(cfg.identifiers)) {
          return cfg.identifiers.filter((x) => typeof x === "string" && x.length);
        }
      }
    } catch {
      /* ignore a malformed private config; fall through to generic patterns */
    }
  }
  return [];
}

// Generic PII patterns (NO specific person). These are the public-CI backstop:
// they catch any email, RFC1918 address, personal home path, or MAC, so leaked
// owner data is caught even where the private identifier list is unavailable.
const GENERIC_PII = [
  { name: "email-address", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { name: "private-ipv4 (RFC1918)", re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g },
  { name: "personal-home-path", re: /(?:\/Users\/|\/home\/)[a-z_][a-z0-9_.-]{1,30}/gi },
  { name: "mac-address", re: /\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b/g },
];

// Obvious placeholders are not PII; a generic-PII hit equal to (or starting with)
// one of these is dropped so docs/examples do not trip the backstop.
const PII_PLACEHOLDERS = [
  "you@example.com", "user@example.com", "test@example.com", "name@example.com",
  "email@example.com", "example@example.com", "your-account@yahoo.com",
  "your.email@gmail.com", "noreply@", "no-reply@", "support@example.com",
  "/users/you", "/users/username", "/users/your-username", "/users/me",
  "/home/you", "/home/user", "/home/username", "/home/me",
  "127.0.0.1", "0.0.0.0", "10.0.0.0", "192.168.0.0", "192.168.1.0",
  "192.168.1.1", "192.168.1.100", "172.16.0.0",
  "00:00:00:00:00:00", "aa:bb:cc:dd:ee:ff", "de:ad:be:ef:00:00",
];

// ----------------------------------------------------------------------------
// SECRET REGEXES. Each has a name (shown on a hit) and a pattern.
// We MASK the matched value so the scanner output itself never leaks a secret.
// ----------------------------------------------------------------------------
const SECRET_PATTERNS = [
  { name: "github-personal-access-token (ghp_)", re: /\bghp_[A-Za-z0-9]{20,}\b/g },
  { name: "github-fine-grained-pat (github_pat_)", re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
  { name: "openai-api-key (sk-)", re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { name: "slack-token (xox*)", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: "aws-access-key-id (AKIA)", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "google-api-key (AIza)", re: /\bAIza[0-9A-Za-z_-]{30,}\b/g },
  { name: "private-key-block", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
];

// High-entropy token assigned to a *key*/*secret*/*token*/*password*-named field.
// Matches things like:  api_key = "AAAA....40+chars"   "secret": 'base64ish...'
// Captures the value so we can entropy-check it before flagging (reduces noise).
const ASSIGNED_SECRET_RE =
  /\b([A-Za-z0-9_.-]*(?:key|secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)\b\s*[:=]\s*["'`]?([A-Za-z0-9+/_=-]{40,})["'`]?/gi;

// ----------------------------------------------------------------------------
// arg parsing
// ----------------------------------------------------------------------------
function parseArgs(argv) {
  const opts = { path: process.cwd(), staged: false, range: null, json: false, quiet: false, color: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--path") opts.path = resolve(argv[++i] ?? ".");
    else if (a === "--staged") opts.staged = true;
    else if (a === "--range") opts.range = argv[++i] ?? null;
    else if (a === "--json") opts.json = true;
    else if (a === "--quiet") opts.quiet = true;
    else if (a === "--no-color") opts.color = false;
    else if (a === "-h" || a === "--help") opts.help = true;
    else if (a.startsWith("--path=")) opts.path = resolve(a.slice(7));
    else if (a.startsWith("--range=")) opts.range = a.slice(8);
  }
  if (process.env.NO_COLOR) opts.color = false;
  return opts;
}

const HELP = `mcp-sanity-check - scan a repo for owner identifiers and secrets

Usage:
  mcp-sanity-check [--path <dir>] [--staged] [--range <a..b>] [--json] [--quiet]

Exit code 1 if any identifier/secret is found, 0 if clean.
See README.md for opt-in (CI workflow + pre-push hook) instructions.`;

// ----------------------------------------------------------------------------
// shannon entropy (per-char bits). Used to suppress low-entropy long strings
// like repeated chars, version constants, or human-readable identifiers.
// ----------------------------------------------------------------------------
function shannonEntropy(str) {
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let H = 0;
  const n = str.length;
  for (const c of freq.values()) {
    const p = c / n;
    H -= p * Math.log2(p);
  }
  return H;
}

// ----------------------------------------------------------------------------
// masking: keep a tiny prefix so a human can grep, hide the rest.
// ----------------------------------------------------------------------------
function mask(value) {
  if (value.length <= 8) return "*".repeat(value.length);
  return value.slice(0, 4) + "*".repeat(Math.max(4, value.length - 8)) + value.slice(-2);
}

// ----------------------------------------------------------------------------
// load optional .sanity-patterns.json from scanned repo root
// ----------------------------------------------------------------------------
function loadRepoConfig(dir) {
  const p = join(dir, ".sanity-patterns.json");
  if (!existsSync(p)) return { identifiers: [], allow: [], allowFiles: [] };
  try {
    const cfg = JSON.parse(readFileSync(p, "utf8"));
    const strArr = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string" && x.length) : []);
    return {
      identifiers: strArr(cfg.identifiers),
      allow: strArr(cfg.allow),
      // allowFiles: path substrings; a scanned file whose relative path contains
      // one of these is skipped entirely. Use for files that legitimately DEFINE
      // the patterns (e.g. the scanner's own identifier list, docs of examples).
      allowFiles: strArr(cfg.allowFiles),
    };
  } catch {
    return { identifiers: [], allow: [], allowFiles: [] };
  }
}

// normalize a path to forward slashes for portable substring matching
function normPath(p) {
  return p.split(sep).join("/");
}

function isAllowedFile(relPath, allowFiles) {
  if (!allowFiles.length) return false;
  const np = normPath(relPath);
  return allowFiles.some((a) => np.includes(a));
}

// ----------------------------------------------------------------------------
// file enumeration
// ----------------------------------------------------------------------------
const EXCLUDE_DIRS = new Set(["node_modules", ".venv", "venv", ".git", "dist", "build", ".next", "coverage", "__pycache__"]);
// Skip obvious binaries by extension (we still scan unknown/text files).
const BINARY_EXT = new Set([
  "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "tiff", "pdf", "zip", "gz", "tar",
  "tgz", "bz2", "7z", "rar", "exe", "dll", "so", "dylib", "o", "a", "class", "jar",
  "woff", "woff2", "ttf", "eot", "otf", "mp3", "mp4", "mov", "avi", "wav", "flac",
  "wasm", "bin", "dat", "db", "sqlite", "lock",
]);

function extOf(p) {
  const i = p.lastIndexOf(".");
  return i >= 0 ? p.slice(i + 1).toLowerCase() : "";
}

function gitTrackedFiles(dir) {
  try {
    const out = execFileSync("git", ["-C", dir, "ls-files", "-z"], {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"], // silence git's stderr (e.g. "not a git repository")
    });
    return out.split("\0").filter(Boolean);
  } catch {
    return null; // not a git repo or git missing
  }
}

function walkDir(dir) {
  const results = [];
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try {
      entries = readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (ent.name.startsWith(".git")) continue;
      const full = join(cur, ent.name);
      if (ent.isDirectory()) {
        if (EXCLUDE_DIRS.has(ent.name)) continue;
        stack.push(full);
      } else if (ent.isFile()) {
        results.push(relative(dir, full));
      }
    }
  }
  return results;
}

// ----------------------------------------------------------------------------
// staged / range scanning via git diff (returns map relPath -> [{line, text}])
// of ADDED lines only. Identifies leaks introduced by the diff being pushed.
// ----------------------------------------------------------------------------
function diffAddedLines(dir, { staged, range }) {
  const args = ["-C", dir, "diff", "--no-color", "--unified=0"];
  if (staged) args.push("--cached");
  if (range) args.push(range);
  let out;
  try {
    out = execFileSync("git", args, { encoding: "utf8", maxBuffer: 128 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
  } catch (e) {
    // If range is bad (e.g. new branch with no remote ref), surface nothing rather than crash.
    out = "";
  }
  const byFile = new Map();
  let curFile = null;
  let newLineNo = 0;
  for (const raw of out.split("\n")) {
    if (raw.startsWith("+++ ")) {
      const p = raw.slice(4);
      curFile = p === "/dev/null" ? null : p.replace(/^b\//, "");
      continue;
    }
    if (raw.startsWith("@@")) {
      const m = raw.match(/\+(\d+)/);
      newLineNo = m ? parseInt(m[1], 10) : 0;
      continue;
    }
    if (raw.startsWith("+") && !raw.startsWith("+++")) {
      if (curFile) {
        if (!byFile.has(curFile)) byFile.set(curFile, []);
        byFile.get(curFile).push({ line: newLineNo, text: raw.slice(1) });
      }
      newLineNo++;
    } else if (!raw.startsWith("-") && !raw.startsWith("\\")) {
      // context line in unified=0 shouldn't appear, but keep counter sane
      newLineNo++;
    }
  }
  return byFile;
}

// ----------------------------------------------------------------------------
// core line scan. Returns array of hit objects for one line.
// ----------------------------------------------------------------------------
function scanLine(text, identifiers, allow) {
  const hits = [];
  // allowlist short-circuit
  for (const a of allow) {
    if (a && text.includes(a)) return hits; // line explicitly allowed
  }
  const lower = text.toLowerCase();

  // 1) owner identifiers. Purely-alphabetic identifiers (names/handles) use a
  // word boundary so a surname like "Lee" does not false-match inside "mcleest";
  // everything else (emails, paths, IPs, ids with separators) uses a substring match.
  for (const id of identifiers) {
    if (!id) continue;
    if (/^[A-Za-z]+$/.test(id)) {
      const re = new RegExp(`\\b${id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
      const m = re.exec(text);
      if (m) hits.push({ class: "identifier", pattern: `owner-identifier:${id}`, value: m[0] });
    } else {
      const needle = id.toLowerCase();
      if (lower.includes(needle)) {
        const idx = lower.indexOf(needle);
        hits.push({ class: "identifier", pattern: `owner-identifier:${id}`, value: text.slice(idx, idx + id.length) });
      }
    }
  }

  // 1b) generic PII (no specific person): the public-CI backstop.
  for (const { name, re } of GENERIC_PII) {
    re.lastIndex = 0;
    let g;
    while ((g = re.exec(text)) !== null) {
      const val = g[0];
      const v = val.toLowerCase();
      // Reserved documentation domains (RFC 2606/6761) are never real PII.
      const reservedEmail = name === "email-address" &&
        /@(?:[a-z0-9-]+\.)*(?:example\.(?:com|org|net)|example|test|invalid|localhost)$/i.test(val);
      const isPlaceholder = reservedEmail || PII_PLACEHOLDERS.some((ph) => v === ph || v.startsWith(ph));
      if (!isPlaceholder) hits.push({ class: "pii", pattern: name, value: val });
      if (g.index === re.lastIndex) re.lastIndex++;
    }
  }

  // 2) named secret regexes
  for (const { name, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      hits.push({ class: "secret", pattern: name, value: m[0] });
      if (m.index === re.lastIndex) re.lastIndex++; // guard zero-width
    }
  }

  // 3) high-entropy assigned secret
  ASSIGNED_SECRET_RE.lastIndex = 0;
  let am;
  while ((am = ASSIGNED_SECRET_RE.exec(text)) !== null) {
    const field = am[1];
    const value = am[2];
    if (am.index === ASSIGNED_SECRET_RE.lastIndex) ASSIGNED_SECRET_RE.lastIndex++;
    // entropy gate: long base64-ish + high entropy => likely a real secret.
    const H = shannonEntropy(value);
    const distinct = new Set(value).size;
    if (H >= 3.5 && distinct >= 12) {
      hits.push({ class: "secret", pattern: `high-entropy-assignment (${field})`, value });
    }
  }

  return hits;
}

// avoid duplicate identical hits on the same line (e.g. a name inside an email matched twice)
function dedupeHits(hits) {
  const seen = new Set();
  const out = [];
  for (const h of hits) {
    const k = `${h.class}|${h.pattern}|${h.value}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(h);
  }
  return out;
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write(HELP + "\n");
    process.exit(0);
  }

  const dir = opts.path;
  if (!existsSync(dir)) {
    process.stderr.write(`mcp-sanity-check: path not found: ${dir}\n`);
    process.exit(2);
  }

  const repoCfg = loadRepoConfig(dir);
  const identifiers = [...DEFAULT_IDENTIFIERS, ...loadOwnerIdentifiers(), ...repoCfg.identifiers];
  const allow = repoCfg.allow;
  const allowFiles = repoCfg.allowFiles;

  const c = opts.color
    ? { red: (s) => `\x1b[31m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`, green: (s) => `\x1b[32m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`, bold: (s) => `\x1b[1m${s}\x1b[0m` }
    : { red: (s) => s, yellow: (s) => s, green: (s) => s, dim: (s) => s, bold: (s) => s };

  const allHits = [];
  let filesScanned = 0;

  if (opts.staged || opts.range) {
    // Diff mode: only added lines.
    const byFile = diffAddedLines(dir, { staged: opts.staged, range: opts.range });
    for (const [file, lines] of byFile) {
      if (isAllowedFile(file, allowFiles)) continue;
      filesScanned++;
      for (const { line, text } of lines) {
        const hits = dedupeHits(scanLine(text, identifiers, allow));
        for (const h of hits) allHits.push({ file, line, ...h });
      }
    }
  } else {
    // Full mode: tracked files (or walk fallback).
    let files = gitTrackedFiles(dir);
    if (files === null) files = walkDir(dir);
    for (const rel of files) {
      if (BINARY_EXT.has(extOf(rel))) continue;
      if (isAllowedFile(rel, allowFiles)) continue;
      const full = join(dir, rel);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (!st.isFile()) continue;
      if (st.size > 5 * 1024 * 1024) continue; // skip >5MB files
      let content;
      try {
        content = readFileSync(full, "utf8");
      } catch {
        continue;
      }
      // crude binary sniff: NUL byte in first 4KB
      if (content.slice(0, 4096).indexOf("\u0000") !== -1) continue;
      filesScanned++;
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const hits = dedupeHits(scanLine(lines[i], identifiers, allow));
        for (const h of hits) allHits.push({ file: rel, line: i + 1, ...h });
      }
    }
  }

  // ---- report ----
  if (opts.json) {
    const report = {
      ok: allHits.length === 0,
      filesScanned,
      hitCount: allHits.length,
      mode: opts.staged ? "staged" : opts.range ? "range" : "full",
      hits: allHits.map((h) => ({ file: h.file, line: h.line, class: h.class, pattern: h.pattern, masked: mask(h.value) })),
    };
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    process.exit(allHits.length ? 1 : 0);
  }

  if (allHits.length === 0) {
    process.stdout.write(c.green(`✓ mcp-sanity-check: clean`) + c.dim(` (${filesScanned} files scanned)\n`));
    process.exit(0);
  }

  if (!opts.quiet) {
    process.stdout.write(c.red(c.bold(`✗ mcp-sanity-check: ${allHits.length} potential leak(s) found\n`)));
    for (const h of allHits) {
      const tag = h.class === "secret" ? c.red("SECRET   ") : c.yellow("IDENTIFIER");
      process.stdout.write(`  ${tag} ${c.bold(h.file)}:${h.line}  ${c.dim(h.pattern)}  -> ${mask(h.value)}\n`);
    }
  }
  process.stdout.write(
    c.red(c.bold(`\nBLOCKED: ${allHits.length} hit(s) across ${filesScanned} files.`)) +
      ` Remove the values above, or whitelist a false-positive line via .sanity-patterns.json "allow".\n`
  );
  process.exit(1);
}

main();
