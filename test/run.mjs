#!/usr/bin/env node
// Tiny self-contained test harness (no deps). Proves the scanner:
//   (1) CATCHES a planted owner identifier and a planted secret -> exit 1
//   (2) PASSES on a clean file -> exit 0
//
// Dirty fixtures are generated into a temp dir at runtime so that the planted
// identifier/secret never lives permanently in this repo's tracked source
// (otherwise the scanner would flag its own repo). The clean fixture lives in
// test/fixtures/clean.txt.

import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCANNER = join(__dirname, "..", "bin", "mcp-sanity-check.mjs");

let passed = 0;
let failed = 0;

function run(args) {
  // Capture stdout only (stderr inherited/ignored) so JSON output is never
  // polluted by stray diagnostics.
  try {
    const out = execFileSync("node", [SCANNER, ...args, "--no-color"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status ?? 1, out: e.stdout || "" };
  }
}

function assert(name, cond, detail = "") {
  if (cond) {
    passed++;
    console.log(`  ok   - ${name}`);
  } else {
    failed++;
    console.log(`  FAIL - ${name} ${detail}`);
  }
}

// ---- Test 1: catches a planted owner identifier + a planted secret ----
// We assemble the planted strings from fragments so this test FILE itself stays
// clean when the scanner runs over the repo.
const ownerFrag = ["nid", "amen"].join(""); // -> baked-in owner identifier
const ghpFrag = "ghp_" + "A".repeat(8) + "Bx7Kq9Zr2Lm4Np6Tv8Wd"; // looks like a GH PAT
const skFrag = "sk-" + "Xy".repeat(15); // looks like an OpenAI key

const dirtyDir = mkdtempSync(join(tmpdir(), "msc-dirty-"));
writeFileSync(
  join(dirtyDir, "leak.env"),
  [
    "OWNER=" + ownerFrag + "@gmail.com",
    "GITHUB_TOKEN=" + ghpFrag,
    "OPENAI_KEY=" + skFrag,
    "",
  ].join("\n")
);

const r1 = run(["--path", dirtyDir]);
assert("dirty fixture exits non-zero", r1.code === 1, `(code=${r1.code})`);
assert("dirty fixture reports the owner identifier", /owner-identifier/.test(r1.out), `\n${r1.out}`);
assert("dirty fixture reports a secret", /SECRET/.test(r1.out), `\n${r1.out}`);
assert(
  "scanner MASKS the secret value (does not print it raw)",
  !r1.out.includes(ghpFrag) && !r1.out.includes(skFrag),
  "raw secret leaked into output!"
);

// ---- Test 2: JSON mode also reports a hit and masks ----
const r1json = run(["--path", dirtyDir, "--json"]);
assert("json mode exits non-zero on dirty", r1json.code === 1, `(code=${r1json.code})`);
let parsed = null;
try {
  parsed = JSON.parse(r1json.out);
} catch {}
assert("json output parses", parsed !== null);
assert("json ok=false on dirty", parsed && parsed.ok === false);
assert("json hitCount > 0", parsed && parsed.hitCount > 0);
assert(
  "json never contains raw secret",
  !r1json.out.includes(ghpFrag) && !r1json.out.includes(skFrag)
);

// ---- Test 3: passes on a clean directory ----
const cleanDir = mkdtempSync(join(tmpdir(), "msc-clean-"));
writeFileSync(
  join(cleanDir, "config.txt"),
  [
    "host = example.com",
    "port = 8080",
    "maintainer = Open Source Contributor",
    "version = v1.2.3",
    "",
  ].join("\n")
);
const r2 = run(["--path", cleanDir]);
assert("clean fixture exits zero", r2.code === 0, `(code=${r2.code})\n${r2.out}`);
assert("clean fixture prints clean", /clean/.test(r2.out));

// ---- Test 4: .sanity-patterns.json allow-list suppresses a false positive ----
const allowDir = mkdtempSync(join(tmpdir(), "msc-allow-"));
writeFileSync(
  join(allowDir, ".sanity-patterns.json"),
  JSON.stringify({ allow: ["EXAMPLE_OWNER_PLACEHOLDER"] })
);
writeFileSync(
  join(allowDir, "doc.md"),
  // line contains the owner identifier but also the allow token -> suppressed
  "EXAMPLE_OWNER_PLACEHOLDER " + ownerFrag + " appears here but is whitelisted.\n"
);
const r3 = run(["--path", allowDir]);
assert("allow-list suppresses a whitelisted line", r3.code === 0, `(code=${r3.code})\n${r3.out}`);

// ---- Test 5: extra identifier via .sanity-patterns.json is enforced ----
const extraDir = mkdtempSync(join(tmpdir(), "msc-extra-"));
writeFileSync(
  join(extraDir, ".sanity-patterns.json"),
  JSON.stringify({ identifiers: ["ACME_INTERNAL_CODENAME"] })
);
writeFileSync(join(extraDir, "notes.txt"), "Project ACME_INTERNAL_CODENAME is secret.\n");
const r4 = run(["--path", extraDir]);
assert("custom identifier from config is caught", r4.code === 1, `(code=${r4.code})\n${r4.out}`);

// ---- Test 6: allowFiles skips a definition file but still catches a leak elsewhere ----
const afDir = mkdtempSync(join(tmpdir(), "msc-allowfiles-"));
writeFileSync(
  join(afDir, ".sanity-patterns.json"),
  JSON.stringify({ allowFiles: ["patterns/definitions.txt"] })
);
mkdirSync(join(afDir, "patterns"), { recursive: true });
// allowed file: legitimately contains the identifier -> must NOT be flagged
writeFileSync(join(afDir, "patterns", "definitions.txt"), "identifier list includes " + ownerFrag + "\n");
const rAllowOnly = run(["--path", afDir]);
assert("allowFiles skips the whitelisted definition file", rAllowOnly.code === 0, `(code=${rAllowOnly.code})\n${rAllowOnly.out}`);
// now add a leak in a NON-allowed file -> must be flagged
writeFileSync(join(afDir, "leak.txt"), "oops " + ownerFrag + "@gmail.com leaked\n");
const rAllowLeak = run(["--path", afDir]);
assert("allowFiles does NOT suppress leaks in other files", rAllowLeak.code === 1, `(code=${rAllowLeak.code})\n${rAllowLeak.out}`);
assert("the leak.txt path (not definitions.txt) is what is flagged", /leak\.txt/.test(rAllowLeak.out) && !/definitions\.txt/.test(rAllowLeak.out), `\n${rAllowLeak.out}`);

// cleanup
for (const d of [dirtyDir, cleanDir, allowDir, extraDir, afDir]) {
  try {
    rmSync(d, { recursive: true, force: true });
  } catch {}
}

// ---- Test 7: --range diff mode catches a leak in the new commit only ----
function git(dir, args) {
  return execFileSync("git", ["-C", dir, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" },
  });
}
let gitTested = false;
try {
  const gitDir = mkdtempSync(join(tmpdir(), "msc-git-"));
  git(gitDir, ["init", "-q"]);
  writeFileSync(join(gitDir, "base.txt"), "clean baseline content\n");
  git(gitDir, ["add", "."]);
  git(gitDir, ["commit", "-q", "-m", "base"]);
  const baseSha = git(gitDir, ["rev-parse", "HEAD"]).trim();
  // new commit that introduces a leak
  writeFileSync(join(gitDir, "added.txt"), "new line with a private host 10.255.1.7 in it\n");
  git(gitDir, ["add", "."]);
  git(gitDir, ["commit", "-q", "-m", "add leak"]);
  const headSha = git(gitDir, ["rev-parse", "HEAD"]).trim();

  const rRange = run(["--path", gitDir, "--range", `${baseSha}..${headSha}`]);
  assert("--range catches a leak added in the outgoing commits", rRange.code === 1, `(code=${rRange.code})\n${rRange.out}`);
  assert("--range flags the added file", /added\.txt/.test(rRange.out), `\n${rRange.out}`);

  // --staged catches a leak in the index before commit
  writeFileSync(join(gitDir, "staged.txt"), "staged secret host 10.255.1.8 here\n");
  git(gitDir, ["add", "staged.txt"]);
  const rStaged = run(["--path", gitDir, "--staged"]);
  assert("--staged catches a staged leak", rStaged.code === 1, `(code=${rStaged.code})\n${rStaged.out}`);

  rmSync(gitDir, { recursive: true, force: true });
  gitTested = true;
} catch (e) {
  console.log(`  skip - git diff-mode tests (git unavailable: ${e.message})`);
}

console.log(`\n${passed} passed, ${failed} failed${gitTested ? "" : " (git tests skipped)"}`);
process.exit(failed ? 1 : 0);
