# mcp-sanity-check: Technical Whitepaper

## Overview and motivation

Publishing automation code publicly is high-value and high-risk at the same time. A single commit can permanently embed a personal email address, a home-LAN IP, a device hostname, an account ID, or a live API key into Git history. Once that history is public, the data is effectively unretractable even after a forced rewrite.

`mcp-sanity-check` is a purpose-built pre-publish PII and secret gate for repositories in a personal MCP fleet or any other personal automation collection. It sits at two chokepoints: the pre-push git hook (on the developer's own machine, where the private identifier list is available) and a CI workflow (on GitHub Actions, where only generic patterns are available). Together they form a two-layer defense: the hook stops leaks before they ever reach a remote; CI catches anything that slips through if the hook is missing or bypassed.

The design constraint is that the scanner itself must be safe to publish publicly. It contains no owner-specific strings. Every personal identifier stays in a private config file on the owner's machine and is loaded at runtime. The public tool is a generic scanner; the private config makes it owner-aware.

## Architecture and transport

`mcp-sanity-check` is a **Node.js ESM CLI** with zero runtime dependencies. It uses only Node built-ins (`child_process`, `fs`, `path`, `os`).

Transport: **stdio**. When used as an MCP server, the client spawns the binary via `npx` or a direct node invocation and communicates over standard input/output. The server is stateless per invocation.

File enumeration strategy:

1. If the target directory is a git repository, `git ls-files -z` enumerates tracked files. This is the primary path: untracked files (including secrets that were never staged) are not scanned.
2. If git is unavailable or the target is not a git repository, a recursive directory walk is used, excluding `node_modules`, `.venv`, `venv`, `.git`, `dist`, `build`, `.next`, `coverage`, and `__pycache__`.

In `--staged` or `--range` mode, `git diff --no-color --unified=0` is used and only added lines (`+` prefix) are parsed. This makes incremental scans fast and avoids re-flagging pre-existing content that the developer cannot change without a history rewrite.

Binary file exclusions by extension: `png jpg jpeg gif webp ico bmp tiff pdf zip gz tar tgz bz2 7z rar exe dll so dylib o a class jar woff woff2 ttf eot otf mp3 mp4 mov avi wav flac wasm bin dat db sqlite lock`. Files larger than 5 MB are also skipped. Files with a NUL byte in the first 4 KB are treated as binary and skipped.

## Security and privacy design

### Identifier isolation

The most sensitive design decision is: where do owner-specific strings live?

**They never live in any tracked file.** The public repo ships with `DEFAULT_IDENTIFIERS = []`. The scanner's own source code is free of any personal data and can be published, forked, and audited by anyone.

Owner identifiers are loaded at runtime from private, untracked locations:

1. Path pointed to by `$MCP_SANITY_IDENTIFIERS` environment variable (the env var holds a filesystem path, not the identifiers themselves, so the env is also safe to log).
2. `~/.config/mcp-sanity/identifiers.json` on the local machine (default).
3. `identifiers` array in the scanned repo's `.sanity-patterns.json` (repo-local extras, committed, so these should be non-sensitive project-specific strings only).

The private `~/.config/mcp-sanity/identifiers.json` format:

```json
{ "identifiers": ["owner@email.com", "192.168.1.50", "myhostname", "cf-acct-id"] }
```

This file is owned by the local user, not committed anywhere, and is the one place that ties the generic public scanner to a specific person.

### Value masking

Matched values are never printed in full. The mask function keeps the first 4 and last 2 characters and replaces the middle with `*` characters. This gives enough context to locate and remove the value without leaking it via scan output, CI logs, or terminal history. Masked values also appear in JSON mode.

### False positive suppression

The scanner includes several mechanisms to reduce noise:

- **PII placeholders:** A hardcoded list of documentation placeholders (`you@example.com`, `192.168.1.1`, `/home/user`, `aa:bb:cc:dd:ee:ff`, etc.) exempts those exact strings from generic PII hits. RFC 2606/6761 reserved domains (`example.com`, `example.org`, `test`, `invalid`, `localhost`) are also excluded from email matches.
- **`.sanity-patterns.json` allow list:** Lines containing any string in the `allow` array are not flagged, even if they match a pattern. This handles intentional sample data, test fixtures referencing placeholders, and documented examples.
- **`.sanity-patterns.json` allowFiles list:** Entire files can be exempted by path substring. Use this only for files that legitimately define or document the patterns (e.g. the scanner's own identifier-list file, a test fixtures directory). Leaks in all other files are still caught.
- **Shannon entropy gate:** The high-entropy assignment rule only fires when H >= 3.5 bits/char AND the value has >= 12 distinct characters. This prevents long-but-repetitive strings (version constants, repeated characters, human-readable encoded values) from triggering false alarms.
- **Hit deduplication:** If the same (class, pattern, value) tuple appears multiple times on the same line (e.g. a name inside an email matched by two patterns), only one hit is reported.

## Capability self-report

### Scan modes

- **Full scan** (`--path <dir>`, default): scans all git-tracked text files in the repository, or all files in a directory walk if not a git repo.
- **Staged scan** (`--staged`): scans only lines added to the git index since the last commit. Designed for pre-commit hook use.
- **Range scan** (`--range <a>..<b>`): scans only lines added in a specific git commit range. Used by the pre-push hook to scan only outgoing commits.

### Detection classes

- **`identifier`**: matches a string from the owner's private identifier list (loaded from `~/.config/mcp-sanity/identifiers.json` or `$MCP_SANITY_IDENTIFIERS`). Purely alphabetic identifiers use word-boundary matching; everything else (emails, paths, IPs, IDs with separators) uses a case-insensitive substring search.
- **`pii`**: matches a generic PII pattern with no knowledge of any specific person. Catches emails, RFC1918 addresses, personal home paths (`/Users/<name>`, `/home/<name>`), and MAC addresses. This is the public-CI backstop.
- **`secret`**: matches a named credential pattern or a high-entropy value assigned to a credential-named field.

### Named secret patterns

- `github-personal-access-token (ghp_)`: GitHub classic PAT (`ghp_` + 20+ chars).
- `github-fine-grained-pat (github_pat_)`: GitHub fine-grained PAT (`github_pat_` + 20+ chars).
- `openai-api-key (sk-)`: OpenAI secret key (`sk-` + 20+ alphanumeric/dash/underscore chars).
- `slack-token (xox*)`: Slack bot/user/app token (`xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` + 10+ chars).
- `aws-access-key-id (AKIA)`: AWS access key ID (`AKIA` + 16 uppercase alphanumeric chars).
- `google-api-key (AIza)`: Google API key (`AIza` + 30+ alphanumeric chars).
- `private-key-block`: PEM private key header (`-----BEGIN ... PRIVATE KEY-----`).
- `high-entropy-assignment (<field>)`: Any `*key/secret/token/password/passwd/pwd*`-named field assigned a 40+ character base64-ish value that clears the entropy gate.

### Generic PII patterns (backstop)

- `email-address`: any `user@domain.tld` form.
- `private-ipv4 (RFC1918)`: 10.x.x.x, 192.168.x.x, 172.16-31.x.x.
- `personal-home-path`: `/Users/<name>` or `/home/<name>`.
- `mac-address`: six colon-separated hex octets.

### Output formats

- **Human text** (default): colored, per-hit lines with `file:line`, pattern name, and masked value; final summary count.
- **JSON** (`--json`): structured object with `ok`, `filesScanned`, `hitCount`, `mode`, and `hits` array (each hit: `file`, `line`, `class`, `pattern`, `masked`).

### Integration artifacts

- **Pre-push hook** (`hooks/pre-push`): bash script; scans outgoing commit range; blocks the push on any hit; resolves the scanner binary via env var, PATH, or npx.
- **GitHub Actions workflow** (`.github/workflows/sanity-check.yml`): runs on push and pull request; can also be called as a reusable workflow from another repo.

### Per-repo configuration (`.sanity-patterns.json`)

- `identifiers` (string array): additional strings appended to the runtime identifier list.
- `allow` (string array): line-level allow-list; a flagged line containing any of these strings is suppressed.
- `allowFiles` (string array): file-level allow-list by path substring; matching files are skipped entirely.

## Full capability reference

### CLI interface

#### Invocation

```
mcp-sanity-check [options]
```

All options are parsed from `process.argv`. The `NO_COLOR` environment variable is also honored.

#### Parameters

| Parameter / env var          | Type    | Required | Default            | Description                                                                       |
| ---------------------------- | ------- | -------- | ------------------ | --------------------------------------------------------------------------------- |
| `--path <dir>`               | string  | No       | `process.cwd()`    | Root of the directory or repo to scan. Resolved to an absolute path.              |
| `--staged`                   | flag    | No       | false              | Scan only lines added to the git index (pre-commit use).                          |
| `--range <a..b>`             | string  | No       | null               | Scan only lines added in the given git commit range (pre-push use).               |
| `--json`                     | flag    | No       | false              | Emit machine-readable JSON. Values are masked.                                    |
| `--quiet`                    | flag    | No       | false              | Suppress individual hit lines; print only the summary count.                      |
| `--no-color`                 | flag    | No       | false              | Disable ANSI color codes in output.                                               |
| `--help` / `-h`              | flag    | No       | false              | Print a short usage message and exit 0.                                           |
| `$MCP_SANITY_IDENTIFIERS`    | env var | No       | (none)             | Filesystem path to a private `{"identifiers":[...]}` JSON file.                   |
| `$NO_COLOR`                  | env var | No       | (none)             | Any non-empty value disables ANSI color (standard convention).                    |

#### Exit codes

| Code | Meaning                                                     |
| ---- | ----------------------------------------------------------- |
| `0`  | Clean: no identifiers or secrets found.                     |
| `1`  | Dirty: one or more hits found.                              |
| `2`  | Usage error: path not found or invalid arguments.           |

#### JSON output schema

```json
{
  "ok": true,
  "filesScanned": 0,
  "hitCount": 0,
  "mode": "full | staged | range",
  "hits": [
    {
      "file": "relative/path/to/file.txt",
      "line": 42,
      "class": "identifier | pii | secret",
      "pattern": "pattern-name",
      "masked": "abcd****ef"
    }
  ]
}
```

### Runtime configuration loading

The scanner builds the active identifier list by merging (in order, deduplicated):

1. `DEFAULT_IDENTIFIERS` (always empty in the public build).
2. Strings from the file at `$MCP_SANITY_IDENTIFIERS`, if that env var is set and the file exists and parses.
3. Strings from `~/.config/mcp-sanity/identifiers.json`, if that file exists and parses.
4. Strings from the `identifiers` key in the scanned repo's `.sanity-patterns.json`, if present.

If neither a private config file nor a repo config is found, only generic PII and named secret patterns are active.

### File filtering logic

In full scan mode, the following files are excluded:

- Files whose extension is in the binary extension set (see Architecture section).
- Files larger than 5 MB.
- Files with a NUL byte in the first 4 KB (binary sniff).
- Files whose relative path contains a substring listed in `.sanity-patterns.json` `allowFiles`.

In `--staged` and `--range` modes, only the added lines from the git diff are examined; exclusions are applied at the file level.

### Line scanning logic

For each text line:

1. If the line contains any substring from the `allow` list, skip it entirely (no hits reported).
2. Test each owner identifier string. Purely alphabetic strings use word-boundary regex; all others use case-insensitive substring search. Each match produces a hit of class `identifier`.
3. Test each generic PII pattern (email, RFC1918 IP, home path, MAC). Placeholder-matching values are dropped. Each remaining match produces a hit of class `pii`.
4. Test each named secret regex. Each match produces a hit of class `secret`.
5. Test the high-entropy assignment regex. For each capture, compute Shannon entropy and distinct-character count. If H >= 3.5 and distinct >= 12, produce a hit of class `secret` with pattern `high-entropy-assignment (<field>)`.
6. Deduplicate hits with identical (class, pattern, value) on the same line.

## Operational notes

### Pre-push hook placement

The pre-push hook is the most important integration point for owner-identifier scanning, because it is the only place where the private `~/.config/mcp-sanity/identifiers.json` is available. CI does not have access to this file, so CI only catches generic PII and named secrets.

Install the hook in every repo that will ever be published publicly. For a personal fleet, use a global hooks directory:

```bash
mkdir -p ~/.git-hooks
cp /path/to/mcp-sanity-check/hooks/pre-push ~/.git-hooks/pre-push
chmod +x ~/.git-hooks/pre-push
git config --global core.hooksPath ~/.git-hooks
```

Point the hook at the local scanner binary for speed (avoid npx network round-trips):

```bash
export MCP_SANITY_CHECK=~/code/personal/open-mcp/mcp-sanity-check/bin/mcp-sanity-check.mjs
```

Add this to your shell profile so it persists.

### False positive management

Start with a full scan and resolve all hits before publishing:

1. **Real leak (remove it):** Delete or rotate the value. If it is in git history, use `git filter-repo` or `git filter-branch` to purge it, then force-push.
2. **Intentional sample data:** Add the line's distinguishing token to `allow` in `.sanity-patterns.json`.
3. **Definition or fixture file that legitimately contains patterns:** Add its path substring to `allowFiles` in `.sanity-patterns.json`. Keep this list minimal.
4. **Generic PII placeholder that is not in the built-in exclusion list:** Add it to `allow`.

### Running a one-time audit

To audit an existing repo that already has history:

```bash
mcp-sanity-check --path /path/to/repo
```

This scans only tracked files at HEAD. It does not scan historical commits. For a history audit, use `git log` and `git show` or a dedicated history-scanning tool.

### Updating the private identifier list

When you add a new email address, a new IP, or a new account ID that should never appear publicly, add it to `~/.config/mcp-sanity/identifiers.json`. No restart or reinstall is required; the file is loaded fresh on each scanner invocation.

## Known limitations and caveats

- **No history scanning:** only the current working tree (or the specified diff range) is scanned. Historical commits are not examined.
- **Git-tracked files only:** untracked files are not scanned in full mode. A secret that was never staged and never committed will not be found.
- **Binary file exclusions may miss some formats:** container images, compiled protobuf files, or binary config formats embedded in otherwise text files may contain personal data that the scanner does not examine.
- **High-entropy false positives:** long deterministic strings (compressed payloads, encoded protobuf, base64 certificates) may trigger the high-entropy rule. Use `allow` to suppress.
- **Low-entropy secrets:** a real API key or password that is short or human-readable may not trigger the high-entropy rule, though it will still be caught if it matches a named pattern (e.g. `ghp_`, `sk-`, `AKIA`).
- **`--staged` and `--range` miss pre-existing leaks:** these modes check only newly added lines. A leak already in the repo before the hook was installed is not caught until a full scan is run.
- **No network requests:** the scanner operates entirely offline. It does not validate whether a matched credential is still active or revoked.
- **Node >= 18 required:** the tool uses native ESM and Node 18+ built-ins.

## Roadmap and TODO

- Support for additional secret patterns: Anthropic API keys, Cloudflare API tokens, Stripe keys, GitHub App private keys.
- Support for scanning arbitrary text (stdin pipe) without requiring a file path.
- `--history` flag to scan all commits in the current branch's history.
- Watch mode for continuous integration in local development.
- Optional integration with `git-secrets` pattern file format for interoperability.
- Configurable entropy and length thresholds via `.sanity-patterns.json`.
- npm registry publication for a faster `npx` experience (no GitHub round-trip).
