# mcp-sanity-check

A dependency-light CLI that scans a repository's tracked files for owner identifiers and secrets, then **exits non-zero if it finds any**. Drop it into CI or a pre-push hook and private data cannot ship into a public repo.

## What problem it solves

When you maintain a fleet of MCP servers (or any set of personal automation repos) that you plan to publish publicly, a single slip can embed your home IP, email, device hostname, or an API key in the Git history forever. `mcp-sanity-check` is the last gate before a push or a CI merge — it scans every tracked file and blocks the operation if anything personal is found.

The tool ships with **no owner identifiers baked in**, so the scanner itself can live in a public repo without leaking anyone's data. Your specific strings (emails, account IDs, home-LAN IPs, device names) stay in `~/.config/mcp-sanity/identifiers.json` on your machine and are never committed anywhere.

## Install

**One-liner via npx (no install needed):**

```bash
npx -y github:nidamen/mcp-sanity-check-mcp --path /path/to/repo
```

**Or install globally:**

```bash
npm install -g mcp-sanity-check
mcp-sanity-check --path /path/to/repo
```

**Or run from a local checkout:**

```bash
node bin/mcp-sanity-check.mjs --path /path/to/repo
```

Requires Node >= 18. Zero runtime dependencies.

## MCP client configuration

This tool runs as a **stdio** MCP server. Add it to your MCP client config:

```json
{
  "mcpServers": {
    "mcp-sanity-check": {
      "command": "npx",
      "args": ["-y", "github:nidamen/mcp-sanity-check-mcp"],
      "env": {}
    }
  }
}
```

To use your private identifier list, set the `MCP_SANITY_IDENTIFIERS` environment variable to the path of your `identifiers.json`:

```json
{
  "mcpServers": {
    "mcp-sanity-check": {
      "command": "npx",
      "args": ["-y", "github:nidamen/mcp-sanity-check-mcp"],
      "env": {
        "MCP_SANITY_IDENTIFIERS": "/Users/you/.config/mcp-sanity/identifiers.json"
      }
    }
  }
}
```

## CLI usage

```
mcp-sanity-check [--path <dir>] [--staged] [--range <a..b>] [--json] [--quiet] [--no-color]
```

| Flag               | Description                                                               |
| ------------------ | ------------------------------------------------------------------------- |
| `--path <dir>`     | Directory to scan. Default: current working directory.                    |
| `--staged`         | Scan only staged (index) added lines. For use in a pre-commit hook.       |
| `--range <a..b>`   | Scan only lines added in the given git commit range. Used by pre-push.    |
| `--json`           | Emit a machine-readable JSON report. Values are still masked.             |
| `--quiet`          | Suppress per-hit lines; print only the summary.                           |
| `--no-color`       | Disable ANSI color. Also honored via the `NO_COLOR` environment variable. |

**Exit codes:** `0` = clean, `1` = one or more hits found, `2` = usage error (bad path, etc.).

## Complete tool reference

This is a CLI tool, not an MCP tool-calling server. The scanner exposes one capability: scan a directory and report leaks.

### `mcp-sanity-check` (CLI / binary)

**Purpose:** Scan a repository for owner identifiers and secrets and exit non-zero if any are found.

**Modes:**

| Mode          | Trigger flag             | What is scanned                                           |
| ------------- | ------------------------ | --------------------------------------------------------- |
| Full scan     | (no flag, default)       | All git-tracked files, or full directory walk if not a git repo |
| Staged scan   | `--staged`               | Only added lines in the git index (`git diff --cached`)   |
| Range scan    | `--range <sha1>..<sha2>` | Only added lines in the given commit range                |

**Input parameters:**

| Parameter        | Type    | Required | Default         | Description                                      |
| ---------------- | ------- | -------- | --------------- | ------------------------------------------------ |
| `--path`         | string  | No       | `process.cwd()` | Absolute or relative path to the repo root        |
| `--staged`       | boolean | No       | false           | Enable staged-lines-only mode                    |
| `--range`        | string  | No       | null            | Git commit range string (`a..b`)                 |
| `--json`         | boolean | No       | false           | Emit JSON instead of colored text                |
| `--quiet`        | boolean | No       | false           | Suppress per-hit lines                           |
| `--no-color`     | boolean | No       | false           | Disable ANSI color codes                         |

**Returns (human mode):**

```
✓ mcp-sanity-check: clean (42 files scanned)
```

or on a hit:

```
✗ mcp-sanity-check: 2 potential leak(s) found
  SECRET    config.env:3  github-personal-access-token (ghp_)  -> ghp_****...ab
  IDENTIFIER src/client.js:7  owner-identifier:you@example.com  -> you@****
BLOCKED: 2 hit(s) across 42 files. Remove the values above, ...
```

**Returns (JSON mode, `--json`):**

```json
{
  "ok": false,
  "filesScanned": 42,
  "hitCount": 2,
  "mode": "full",
  "hits": [
    {
      "file": "config.env",
      "line": 3,
      "class": "secret",
      "pattern": "github-personal-access-token (ghp_)",
      "masked": "ghp_****...ab"
    }
  ]
}
```

Fields in each hit object:

| Field     | Type   | Description                                                    |
| --------- | ------ | -------------------------------------------------------------- |
| `file`    | string | Relative path of the file containing the hit                   |
| `line`    | number | 1-indexed line number                                          |
| `class`   | string | `"identifier"`, `"pii"`, or `"secret"`                        |
| `pattern` | string | Human-readable name of the rule that matched                   |
| `masked`  | string | First 4 + last 2 chars of the value; middle replaced with `*` |

## What gets flagged

### Owner identifiers

Loaded at runtime from (in priority order):

1. Path in `$MCP_SANITY_IDENTIFIERS` environment variable (points to a JSON file).
2. `~/.config/mcp-sanity/identifiers.json` (default private config location).
3. `identifiers` array in the scanned repo's `.sanity-patterns.json`.

The JSON file must be an object with an `identifiers` array of strings:

```json
{ "identifiers": ["your@email.com", "192.168.1.50", "myhostname", "acct-id-xyz"] }
```

This file is never committed anywhere. It lives only on your machine.

### Generic PII (public CI backstop)

Even without a private identifier list, the scanner catches:

| Pattern name              | What it matches                                    |
| ------------------------- | -------------------------------------------------- |
| `email-address`           | Any `user@domain.tld` email                        |
| `private-ipv4 (RFC1918)`  | 10.x.x.x, 192.168.x.x, 172.16-31.x.x addresses   |
| `personal-home-path`      | `/Users/<name>` or `/home/<name>` path segments   |
| `mac-address`             | Six colon-separated hex octets                     |

Obvious documentation placeholders (`you@example.com`, `192.168.1.1`, `/home/user`, `aa:bb:cc:dd:ee:ff`, etc.) are excluded so docs and examples do not trip the backstop.

### Secret patterns

| Pattern name                          | Shape matched                                           |
| ------------------------------------- | ------------------------------------------------------- |
| `github-personal-access-token (ghp_)` | `ghp_` + 20+ alphanumeric chars                        |
| `github-fine-grained-pat`             | `github_pat_` + 20+ chars                               |
| `openai-api-key (sk-)`                | `sk-` + 20+ alphanumeric/dash/underscore chars         |
| `slack-token (xox*)`                  | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` + 10+ chars |
| `aws-access-key-id (AKIA)`            | `AKIA` + 16 uppercase alphanumeric chars               |
| `google-api-key (AIza)`               | `AIza` + 30+ alphanumeric chars                        |
| `private-key-block`                   | `-----BEGIN ... PRIVATE KEY-----`                      |
| `high-entropy-assignment`             | `*key/secret/token/password* = "40+ high-entropy chars"` |

The high-entropy rule fires only when the assigned value is 40+ characters, base64-ish, and clears a Shannon-entropy threshold (H >= 3.5 bits/char, 12+ distinct characters). This keeps false positives low on long-but-repetitive strings.

All matched values are **masked** in output: the first 4 and last 2 characters are shown; everything in between is replaced with `*`.

## Private config: `~/.config/mcp-sanity/`

The directory `~/.config/mcp-sanity/` is the one place the owner's specific identifiers live. It is:

- Never committed (it sits outside any repo).
- Never referenced by path in any tracked file.
- Loaded at runtime by the scanner binary on the machine where the private list is needed.

Structure:

```
~/.config/mcp-sanity/
  identifiers.json      <- {"identifiers": ["your@email.com", "192.168.1.50", ...]}
```

## How a repo opts in

### Option 1: CI workflow

Copy `.github/workflows/sanity-check.yml` from this repo into the target repo. It runs on every push and PR using `ubuntu-latest` + Node 20, fetches the full history, and fails the build on any hit.

It can also be called as a reusable workflow:

```yaml
jobs:
  sanity:
    uses: nidamen/mcp-sanity-check/.github/workflows/sanity-check.yml@main
```

### Option 2: Pre-push git hook

Install `hooks/pre-push` so leaks are blocked before they ever reach the remote. The hook scans only the outgoing commit range, so it is fast.

```bash
# Per-repo:
cp /path/to/mcp-sanity-check/hooks/pre-push /path/to/your-repo/.git/hooks/pre-push
chmod +x /path/to/your-repo/.git/hooks/pre-push

# Shared across all repos (global hooks dir):
mkdir -p ~/.git-hooks
cp /path/to/mcp-sanity-check/hooks/pre-push ~/.git-hooks/pre-push
chmod +x ~/.git-hooks/pre-push
git config --global core.hooksPath ~/.git-hooks
```

The hook resolves the scanner via (in order): `$MCP_SANITY_CHECK` env var (full path to the `.mjs`), `mcp-sanity-check` on `PATH`, or `npx mcp-sanity-check`.

To bypass intentionally (not recommended): `git push --no-verify`.

## Per-repo tuning: `.sanity-patterns.json`

Place a `.sanity-patterns.json` file at the scanned repo's root to extend or relax the defaults:

```json
{
  "identifiers": ["ACME_INTERNAL_CODENAME", "another-owner-string"],
  "allow":       ["EXAMPLE_PLACEHOLDER"],
  "allowFiles":  ["docs/sample-output.txt", "test/fixtures/"]
}
```

| Key           | Type          | Effect                                                                          |
| ------------- | ------------- | ------------------------------------------------------------------------------- |
| `identifiers` | string array  | Added to the runtime identifier list. Case-insensitive substring match.         |
| `allow`       | string array  | If a flagged line contains any allow-string, the hit is dropped. For known false positives and sample data. |
| `allowFiles`  | string array  | File-path substrings: any file whose relative path contains one of these is skipped entirely. Use sparingly, only for files that legitimately define or document the patterns. |

## Quick usage examples

**Check a repo before publishing:**

```bash
mcp-sanity-check --path ~/code/my-mcp-server
```

**Run in CI (no color, machine output):**

```bash
mcp-sanity-check --path . --no-color --json | tee scan-report.json
```

**Check only what you are about to commit:**

```bash
mcp-sanity-check --staged
```

## Tests

```bash
npm test
# or
node test/run.mjs
```

The suite creates dirty fixtures in a temp directory (planted identifiers and secrets never live in tracked source), confirms the scanner catches them, confirms the values are masked in output, confirms the allow-list suppresses false positives, and confirms a clean directory exits zero.

## Limitations

- Scans text files only. Files larger than 5 MB and files with a NUL byte in the first 4 KB are skipped.
- Binary file types (images, archives, compiled objects, fonts, audio, video, SQLite, lock files) are skipped by extension.
- The high-entropy rule can still produce false positives on long deterministic strings (base64-encoded config blobs, encoded protobuf payloads). Use `allow` in `.sanity-patterns.json` to suppress these.
- Generic PII patterns (email, RFC1918 IP, home path, MAC) are designed to catch leaks in public CI where the private identifier list is unavailable; they may fire on legitimate example values that are not in the placeholder list. Add them to `allow` as needed.
- `--staged` and `--range` modes scan only added lines in the diff, not the full file state. A pre-existing leak in unchanged lines is not caught until a full `--path` scan is run.
- Entropy check thresholds (H >= 3.5, distinct >= 12) were tuned empirically; an unusually low-entropy real secret may not be caught by the high-entropy rule (but would still be caught if it matches a named pattern).

## License

MIT
