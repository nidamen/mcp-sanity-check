# mcp-sanity-check

A dependency-light **PII / secret sanity-check gate**. It scans a repository's
tracked files for two classes of leak and **fails (exit 1)** if it finds any,
so private data never ships into a public or open-source repo.

1. **Owner identifiers** — names, emails, home-LAN IPs, device hostnames, cloud
   account IDs, and other personal strings that should never appear in public
   code. A default set is baked in; each repo can extend or relax it.
2. **Secrets** — GitHub PATs, OpenAI keys, Slack tokens, AWS access-key IDs,
   Google API keys, PEM private-key blocks, and high-entropy values assigned to
   `*key* / *secret* / *token* / *password*`-named fields.

Every hit is reported as `file:line` plus the pattern that matched, with the
**value masked** so the scanner output itself never leaks the secret.

Pure Node + regex, ESM, zero runtime dependencies. Node >= 18.

## Install

This is a standalone CLI. From a checkout:

```bash
node bin/mcp-sanity-check.mjs --path /path/to/repo
```

Or, once available on a registry / via a local link:

```bash
npm i -g mcp-sanity-check   # or: npm link from this dir
mcp-sanity-check --path /path/to/repo
```

## Usage

```bash
mcp-sanity-check [--path <dir>] [--staged] [--range <a..b>] [--json] [--quiet] [--no-color]
```

| Flag            | Meaning                                                                 |
| --------------- | ----------------------------------------------------------------------- |
| `--path <dir>`  | Directory to scan (default: cwd).                                       |
| `--staged`      | Scan only **staged** added lines (`git diff --cached`). Pre-commit use. |
| `--range <a..b>`| Scan only lines added in a commit range. Used by the pre-push hook.     |
| `--json`        | Machine-readable JSON report (still masks values).                     |
| `--quiet`       | Suppress per-hit lines; print only the summary.                        |
| `--no-color`    | Disable ANSI color (also honored via `NO_COLOR`).                      |

**Exit code:** `1` if any identifier/secret is found, `0` if clean, `2` on a
usage error (e.g. missing path).

By default the scanner enumerates **git-tracked files** (`git ls-files`). If the
target is not a git repo, it walks the directory, excluding `node_modules`,
`.venv`, `.git`, `dist`, `build`, `.next`, `coverage`, and `__pycache__`, and
skips binary file types.

## How a repo opts in

### 1. CI workflow

Copy [`.github/workflows/sanity-check.yml`](.github/workflows/sanity-check.yml)
into the repo you want to protect. It checks out the repo and runs the scanner on
every push and PR, failing the build on any hit. It can also be invoked as a
[reusable workflow](https://docs.github.com/actions/using-workflows/reusing-workflows)
with `uses: <owner>/mcp-sanity-check/.github/workflows/sanity-check.yml@main`.

### 2. Pre-push git hook

Install [`hooks/pre-push`](hooks/pre-push) so leaks are blocked **before** they
ever reach the remote. It scans only the **outgoing** commit range, so it is fast
and ignores pre-existing history.

```bash
# Per-repo:
cp hooks/pre-push /path/to/repo/.git/hooks/pre-push
chmod +x /path/to/repo/.git/hooks/pre-push

# Or shared across all repos that opt in:
mkdir -p ~/.git-hooks && cp hooks/pre-push ~/.git-hooks/
chmod +x ~/.git-hooks/pre-push
git config --global core.hooksPath ~/.git-hooks
```

The hook finds the scanner via `$MCP_SANITY_CHECK` (full path to the `.mjs`), a
`mcp-sanity-check` binary on `PATH`, or `npx mcp-sanity-check`, in that order.

To bypass intentionally (not recommended): `git push --no-verify`.

## Per-repo tuning: `.sanity-patterns.json`

Drop a `.sanity-patterns.json` at the scanned repo's root to customize:

```json
{
  "identifiers": ["ACME_INTERNAL_CODENAME", "another-owner-string"],
  "allow": ["EXAMPLE_PLACEHOLDER"],
  "allowFiles": ["docs/sample-output.txt", "test/fixtures/"]
}
```

- **`identifiers`** are **added** to the baked-in defaults (case-insensitive
  substring match).
- **`allow`** substrings whitelist a **line**: if a flagged line contains any
  `allow` substring, that hit is dropped. Use it for intentional sample data and
  documented placeholders.
- **`allowFiles`** substrings whitelist a **whole file** by relative path: any
  scanned file whose path contains one of these substrings is skipped. Use it
  sparingly, only for files that legitimately *define* or *document* the
  patterns (e.g. a security tool's own pattern list, or a fixtures directory).
  This is a per-file bypass, so keep the list tight; a leak in any other file is
  still caught.

## What gets flagged

**Owner identifiers** (default set, case-insensitive): personal names, the
owner's email addresses, home `/Users/` and `/home/` paths, a Cloudflare account
ID, Supabase project refs, the home-LAN and tailnet IP prefixes, Pi/host names,
a license/recovery code, and a device MAC address.

**Secrets** (regex):

| Pattern                       | Example shape                          |
| ----------------------------- | -------------------------------------- |
| GitHub PAT                    | `ghp_…`                                |
| GitHub fine-grained PAT       | `github_pat_…`                         |
| OpenAI key                    | `sk-…` (20+ chars)                     |
| Slack token                   | `xoxb-` / `xoxp-` / `xoxa-` / `xoxr-` / `xoxs-` |
| AWS access-key ID             | `AKIA…` (16 chars)                     |
| Google API key                | `AIza…` (30+ chars)                    |
| PEM private key               | `-----BEGIN … PRIVATE KEY-----`        |
| High-entropy assigned secret  | `api_key = "…40+ high-entropy chars…"` |

The high-entropy rule only fires when the value is long, base64-ish, and clears a
Shannon-entropy threshold, which keeps false positives low.

## Tests

```bash
npm test
# or
node test/run.mjs
```

The suite generates dirty fixtures in a temp dir (so planted identifiers/secrets
never live in this repo's tracked source), proves the scanner catches a planted
`nidamen` identifier and planted secrets, **masks** them in output, honors the
`allow`-list and custom `identifiers`, and passes on a clean file.

## License

MIT
