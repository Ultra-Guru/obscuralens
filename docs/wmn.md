# WhatsMyName dataset interop

ObscuraLens can sweep usernames across the community-curated
[WhatsMyName](https://github.com/WebBreacher/WhatsMyName) dataset (by Micah
Hoffman / WebBreacher and the OSINT community) in addition to its own
live-verified 112-platform registry. The dataset currently carries **~690
valid site checks across 20 categories** (social, coding, gaming, finance,
dating, ...) and is the same site list projects like Sherlock and Maigret
consume — so ObscuraLens results stay comparable with the wider ecosystem
while keeping the honest three-state verdicts this project is built on.

## The 60-second version

```bash
obscuralens wmn update                  # download the official dataset
obscuralens wmn info                    # provenance + integrity digest
obscuralens wmn categories              # browse the 20 categories
obscuralens wmn check somename          # sweep (all categories)
obscuralens wmn check somename --category social,coding
obscuralens wmn check somename --sites GitHub,Mastodon --limit 10
obscuralens wmn check somename --format json -o wmn.json
```

## Why a second username registry?

The built-in sweep (`obscuralens username`) checks 112 platforms whose
200-vs-404 splits and verdict rules were verified by hand, with profile
extraction on hits. The WMN dataset adds ~580 *extra* sites that the
community maintains — far broader coverage, at lower per-site trust:

| | built-in `username` sweep | WMN sweep (`wmn check`) |
|---|---|---|
| Sites | 112 (hand-verified) | ~690 (community-verified) |
| Verdicts | honest 3-state + per-platform rules | honest 3-state from WMN's own e/m rules |
| Profile extraction | yes (deep scans) | no (URLs only; `uri_pretty` when the dataset provides it) |
| Bot-walled sites | excluded by design | excluded by default (`--include-protected` to opt in) |
| Update cadence | per release | whenever the community ships (`wmn update`) |

Use the built-in sweep for depth, the WMN sweep for breadth, and treat a
WMN row like any other fact: its confidence column tells you how it was
decided (see the verdict table below).

## Commands

### `obscuralens wmn update`

Downloads the official dataset
(`WebBreacher/WhatsMyName`, `wmn-data.json` on the `main` branch) into the
config directory (`wmn-data.json` + a `wmn-data.meta.json` sidecar), then
prints a summary: source URL, SHA-256 of the stored file, fetch time,
license, and the valid/skipped breakdown. Entries that fail validation are
listed with reasons — as of writing the only skip is the single site the
upstream dataset itself marks `valid: false`.

- `--source PATH_OR_URL` imports a different dataset: any local JSON file
  or http(s) URL using the WMN schema (useful for pinning a dataset copy,
  an internal mirror, or a reduced internal list).
- The cache write is atomic (tmp + replace); a killed process cannot leave
  a truncated dataset behind.
- The download bypasses the HTTP response cache — `wmn update` always asks
  the network.

### `obscuralens wmn info`

Prints the cached dataset's provenance (source, fetched-at, license,
authors) plus the SHA-256 digest and the per-category site counts. The
cached file is re-validated and its digest checked against the sidecar on
every load — a corrupted cache degrades to "no dataset" (with a hint to
re-run `wmn update`) instead of sweeping half a list.

### `obscuralens wmn categories`

Lists the dataset's categories with site counts (`social`, `coding`,
`gaming`, `finance`, ...). `--format json` emits the raw mapping.

### `obscuralens wmn check <username>`

Sweeps one username across the selected sites in parallel (thread pool
honours `max_workers`, per-host rate limits apply, proxies from the config
are used). Output is a summary grid plus a per-site results table, or
`--format json` / `csv` for tooling — the row schema matches the built-in
username sweep (`platform`, `url`, `status`, `confidence`, `reason`,
`status_code`, `response_time`), so downstream tooling can consume both
without special-casing.

Filters:

- `--category social,coding` — restrict to categories (case-insensitive).
- `--sites Name1,Name2` — restrict to site names (case-insensitive).
- `--limit N` — cap the number of sites checked after filtering (useful
  for a quick taste before committing to a full sweep).
- `--include-protected` — include sites WMN flags as bot-protected
  (Cloudflare & friends). Off by default: from scripted clients those can
  only ever answer "unknown", so excluding them saves noise, not signal.

Username validation is shared with the built-in sweep
(`obscuralens.utils.validators.validate_username`), so the `{account}`
placeholder can never be abused to inject path tricks into a site URL.

## Verdict mapping

WMN encodes per-site rules as an expected "found" response
(`e_code` + optional `e_string`) and an expected "missing" response
(`m_code` + optional `m_string`). ObscuraLens maps them onto the honest
three-state model:

| Condition | Verdict | Confidence |
|---|---|---|
| `status == e_code` and `e_string` in body | `found` | **high** |
| `status == e_code`, no `e_string` declared | `found` | medium (community-verified status split) |
| `m_string` present in body | `not_found` | **high** |
| `status == m_code`, no `m_string` declared | `not_found` | medium (community-verified missing split) |
| HTTP 400/401/403/429/999 (bot wall / rate limit) | `unknown` | low |
| network error | `unknown` | low |
| anything else (code/evidence mismatch) | `unknown` | low |

Notes:

- Evidence matching is **case-insensitive** so a small markup change cannot
  flip a verdict; a genuinely redesigned page fails the evidence check and
  lands in `unknown` — never a fabricated hit.
- POST entries (23 sites use a form/GraphQL body instead of a GET) are
  supported: the body is sent with the entry's declared headers via the
  shared HTTP client's raw `post`.
- A bare `200` is **never** a hit on a site whose WMN entry declares an
  `e_string` that is missing from the response. Example seen in the wild
  while validating this integration: PyPI now serves a JS shell for
  profile pages, its WMN entry still expects `Profile of`, and ObscuraLens
  reports `unknown (no decisive signal)` instead of a false positive.

## Integrity & trust

- The digest recorded at `wmn update` time is shown in `wmn info`, in the
  sweep summary, and in every JSON result (`dataset.sha256`), so a report
  can always state exactly which dataset revision produced it.
- Upstream `valid: false` entries are skipped; malformed entries (missing
  fields, missing `{account}` placeholder, impossible status codes) are
  skipped with reasons rather than silently repaired.
- Duplicate site names are deduplicated (first wins) and reported.

## OPSEC

The WMN sweep is active reconnaissance: it sends one HTTP request per
selected site from your machine (or your configured proxy). Keep sweeps
targeted (`--category`, `--sites`, `--limit`), respect the rate limiter,
and remember that the dataset itself carries categories like `xx NSFW xx`
that you may want to exclude from professional reports.

## Testing

`tests/test_wmn.py` (53 cases) covers site validation, dataset parsing and
dedup, cache integrity (digest mismatch, atomic writes, missing sidecar),
URL failure paths, the full verdict matrix, category/name/protected
filters, POST-body entries, pretty-URL handling, and the CLI surface — all
offline against synthetic datasets and the shared HTTP fakes.
