# Egress Guard

**Why.** AI agents leak data by accident, not malice. Asked to summarize a clinic dataset for a colleague, an agent may include a table showing three patients in a small town (enough for neighbours to work out who they are), upload the raw file to a paste site to "share" it, or paste an API key into a command. Everything that leaves the agent (commands, uploads, messages, replies) is *egress*. Egress Guard checks it in code, outside the model, before it leaves, so the protection doesn't depend on the model remembering the rules.

A policy-driven guard for what leaves a Hermes agent. It runs as plain Python hooks,
**outside the model**, so it behaves the same on a small local model as on a frontier one.
A prompt can ask a model to behave. A plugin can enforce it.

Egress Guard does three things:

1. **Redacts credentials in tool arguments** before a command runs (Hermes does not redact arguments).
2. **Sends data-upload commands to Hermes's approval prompt** when the destination is not on your allowlist
   (`curl -d`, `wget --post-file`, `nc`, `scp`, `rsync`, `aws s3 cp`, `gsutil cp`, `rclone copy`, `gh gist create`,
   `git push` to a URL, `python -c`/`node -e` upload one-liners and similar). With nobody present to approve, the call is blocked.
3. **Suppresses small counts in tables** (statistical disclosure control), including the extra cells needed so a
   hidden value cannot be worked out from the row and column totals, and the percentages that would give it away.

It also notes record-level tables (microdata) in its audit log, and adds a `/guard` command to check what it is doing.

## Demo

A cross-tab of 800 synthetic records, copied by a local `qwen2.5:7b` model through Hermes. Same prompt, plugin off then on
(demo policy that also hides small cells from tool results, see [Policies](#policies)):

```
Plugin off:  | Peace Valley | 7 | 0 | 3 | 10 |
Plugin on:   | Peace Valley | [suppressed] | 0 | [suppressed] | 10 |
```

Only the 3 is below the threshold of 5. Egress Guard also hides five other cells (7, 8, 9, 20 and 29) so the 3 cannot be
recovered by subtraction from any row or column total. The totals stay visible. Result: 4 of 4 runs suppressed with the plugin
on, 4 of 4 showed raw values with it off. All data is synthetic.

Solving the visible row and column totals, an attacker can only tell that the hidden 3 is somewhere between 0 and 10.

## How it works

| Hermes hook | What Egress Guard does |
|---|---|
| `pre_tool_call` | Inspects every string in the tool arguments. Depending on the rule's mode it redacts (`modify`), escalates to Hermes's approval prompt (`approve`), or blocks. |
| `transform_tool_result` | Rewrites JSON tool results string by string, keeping the JSON shape. Off for small cells by default (see below). |
| `transform_llm_output` | Rewrites the model's final reply, and appends a short note when values were withheld. |

Every callback catches its own errors, because Hermes blocks a `pre_tool_call` whose callback raises. What happens on an
internal error follows `fail_mode`: `open` lets the call through, `closed` blocks it. Messages shown to the model never contain
a raw flagged value.

When the guard asks for approval or blocks a shell command, the message ends with a one-line preview of the command, at most
120 characters, with credentials always masked (even if the secrets rule is set to `warn` or `off`):

```
[egress-guard] APPROVE: Command sends data via curl upload to 'upload.example.invalid', which is not in
allowed_hosts. (EG-NET-001) Command: curl -s -d 'report=quarterly' https://upload.example.invalid/drop
```

### The `/guard` command

- `/guard` or `/guard status`: the active policy file, preset, and each rule's mode, scopes and settings.
- `/guard report`: finding counts by rule and by action from the audit log, and the last 5 entries (masked values only,
  as stored). Reads at most the last 16 MB of the log.
- `/guard check <text>`: a dry run. Shows what each enabled rule would do with `<text>` as a tool argument or shell
  command, as a tool result and as a reply, with a masked preview. It writes no audit entry and changes nothing.

**Don't paste real secrets into `/guard check`.** Hermes saves everything you type at its prompt, slash commands included,
to its input history (`~/.hermes/.hermes_history`, or the profile's own). The guard's output is masked; that history file is not
the guard's to control. Test with made-up values.

### Rules and reason codes

| Rule | Code | Detects |
|---|---|---|
| secrets | `EG-SECRET-001` | AWS, GitHub, Slack, Stripe, Google, Anthropic and OpenAI-style keys, Hugging Face, npm, GitLab, SendGrid and Telegram tokens, JWTs, private key blocks, bearer tokens, passwords in URLs, database connection strings, and values assigned to credential-named variables |
| smallcell | `EG-CELL-001` | Counts from `min_value` up to `threshold - 1` in markdown tables and CSV/TSV blocks (including `read_file` and `cat -n` line-number prefixes), plus complementary cells and percentage/rate/share cells next to hidden counts |
| microdata | `EG-MICRO-001` | Record-level tables: an ID-like column (`id`, `record_id`, `uuid`, `case`, `person`, or any `..._id`) and more than `max_rows` rows |
| network | `EG-NET-001` | Shell commands that upload data to a destination not in `allowed_hosts` (see [What the network rule catches](#what-the-network-rule-catches)); in strict mode, any request to such a host |
| size cap | `EG-SIZE-001` | A string over `max_scan_bytes` that was not scanned (blocked only with `fail_mode: closed`) |

Hermes's own redaction markers in `read_file` output (`«redacted:AKIA…»` and similar) are recognised and left alone, so a value
Hermes already hid is not flagged a second time. Values Hermes leaves visible are still redacted by the guard.

### What the network rule catches

In shell commands (the `command` argument of a tool), uploads to destinations not in `allowed_hosts`:

| Command | Flagged when |
|---|---|
| `curl`, `wget` | sending data (`-d`, `-F`, `-T`, `--data*`, `--json`, `-X POST/PUT/PATCH`, `--post-*`, `--body-*`) |
| `nc`, `ncat`, `socat`, `scp`, `rsync`, `sftp` | connecting or copying to a remote host |
| `aws s3 cp`/`sync`, `gsutil cp`/`rsync`/`mv`, `rclone copy`/`sync`/`move` | local data copied to a bucket or remote |
| `gh gist create` | always (destination `gist.github.com`) |
| `git push` | the remote is a URL, or a name defined by `git remote add` earlier in the same command |
| `python -c`, `node -e` | the code calls `requests.post/put/patch`, `urllib`, `http.client` or `fetch` with a URL |

Cloud destinations are allowlisted by name: `s3://bucket`, `gs://bucket`, `rclone:remote`. Subdomains of an allowed host are
allowed too.

### Policies

Each rule has a mode (`off`, `warn`, `redact`, `approve`, `block`; the strictest finding wins) and the scopes it runs in:
`args` (before a tool runs), `result` (tool output before the model sees it) and `reply` (the final answer).

Built-in defaults (the bundled `egress-guard.yaml` sets nothing; it is a list of commented examples):

| Rule | Mode | Scopes |
|---|---|---|
| secrets | redact | args, result, reply |
| smallcell (threshold 5) | redact | args, reply |
| microdata (more than 20 rows) | warn (audit log only) | args, reply |
| network (uploads) | approve | args |

Small cells are **not** hidden from the model by default, only from outgoing arguments and the final reply. To also hide them
from tool results (this is what the demo above used), add `result`:

```yaml
rules:
  smallcell:
    scopes: [args, result, reply]
```

Policy lookup order: the file named by `EGRESS_GUARD_POLICY`, then `~/.hermes/egress-guard.yaml`, then the bundled default.
An invalid policy file falls back to built-in defaults, never to "off". Other options: `fail_mode`, an `allowlist` of regexes for
findings to ignore, `allowed_hosts`, `min_value` (set to 0 to flag zero cells) and `audit.enabled`.

#### Presets

Start from a named preset and change only what you need:

```yaml
preset: research-data
rules:
  network:
    allowed_hosts: [localhost, 127.0.0.1, "::1", data.internal]
```

| Preset | What it sets |
|---|---|
| `research-data` | small-cell threshold 10 on tool arguments, tool results and replies; uploads to non-allowlisted hosts blocked instead of sent for approval |
| `dev` | secrets protection only (small-cell, microdata and network rules off) |

Settings in your file always win over the preset, and nested settings merge, so the example above keeps the preset's
`mode: block` and only replaces `allowed_hosts`. An unknown preset name is rejected (the plugin falls back to the built-in
defaults and prints why).

#### Strict network mode

By default (`match: uploads`) the network rule flags commands that send data out. `match: any_host` also asks before any
request to a host not in `allowed_hosts`, plain downloads included, for `curl`, `wget`, httpie (`http`, `https`, `xh`),
`aria2c`, `ssh`, `telnet` and `ftp`. Use it when the agent should only talk to hosts you listed:

```yaml
rules:
  network:
    match: any_host
    allowed_hosts: [localhost, 127.0.0.1, "::1", pypi.org]
```

#### Percentages next to hidden counts

A hidden count is no use if its percentage is still shown: 30.0% of a visible total of 10 is 3. So when a count is suppressed,
the guard also hides percentage, rate and share cells in the same row (columns whose header contains `%`, `pct`, `percent`,
`rate` or `share`). A column named after a count column (`Referred %`, `Visit rate`) is hidden only where that count is hidden;
any other percentage column (`%`, `% of all`) is hidden in every row that has a hidden count.

#### Rounding instead of suppression

`smallcell.method: round` (default `suppress`) publishes every count instead of hiding some, randomly rounded to a multiple of 5:
a count of 3 becomes 5 with probability 3/5 and 0 otherwise, so rounding is unbiased on average. Totals are rounded on their
own, so they need not equal the sum of the rounded cells. The random draw is seeded by a hash of the table's contents: asking
for the same table again gives exactly the same rounded output, so repeated queries cannot be averaged to recover the true
values. Percentage cells are hidden in this mode, because they were computed from the unrounded counts.

```yaml
rules:
  smallcell:
    method: round
```

Limit: a table that differs in any cell (one extra row, say) gets a fresh draw, so someone who can request many slightly
different versions of a table can still average them.

#### Record-level tables (`microdata`)

A table with an ID-like column and more than `max_rows` rows (default 20) looks like one row per person or case. By default
the guard only notes this in the audit log (`mode: warn`), so you can see when an agent moves microdata around without anything
being blocked. Set `mode: redact` to withhold such tables (`[microdata table withheld: 800 rows]`), or `approve`/`block` to
confirm or stop tool calls that carry them.

#### Large inputs (`max_scan_bytes`)

Each string the guard inspects is scanned only if it is at most `max_scan_bytes` (default 1 MB, in UTF-8 bytes). Larger strings
are not parsed, and `fail_mode` decides: `open` lets them through and writes an audit entry, `closed` blocks them (`EG-SIZE-001`).
Smaller strings in the same call are still scanned. This keeps every hook well inside Hermes's 30-second limit for
`pre_tool_call`. With `fail_mode: open`, a secret inside a string larger than the cap is not redacted.

## Install

From the Hermes Marketplace, or manually:

1. Put this folder at `~/.hermes/plugins/egress-guard/`.
2. Add `egress-guard` to `plugins.enabled` in `~/.hermes/config.yaml`.
3. Check it with `hermes plugins doctor egress-guard` (it should report 3 hooks).

Requires Hermes Agent 0.22.2 or newer (the only version tested) and PyYAML.

## What this plugin does on your machine

Disclosures for catalog rule 13:

- **Network calls:** none. The plugin imports no networking modules. If PyYAML is not already present, Hermes's own dependency
  installer may fetch it from the package index when the plugin is installed.
- **Reads outside the plugin's own data:** the policy file (the path in `EGRESS_GUARD_POLICY`, or
  `~/.hermes/egress-guard.yaml`), and its own audit log when you run `/guard report`. It also inspects, in memory, every tool
  argument, tool result and final reply that passes through the three hooks. It keeps none of that content.
- **Writes:** appends one JSON line per inspected string that had findings to `~/.hermes/egress-guard/audit.jsonl` (path
  configurable, disable with `audit.enabled: false`). Each line holds a timestamp, direction, tool name, action, the number of
  findings per rule, and for at most 50 findings the rule, severity, reason and a masked preview (for example `AKIA…****` or `<5`),
  plus the first 12 characters of a SHA-256 hash of the inspected text. Lines are capped at 64 KB. Raw secrets and raw counts are
  never written. `/guard check` writes nothing.
- **Shell commands:** none are run. The network rule only parses command strings; it never executes them.
- **Background processes:** none.
- **Stored credentials:** none.
- **Telemetry:** none.
- **Approvals:** the plugin never approves anything. `approve` only hands the decision to Hermes's own approval prompt.

## Limitations

- **Heuristics, not certification.** Egress Guard flags and blocks by policy. It does not prove that data is safe to release, and
  it does not replace a disclosure review. The threshold of 5 is a default, not any agency's rule.
- **Small-cell scope:** markdown tables and delimited text blocks only. Not images, spreadsheet files, or tables nested in JSON.
  A CSV whose quoted fields contain the delimiter (`"1,232"`) is not recognised as a table.
  Complementary suppression is an iterative heuristic, not an optimal suppression pattern. A percentage column that sums to 100%
  could still let someone work out a single hidden percentage from the others. There are no dominance or quasi-identifier checks.
- **Microdata** is judged by column names and row count only: record-level data without an ID-like column is not recognised, and
  a long aggregate table whose first column is called `id` will be flagged.
- **Network rule:** it targets uploads with common tools. Not caught: `git push origin` (or any named remote set up earlier,
  because the guard cannot read your git config), scripts in files (`python upload.py`), heredocs, code run by a code-execution
  tool rather than a shell command, package managers, and anything obfuscated. Plain downloads are allowed unless you choose
  `match: any_host`. It is a seatbelt for an agent making a mistake, not a sandbox against a determined one.
- **Secrets:** pattern-based. There is deliberately no global "random-looking string" detector, because it would flag hashes and IDs.
- **Size cap:** with the default `fail_mode: open`, strings over `max_scan_bytes` pass unscanned (each one is logged).
- **Reply scope:** reply-level small-cell suppression is covered by unit and dispatch tests. In live runs, small cells were hidden at
  the result scope before the model could repeat them.

## Tested

- Hermes Agent v0.22.2, with a local `qwen2.5:7b` through Ollama, using synthetic data only.
- 187 unit tests, plus a 14-check harness through Hermes's real tool dispatch: `python -m pytest -q` from this folder.
  A GitHub Actions workflow (`.github/workflows/tests.yml`) runs them on Python 3.11, 3.12 and 3.13, with no secrets;
  they pass on Python 3.11, 3.12, 3.13 and 3.14.
- Against a small synthetic set of 29 secret formats (an illustration, not a benchmark): the guard caught 27, Hermes's built-in
  redactor 22, and the two together 27, with no false positives on 3 negative samples. The two tools complement each other.
- Overhead: about 0.05 ms for a command, about 0.2 ms for a small table, about 10 ms for the 800-row demo CSV (29 KB).
- Worst case: about 3 seconds per MB of input, measured on inputs just under the 1 MB scan cap built to be as slow as possible
  (for example a CSV with almost 400,000 small cells). Larger strings are not scanned (see `max_scan_bytes`).

## License

MIT, see [LICENSE](LICENSE).
