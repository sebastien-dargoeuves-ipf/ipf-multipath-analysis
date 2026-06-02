# IP Fabric Path Lookup Automation

A small set of Python CLIs for automating [IP Fabric](https://ipfabric.io) path lookup workflows
from CSV input.

The repo currently has two related scripts:

- `ipf_pathlookup.py` runs a **unicast path lookup** for each CSV row and writes descriptive
  results such as `REACHED`, `PARTIAL`, `BLOCKED`, and `NO-PATH`.
- `ipf_create_path_checks.py` creates saved **Path verification** checks in IP Fabric from the same
  CSV shape, with duplicate pre-checking via the API.

IP Fabric's UI handles these flows one at a time; these scripts do it in bulk.

## Features

- Reads flows from CSV (single IPs or subnets up to `/16`, TCP/UDP/ICMP, ports, NGFW applications).
- Bulk path simulation with descriptive per-flow status:
  - **REACHED** — all requested traffic reaches the destination
  - **PARTIAL** — some destination hosts/ports reach, others are denied
  - **BLOCKED** — a security policy denies the traffic; nothing reaches
  - **NO-PATH** — no route / unreachable (no security deny recorded)
  - **ERROR** — empty/unexpected response or a bad input row
- Bulk saved-check creation using the same CSV input.
- Duplicate detection before create via `POST /api/graphs/path-lookup/checks/exists`.
- The path lookup `details` column leads with **what actually reaches the destination** (e.g. which
  hosts of a subnet got through), read from the path's terminal host nodes.
- Optional **intent validation**: add an `expected` column (`allow`/`block`/`assess`) and each flow
  either gets a `MATCH` / `MISMATCH` / `ASSESS` verdict (`ipf_pathlookup.py`) or maps to saved-check
  `expectedPassingTraffic` (`ipf_create_path_checks.py`).

## Requirements

- Python 3.10+
- [`ipfabric`](https://pypi.org/project/ipfabric/) SDK (tested with 7.11.x; works with IP Fabric 7.x)
- `python-dotenv` (optional, for `.env` support)

```bash
pip install -r requirements.txt
```

## Configuration

Connection details are read in this priority order (highest first):

1. CLI args: `--url`, `--token`
2. Environment variables: `IPF_URL`, `IPF_TOKEN`
3. `.env` file in the script directory (copy `.env.example` → `.env`)

```bash
cp .env.example .env
# then edit .env:
#   IPF_URL=https://your-ipfabric-instance
#   IPF_TOKEN=your-api-token
```

> **Note:** `.env` is **not** loaded over variables already set in your shell. If `IPF_URL` /
> `IPF_TOKEN` are exported in your shell, they win over `.env` (every flow returning `NO-PATH` /
> `no-dgw` is the usual symptom of pointing at the wrong instance). `unset` them or pass `--url` /
> `--token` explicitly.

## Usage

### Run bulk path lookups

```bash
python ipf_pathlookup.py --input flows.csv [--output results.csv] [--snapshot $last] [--delay 0.2]
```

| Option | Default | Description |
| --- | --- | --- |
| `--input` | _(required)_ | Input CSV path |
| `--output` | `results.csv` | Output CSV path |
| `--snapshot` | `$last` | Snapshot ID or `$last` |
| `--delay` | `0.2` | Seconds between API calls |
| `--url` / `--token` | env / `.env` | IP Fabric URL and API token |

### Create saved path checks

```bash
python ipf_create_path_checks.py --input flows.csv [--output path_checks_results.csv] [--snapshot $last] [--delay 0.2]
```

| Option | Default | Description |
| --- | --- | --- |
| `--input` | _(required)_ | Input CSV path |
| `--output` | `path_checks_results.csv` | Output CSV path |
| `--snapshot` | `$last` | Snapshot ID for SDK context |
| `--delay` | `0.2` | Seconds between API calls |
| `--limit` | `0` | Only process the first `N` rows |
| `--force-create` | `false` | Create even if the same parameters already exist |
| `--url` / `--token` | env / `.env` | IP Fabric URL and API token |

## Input CSV format

| Column | Required | Default | Notes |
| --- | --- | --- | --- |
| `srcIP` | yes | — | Single IP (`10.0.0.1`) or subnet up to `/16` (`10.0.0.0/16`) |
| `dstIP` | yes | — | Same as `srcIP` |
| `srcPort` | no | `1024-65535` | Integer, range, or list |
| `dstPort` | no | `443` | Integer, range, or name (`https`) |
| `protocol` | no | `tcp` | `tcp`, `udp`, or `icmp` |
| `application` | no | _(empty)_ | NGFW app name, e.g. `ssh`, `https`, `rdp` |
| `security` | no | `drop` | `drop` = stop at security denies; `continue` = simulate past them |
| `expected` | no | _(empty)_ | `allow` / `block` / `assess` for lookup verdicts; maps to `all` / `none` / `part` for saved checks |
| `comment` | no | _(empty)_ | Free-text note, copied straight through to the output |

Any other column you add is copied through unchanged too. See
[`flows_sample.csv`](flows_sample.csv) for an example.

## Outputs

### `ipf_pathlookup.py`

The input columns (including your free-text `comment`) are copied through, with `status`,
`details`, and — when `expected` is present — `verdict` appended. Example run:

```text
[1/4] 172.16.12.60/24 → 172.16.23.20      tcp/3389 ... ⛔ BLOCKED  [MATCH]    Blocked [zone-deny]: d1xfw01 [fw] on ge-0/0/3.0 (ports: 3389)
[2/4] 172.16.12.60/24 → 172.16.23.20/24   tcp/3389 ... ◐ PARTIAL  [MISMATCH] Reached 172.16.23.21:3389; denied [zone-deny]: d1xfw01 [fw] ...
[3/4] 172.16.12.60/24 → 172.16.22.20      tcp/443  ... ✓ REACHED  [MATCH]    Reached 172.16.22.20:443
[4/4] 172.16.12.60/24 → 10.2.0.222        tcp/443  ... ✓ REACHED  [MATCH]    Reached 10.2.0.222:443

→ results.csv   REACHED: 2  PARTIAL: 1  BLOCKED: 1   |  checks → MATCH: 3  MISMATCH: 1
```

A full example output (from [`flows_sample.csv`](flows_sample.csv)) is committed as
[`results_sample.csv`](results_sample.csv). Your own runs default to `results.csv`, which is
git-ignored so scratch/real output isn't accidentally committed.

### `ipf_create_path_checks.py`

The input columns are copied through, with these extra fields appended:

- `create_status` — `CREATED`, `SKIPPED`, or `ERROR`
- `exists` — whether the check already existed before create
- `check_id` — the saved path-check ID returned by IP Fabric
- `job_id` — the async job ID returned by IP Fabric
- `expectedPassingTraffic` — the value sent to IP Fabric
- `details` — a short create/skip/error message

Typical one-row output:

```text
[1/1] 53.32.28.0/24 -> 53.32.101.82 icmp [VDS] ... CREATED id=8 job=390
```

On rerun, the duplicate pre-check skips creation by default:

```text
[1/1] 53.32.28.0/24 -> 53.32.101.82 icmp [VDS] ... SKIPPED existing
```

### Intent handling (`expected`)

`expected` accepts `allow` / `block` / `assess` (synonyms accepted, e.g. `deny`, `permit`,
`check`/`fyi`/`review` for assess). A flow's intent is satisfied only by a _full_ outcome
(`PARTIAL` matches neither); `assess` makes no assertion and is never scored:

| `expected` | REACHED | PARTIAL | BLOCKED | NO-PATH |
| --- | --- | --- | --- | --- |
| `allow` | MATCH | MISMATCH | MISMATCH | MISMATCH |
| `block` | MISMATCH | MISMATCH | MATCH | MATCH |
| `assess` | ASSESS | ASSESS | ASSESS | ASSESS |

Use `assess` when you just want to **observe** a flow's outcome without a pass/fail judgment — it
surfaces the `status`/`details` but stays out of the MATCH/MISMATCH tally (`ASSESS`).

The security-critical case is **expected `block` but `REACHED`/`PARTIAL`** — traffic you meant to deny
is getting through.

For `ipf_create_path_checks.py`, `expected` is interpreted as the saved-check target:

- `allow` and its synonyms map to `expectedPassingTraffic=all`
- `block` and its synonyms map to `expectedPassingTraffic=none`
- `part` / `partial` / `some` map to `expectedPassingTraffic=part`
- `assess` is not valid for saved-check creation, because IP Fabric requires an explicit expected result

## Notes

- TLS verification is disabled (`verify=False`) for lab convenience — revisit for production use.
- Path lookup results are a **simulation**. Treat the output as draft validation evidence and have a
  network engineer review it before it feeds any audit or compliance deliverable.
- The saved-check create workflow uses the SDK to build the `parameters` payload, then posts to
  `graphs/path-lookup/checks` and `graphs/path-lookup/checks/exists`.

## License

MIT
