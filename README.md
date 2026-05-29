# IP Fabric Bulk Path Lookup

A small Python CLI that reads network flows from a CSV, runs a **unicast path lookup** for each one
against an [IP Fabric](https://ipfabric.io) instance, and writes the results back to a CSV with a
descriptive status and a human-readable comment.

IP Fabric's UI validates one flow at a time; this script does it in bulk via the API — handy for
checking a large set of flows (e.g. firewall/segmentation intent) in one pass.

## Features

- Reads flows from CSV (single IPs or subnets up to `/16`, TCP/UDP/ICMP, ports, NGFW applications).
- Descriptive per-flow status, not just pass/fail:
  - **REACHED** — all requested traffic reaches the destination
  - **PARTIAL** — some destination hosts/ports reach, others are denied
  - **BLOCKED** — a security policy denies the traffic; nothing reaches
  - **NO-PATH** — no route / unreachable (no security deny recorded)
  - **ERROR** — empty/unexpected response or a bad input row
- The comment leads with **what actually reaches the destination** (e.g. which hosts of a subnet got
  through), read from the path's terminal host nodes.
- Optional **intent validation**: add an `expected` column (`allow`/`block`) and each flow gets a
  `MATCH` / `MISMATCH` verdict — turning the run into a segmentation-policy report.

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
| `expected` | no | _(empty)_ | `allow` or `block` — adds a `MATCH` / `MISMATCH` verdict |

See [`flows_sample.csv`](flows_sample.csv) for an example.

## Output

The input columns are copied through, with `status`, `comment`, and (when `expected` is present)
`verdict` appended. Example run:

```text
[1/4] 172.16.12.60/24 → 172.16.23.20      tcp/3389 ... ⛔ BLOCKED  [MATCH]    Blocked [zone-deny]: d1xfw01 [fw] on ge-0/0/3.0 (ports: 3389)
[2/4] 172.16.12.60/24 → 172.16.23.20/24   tcp/3389 ... ◐ PARTIAL  [MISMATCH] Reached 172.16.23.21:3389; denied [zone-deny]: d1xfw01 [fw] ...
[3/4] 172.16.12.60/24 → 172.16.22.20      tcp/443  ... ✓ REACHED  [MATCH]    Reached 172.16.22.20:443
[4/4] 172.16.12.60/24 → 10.2.0.222        tcp/443  ... ✓ REACHED  [MATCH]    Reached 10.2.0.222:443

→ results.csv   REACHED: 2  PARTIAL: 1  BLOCKED: 1   |  checks → MATCH: 3  MISMATCH: 1
```

### Intent validation (`expected` → `verdict`)

A flow's intent is satisfied only by a *full* outcome (`PARTIAL` matches neither):

| `expected` | REACHED | PARTIAL | BLOCKED | NO-PATH |
| --- | --- | --- | --- | --- |
| `allow` | MATCH | MISMATCH | MISMATCH | MISMATCH |
| `block` | MISMATCH | MISMATCH | MATCH | MATCH |

The security-critical case is **expected `block` but `REACHED`/`PARTIAL`** — traffic you meant to deny
is getting through.

## Notes

- TLS verification is disabled (`verify=False`) for lab convenience — revisit for production use.
- Path lookup results are a **simulation**. Treat the output as draft validation evidence and have a
  network engineer review it before it feeds any audit or compliance deliverable.

## License

MIT
