# IP Fabric Bulk Path Lookup — Project Context

## What we're building

A Python CLI script (`ipf_pathlookup.py`) that reads a list of network flows from a CSV file, runs a unicast path lookup for each flow against an IP Fabric instance via its API, and writes the results back to a CSV with a descriptive status (**REACHED / PARTIAL / BLOCKED / NO-PATH**) and a human-readable `details` column explaining the outcome.

The end user is a network engineer at an IP Fabric customer/prospect. They want to validate a large number of flows programmatically — something the IP Fabric UI supports one flow at a time, but the API supports in bulk.

---

## IP Fabric background

[IP Fabric](https://ipfabric.io) is a network assurance platform. It discovers and models the entire network, then allows simulating traffic paths ("path lookup") to verify reachability and security policy outcomes.

The **path lookup** simulates a packet traversal through the network and returns:

- The list of nodes (devices) and edges (links) the packet traverses
- Which devices dropped packets and on which interfaces/ports
- Whether the destination was reached (and how much of the simulated traffic passes)

The path lookup is one kind of **diagram**. The graph is computed by:

```text
POST /api/v1/graphs
```

> ⚠️ There is **no** `POST /api/v1/graphs/path-lookup` endpoint — calling it returns HTTP 404. The
> `/graphs/path-lookup/*` paths are GET-only helpers (advanced-options, vrfs). An earlier version of
> this script POSTed to `graphs/path-lookup`, which silently 404'd and produced empty results.

We talk to this endpoint **through the SDK's diagram engine** rather than hand-building the payload:

```python
from ipfabric import IPFClient
from ipfabric.diagrams import Unicast, OtherOptions

client = IPFClient(base_url=..., auth=..., snapshot_id="$last", verify=False)
u = Unicast(startingPoint="172.16.12.60/24", destinationPoint="172.16.22.20",
            protocol="tcp", srcPorts="1024-65535", dstPorts="443", securedPath=True)
raw = client.diagram.json(u, snapshot_id="$last")   # -> dict (graphResult + pathlookup)
```

The `Unicast` model builds the correct payload for the running API version, including the fields a
raw request is easy to get wrong (`startingPoint`/`destinationPoint`, `firstHopAlgorithm`,
`networkMode`). Tested against **ipfabric SDK 7.11.2** / IP Fabric 7.x.

---

## Input CSV format

File: `flows_sample.csv`

| Column | Required | Default | Notes |
| --- | --- | --- | --- |
| `srcIP` | yes | — | Single IP (`10.0.0.1`) or subnet up to /16 (`10.0.0.0/16`) |
| `dstIP` | yes | — | Same as srcIP |
| `srcPort` | no | `1024-65535` | Integer, range (`1024-65535`), or list |
| `dstPort` | no | `443` | Integer, range, or name (`https`) |
| `protocol` | no | `tcp` | `tcp`, `udp`, or `icmp` |
| `application` | no | _(empty)_ | App name for NGFW validation, e.g. `ssh`, `https`, `rdp` |
| `security` | no | `drop` | `drop` = stop at security denies; `continue` = simulate past them |
| `expected` | no | _(empty)_ | Intended outcome: `allow` / `block` / `assess` (synonyms accepted). Drives the `verdict` column |
| `comment` | no | _(empty)_ | Free-text note, copied straight through to the output (e.g. app name / purpose) |

Any other column present in the input is copied through to the output unchanged. The script
appends `status`, `verdict` (when `expected` is present), and `details`.

**How CSV columns map onto the `Unicast` model:**

- `srcIP` → `startingPoint`, `dstIP` → `destinationPoint`.
- **`networkMode` is derived automatically by the SDK** from the prefix length — a `/24` source is
  expanded to the whole subnet, a single host becomes `/32`. We do **not** set it manually.
- If `protocol` is `icmp`, no L4 ports are sent (the model carries its own `icmp` type/code).
- `security: drop` → `securedPath=True`; `continue` → `securedPath=False`.
- `application` → `otherOptions=OtherOptions(applications=<app>)`.

---

## API request payload (what the SDK sends)

The `Unicast` model serialises to roughly this `parameters` block (the SDK wraps it as
`{"parameters": {...}, "snapshot": "..."}` and POSTs to `/api/v1/graphs`):

```json
{
  "type": "pathLookup",
  "pathLookupType": "unicast",
  "protocol": "tcp",
  "startingPoint": "172.16.12.0/24",
  "destinationPoint": "172.16.22.20/32",
  "securedPath": true,
  "networkMode": true,
  "groupBy": "siteName",
  "ttl": 128,
  "fragmentOffset": 0,
  "enableRegions": false,
  "srcRegions": ".*",
  "dstRegions": ".*",
  "l4Options": { "srcPorts": "1024-65535", "dstPorts": "443", "flags": [] },
  "otherOptions": { "applications": ".*", "tracked": false, "category": "", "url": "" },
  "firstHopAlgorithm": { "type": "automatic" }
}
```

> Note: the field names are **`startingPoint`/`destinationPoint`**, not `src`/`dst`. Sending
> `src`/`dst` returns HTTP 422 `API_VALIDATION_FAILED` ("parameters does not match any of the
> allowed types"). `firstHopAlgorithm` is required.

`snapshot` can be `"$last"` or a specific UUID.

---

## API response structure (what matters)

`client.diagram.json(u)` returns a dict with two top-level keys:

```jsonc
{
  "graphResult": {
    "graphData": { "nodes": { ... }, "edges": { ... } },   // the drawn graph
    "settings":  { ... }
  },
  "pathlookup": {
    "passingTraffic": "all",                 // "all" | "part" | "none"  <- authoritative verdict
    "eventsSummary": { "flags": [], ... },   // e.g. ["zone-deny"], ["no-dgw"]
    "decisions": { ... },
    "check": { "exists": false }             // saved path-verification match; NOT "dest reached"
  }
}
```

**`pathlookup.passingTraffic` is the authoritative reachability signal** — `all` (delivered
end-to-end), `part` (some of the simulated traffic delivered — e.g. some hosts in a destination
subnet reach, others are denied), `none` (nothing reaches the dest). Do **not** infer reachability
from node/edge counts: a blocked flow still returns a (short) graph.

**`pathlookup.eventsSummary.flags`** explains _why_ — observed values include `zone-deny`
(firewall zone policy), `no-dgw` (no default gateway / unknown subnet on this snapshot). A security
flag (`zone-deny`/`acl-deny`/…) distinguishes a deliberate **block** from a **no-route**.

**What actually reaches the destination** is read from the terminal host `cloud` nodes (type
`cloud`, id starts `host-`, never the source of an edge). The edge arriving at each one carries the
delivered packet (`ip.dst`, `tcp/udp.dst`), so we report `IP:ports` — and for a subnet destination
this lists only the hosts that got through.

**Nodes** (`graphResult.graphData.nodes`) are devices. A node with `droppedPackets` shows where and
on which interface/ports traffic was dropped — used to enrich the `details` text:

```json
"2483": {
  "label": "d1xfw01",
  "type": "fw",
  "droppedPackets": {
    "2483@ge-0/0/3.0--dropped--#0": {
      "ifaceName": "ge-0/0/3.0",
      "packet": [
        {"type": "ip",  "src": ["172.16.12.0 .. 172.16.12.255"], "dst": ["172.16.22.20"]},
        {"type": "tcp", "dst": ["3389"], "src": ["1024 .. 65535"], "flags": []}
      ]
    }
  }
}
```

---

## Status taxonomy

A descriptive status (not a binary OK/NOK) is derived from `passingTraffic`, with `flags`,
`droppedPackets`, and the arriving-packet details shaping the `details` text, which always **leads
with what reaches the destination**.

| `passingTraffic` | Status | Marker | Details |
| --- | --- | --- | --- |
| `all` | **REACHED** | ✓ | "Reached \<ip:ports\>" |
| `part` | **PARTIAL** | ◐ | "Reached \<ip:ports\>; denied [\<flags\>]: \<device\> [\<type\>] on \<iface\> (ports: …)" |
| `none` + security flag / drops | **BLOCKED** | ⛔ | "Blocked [\<flags\>]: \<device\> [\<type\>] on \<iface\> (ports: …)" |
| `none`, no security flag/drops | **NO-PATH** | ✗ | "No path to destination – routing/reachability issue" |
| (empty / unexpected response) | **ERROR** | ! | "Empty response …" / exception text |

Why descriptive rather than OK/NOK: a firewall **deny** is frequently the _expected, correct_
outcome, so it must be distinguishable from a genuine no-route fault — and a subnet destination
is rarely all-or-nothing. `BLOCKED` vs `NO-PATH` is decided by whether a security deny was recorded
(`droppedPackets` present, or a flag in `SECURITY_FLAGS = {zone-deny, acl-deny, policy-deny}`).

**Verified results (lab/demo instance, `flows_sample.csv`):**

- `172.16.12.60/24 → 172.16.23.20:3389`     → **BLOCKED** `[zone-deny]`, d1xfw01 [fw] on ge-0/0/3.0 (3389)
- `172.16.12.60/24 → 172.16.23.20/24:3389`  → **PARTIAL** — only `172.16.23.21:3389` reaches; rest zone-denied
- `172.16.12.60/24 → 172.16.22.20:443`       → **REACHED** `172.16.22.20:443`
- `172.16.12.60/24 → 10.2.0.222:443`         → **REACHED** `10.2.0.222:443`

---

## Expected-result check (intent validation)

If the input CSV has an **`expected`** column, each flow gets a **`verdict`** column comparing intent
to reality. This turns the run into a validation report: a firewall deny is only a problem when it
wasn't intended, and a partial leak on a flow you expected blocked is surfaced as a `MISMATCH`.

`expected` accepts (case-insensitive):

- **allow** — `allow`, `allowed`, `pass`, `permit`, `permitted`, `reach`, `reached`, `yes`, `ok`
- **block** — `block`, `blocked`, `deny`, `denied`, `no`
- **assess** — `assess`, `check`, `info`, `fyi`, `review`, `observe`, `report`

Verdict logic — a flow's intent is satisfied only by a _full_ outcome (`PARTIAL` satisfies neither).
`assess` asserts nothing — it just surfaces the result for review and is never scored:

| `expected` | REACHED | PARTIAL | BLOCKED | NO-PATH | ERROR |
| --- | --- | --- | --- | --- | --- |
| allow | MATCH | MISMATCH | MISMATCH | MISMATCH | n/a |
| block | MISMATCH | MISMATCH | MATCH | MATCH | n/a |
| assess | ASSESS | ASSESS | ASSESS | ASSESS | ASSESS |

`verdict` is empty when no intent is stated, and `?` when the `expected` value is unrecognised.
The end-of-run summary tallies the checks, e.g. `checks → MATCH: 3  MISMATCH: 1  ASSESS: 1`.

> The security-critical case is **expected `block` → actual `REACHED`/`PARTIAL`** (`MISMATCH`):
> traffic you intended to deny is getting through. In `flows_sample.csv`, RDP to `172.16.23.20/24`
> is expected `block` but `172.16.23.21:3389` reaches → flagged `MISMATCH`.

---

## Configuration

The script reads connection details in this priority order:

1. CLI args: `--url`, `--token`
2. Environment variables: `IPF_URL`, `IPF_TOKEN`
3. `.env` file in the same directory as the script (see `.env.example`)

> ⚠️ **Env precedence gotcha:** `python-dotenv` does **not** override variables already exported in
> the shell. If `IPF_URL`/`IPF_TOKEN` are set in your shell (e.g. left in `~/.zshrc`), they win over
> `.env` and the script silently queries the _wrong_ instance (symptom: every flow comes back
> `no-dgw`). Either `unset IPF_URL IPF_TOKEN` or pass `--url/--token` explicitly.

---

## Current script structure (`ipf_pathlookup.py`)

```text
load_dotenv()                       # reads .env if present (does not override shell env)
IPFClient                           # SDK required (no raw-requests fallback)
build_unicast(row)                  # CSV row -> ipfabric.diagrams.Unicast model
run_pathlookup(client, u, snap)     # client.diagram.json(u, snapshot_id=snap) -> raw dict
interpret_result(data)              # passingTraffic + flags + droppedPackets -> (status, detail)
main()                              # CLI arg parsing, CSV loop, output writing
```

---

## Known issues / things to fix

- No handling yet for rate limiting (HTTP 429) — currently just a fixed `--delay` between calls.
- Output file path defaults to `results.csv` in the current working directory, not next to the input file — may be confusing.
- The resolved instance URL is printed, but **not** which source it came from (CLI/env/.env) — adding that would make the env-precedence gotcha above visible at a glance.
- `verify=False` disables TLS verification (lab convenience). Revisit before any non-lab use.

---

## Dependencies

```text
ipfabric        # IP Fabric Python SDK (required) — tested with 7.11.2
python-dotenv   # for .env file support (optional but recommended)
```

Install: `pip install ipfabric python-dotenv`
