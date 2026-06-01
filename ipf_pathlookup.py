#!/usr/bin/env python3
"""
IP Fabric Bulk Path Lookup
Reads flows from a CSV, runs unicast path lookup via the IP Fabric SDK,
and writes results with a descriptive status and details.

CSV columns (all optional except srcIP, dstIP):
  srcIP       - single IP or subnet up to /16 (e.g. 10.1.1.1, 192.168.0.0/16)
  dstIP       - single IP or subnet up to /16
  srcPort     - port or range, e.g. 1024-65535, 443   (default: 1024-65535)
  dstPort     - port or range or name, e.g. 443, https (default: 443)
  protocol    - tcp / udp / icmp                       (default: tcp)
  application - app name for NGFW, e.g. ssh, https     (default: empty)
  security    - drop / continue                        (default: drop)
  expected    - allow / block / assess: intended outcome; adds a verdict column
                (MATCH/MISMATCH, or ASSESS for assess = informational only)  (optional)
  comment     - free-text note copied straight through to the output (optional)

Any other column present in the input CSV is copied through unchanged. The script appends:
status, [verdict if 'expected' present], details.

Configuration (in priority order):
  1. CLI args:        --url / --token
  2. Environment:     IPF_URL / IPF_TOKEN
  3. .env file:       IPF_URL=... / IPF_TOKEN=... in a .env file next to this script

Usage:
  pip install ipfabric python-dotenv
  python ipf_pathlookup.py --input flows.csv [--output results.csv] [--snapshot $last]
"""

import argparse
import csv
import ipaddress
import os
import sys
import time
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Load .env (optional — silently skip if python-dotenv not installed)
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass  # python-dotenv not required, just convenient

# ---------------------------------------------------------------------------
# IP Fabric SDK (required — it builds the correct path-lookup payload and
# handles auth / base URL / snapshot context for this API version)
# ---------------------------------------------------------------------------
try:
    from ipfabric import IPFClient
    from ipfabric.diagrams import Unicast, OtherOptions
except ImportError:
    print("ERROR: the 'ipfabric' SDK is required.\n"
          "Run: pip install ipfabric python-dotenv")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_SRC_PORT = "1024-65535"
DEFAULT_DST_PORT = "443"
DEFAULT_PROTOCOL = "tcp"
DEFAULT_SECURITY = "drop"
RATE_LIMIT_DELAY = 0.2  # seconds between API calls
MIN_PREFIX_LEN   = 16   # largest subnet we allow (e.g. /16); smaller prefixes are too broad

# Result statuses (most-reachable first) and their console markers.
STATUSES = ("REACHED", "PARTIAL", "BLOCKED", "NO-PATH", "ERROR")
STATUS_MARKER = {
    "REACHED": "✓",
    "PARTIAL": "◐",
    "BLOCKED": "⛔",
    "NO-PATH": "✗",
    "ERROR":   "!",
}


def validate_endpoint(value: str, field: str) -> None:
    """Validate a srcIP/dstIP cell: a plain IP, or a subnet no larger than /MIN_PREFIX_LEN."""
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            if net.prefixlen < MIN_PREFIX_LEN:
                raise ValueError(
                    f"{field} subnet {value} is larger than /{MIN_PREFIX_LEN} "
                    f"(got /{net.prefixlen}) — narrow it to /{MIN_PREFIX_LEN} or smaller"
                )
        else:
            ipaddress.ip_address(value)
    except ValueError as e:
        # re-raise our own message as-is, wrap the stdlib parse errors
        raise ValueError(str(e) if field in str(e) else f"{field} is not a valid IP/subnet: {value!r}")


# ---------------------------------------------------------------------------
# CSV row -> SDK Unicast model
# ---------------------------------------------------------------------------

def build_unicast(row: dict) -> Unicast:
    """Build an ipfabric.diagrams.Unicast model from a CSV row.

    The SDK derives `networkMode` from the prefix length automatically and
    populates `startingPoint`/`destinationPoint`/`firstHopAlgorithm` as the
    API expects — we only map the user-facing CSV fields onto it.
    """
    src      = row.get("srcIP", "").strip()
    dst      = row.get("dstIP", "").strip()
    protocol = (row.get("protocol") or DEFAULT_PROTOCOL).strip().lower()
    src_port = (row.get("srcPort") or DEFAULT_SRC_PORT).strip()
    dst_port = (row.get("dstPort") or DEFAULT_DST_PORT).strip()
    app      = (row.get("application") or "").strip()
    security = (row.get("security") or DEFAULT_SECURITY).strip().lower()

    if not src or not dst:
        raise ValueError("srcIP and dstIP are required")
    if protocol not in ("tcp", "udp", "icmp"):
        raise ValueError(f"protocol must be tcp/udp/icmp, got: {protocol!r}")
    validate_endpoint(src, "srcIP")
    validate_endpoint(dst, "dstIP")

    kwargs: dict = {
        "startingPoint":    src,
        "destinationPoint": dst,
        "protocol":         protocol,
        "securedPath":      (security != "continue"),
    }

    # L4 ports apply to tcp/udp only — ICMP uses its own type/code defaults.
    if protocol != "icmp":
        kwargs["srcPorts"] = src_port
        kwargs["dstPorts"] = dst_port

    if app:
        kwargs["otherOptions"] = OtherOptions(applications=app)

    return Unicast(**kwargs)


# ---------------------------------------------------------------------------
# API call via the SDK diagram engine -> raw JSON
# ---------------------------------------------------------------------------

def run_pathlookup(client: IPFClient, unicast: Unicast, snapshot: str) -> dict:
    """POST the path lookup and return the raw graph JSON.

    Response shape:
      {
        "graphResult": {"graphData": {"nodes": {...}, "edges": {...}}, ...},
        "pathlookup":  {"passingTraffic": "all|some|none",
                        "eventsSummary": {"flags": [...], ...},
                        "check": {"exists": bool}, ...}
      }
    """
    return client.diagram.json(unicast, snapshot_id=snapshot)


# ---------------------------------------------------------------------------
# Result interpretation
# ---------------------------------------------------------------------------

# Firewall/ACL deny flags (vs routing flags like 'no-dgw') — distinguishes BLOCKED from NO-PATH.
SECURITY_FLAGS = {"zone-deny", "acl-deny", "policy-deny"}


def _fmt_ports(ports) -> str:
    return ", ".join(sorted({str(p) for p in (ports or [])}))


def _arriving_at_destination(graph: dict) -> list[str]:
    """What ACTUALLY reaches the destination.

    The destination shows up as terminal host 'cloud' node(s) — type 'cloud', id starts
    'host-', and never the source of an edge. The edge arriving at each one carries the
    delivered packet, so we report its IP[:ports]. For a subnet destination this lists only
    the hosts that got through (the basis of a PARTIAL result).
    """
    nodes, edges = graph.get("nodes", {}), graph.get("edges", {})
    sources = {e.get("source") for e in edges.values()}
    arrived = []
    for node in nodes.values():
        nid = str(node.get("id", ""))
        if node.get("type") != "cloud" or not nid.startswith("host-") or node.get("id") in sources:
            continue
        ip_dst, l4_dst = None, None
        for e in edges.values():
            if e.get("target") != node.get("id"):
                continue
            for pkt in e.get("packet", []):
                if pkt.get("type") == "ip":
                    ip_dst = pkt.get("dst")
                elif pkt.get("type") in ("tcp", "udp"):
                    l4_dst = pkt.get("dst")
        ip_str = ", ".join(ip_dst) if ip_dst else node.get("label", nid)
        ports  = _fmt_ports(l4_dst)
        arrived.append(f"{ip_str}:{ports}" if ports else ip_str)
    return arrived


def _collect_drops(nodes: dict) -> list[str]:
    """Summarise each device that dropped packets: 'label [type] on iface (ports: ...)'."""
    drops = []
    for node in nodes.values():
        dropped = node.get("droppedPackets", {})
        if not dropped:
            continue
        label  = node.get("label", node.get("id", "unknown"))
        ntype  = node.get("type", "")
        ifaces = sorted({d.get("ifaceName", "?") for d in dropped.values()})
        ports: set[str] = set()
        for dp in dropped.values():
            for pkt in dp.get("packet", []):
                if pkt.get("type") in ("tcp", "udp"):
                    ports |= {str(p) for p in pkt.get("dst", [])}
        port_info = f" (ports: {_fmt_ports(ports)})" if ports else ""
        drops.append(f"{label} [{ntype}] on {', '.join(ifaces)}{port_info}")
    return drops


def interpret_result(data: dict) -> tuple[str, str]:
    """Return (status, detail) from a path-lookup response.

    Status is driven by `pathlookup.passingTraffic` (all / part / none); the detail text
    leads with what actually reaches the destination.

      REACHED  all   - all requested traffic reaches the destination
      PARTIAL  part  - some destination hosts/ports reach, others are denied
      BLOCKED  none  - a security policy denies the traffic; nothing reaches
      NO-PATH  none  - no route / unreachable, with no security deny recorded
      ERROR          - empty/unexpected response
    """
    pathlookup = data.get("pathlookup", {})
    graph      = data.get("graphResult", {}).get("graphData", {})
    nodes      = graph.get("nodes", {})

    passing = pathlookup.get("passingTraffic")
    flags   = pathlookup.get("eventsSummary", {}).get("flags", []) or []

    if passing is None and not nodes:
        return "ERROR", "Empty response – no path data returned"

    arrived   = _arriving_at_destination(graph)
    drops      = _collect_drops(nodes)
    flag_info  = f" [{', '.join(flags)}]" if flags else ""

    if passing == "all":
        return "REACHED", "Reached " + ("; ".join(arrived) if arrived else "destination")

    if passing == "part":
        comment = "Reached " + ("; ".join(arrived) if arrived else "part of destination")
        comment += (f"; denied{flag_info}: " + "; ".join(drops)) if drops \
                   else f"; remainder not reached{flag_info}"
        return "PARTIAL", comment

    # passing == "none" (or unknown): nothing reaches the destination
    if drops or (set(flags) & SECURITY_FLAGS):
        detail = "; ".join(drops) if drops else "security policy"
        return "BLOCKED", f"Blocked{flag_info}: {detail}"
    return "NO-PATH", f"No path to destination{flag_info} – routing/reachability issue"


# ---------------------------------------------------------------------------
# Expected-result check (optional 'expected' CSV column -> MATCH / MISMATCH / ASSESS)
# ---------------------------------------------------------------------------

# Synonyms for the intent stated in the CSV's `expected` column.
EXPECTED_ALLOW  = {"allow", "allowed", "pass", "permit", "permitted", "reach", "reached", "yes", "ok"}
EXPECTED_BLOCK  = {"block", "blocked", "deny", "denied", "no"}
# 'assess' states no pass/fail intent — just surface the result for review (ASSESS).
EXPECTED_ASSESS = {"assess", "check", "info", "fyi", "review", "observe", "report"}

# A flow's intent is satisfied only when its full traffic reaches (allow) or fully
# fails to reach (block). PARTIAL satisfies neither — a partial leak or partial outage.
_ALLOW_OK = {"REACHED"}
_BLOCK_OK = {"BLOCKED", "NO-PATH"}


def evaluate_expectation(expected_raw: str, status: str) -> str:
    """Compare a stated intent against the actual status.

    Returns one of: '' (no intent stated), 'MATCH', 'MISMATCH', 'ASSESS' (assess-only, not
    scored), 'n/a' (status was ERROR, can't judge), '?' (unrecognised expected value).
    """
    exp = (expected_raw or "").strip().lower()
    if not exp:
        return ""
    if exp in EXPECTED_ASSESS:
        return "ASSESS"          # informational only — no pass/fail judgment
    if exp in EXPECTED_ALLOW:
        intent = "allow"
    elif exp in EXPECTED_BLOCK:
        intent = "block"
    else:
        return "?"
    if status == "ERROR":
        return "n/a"
    ok = (status in _ALLOW_OK) if intent == "allow" else (status in _BLOCK_OK)
    return "MATCH" if ok else "MISMATCH"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="IP Fabric bulk path lookup from CSV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="IPF_URL and IPF_TOKEN can also be set as env vars or in a .env file.",
    )
    parser.add_argument("--url",      default=os.getenv("IPF_URL"),
                        help="IP Fabric base URL (env: IPF_URL)")
    parser.add_argument("--token",    default=os.getenv("IPF_TOKEN"),
                        help="IP Fabric API token (env: IPF_TOKEN)")
    parser.add_argument("--input",    required=True, help="Input CSV file path")
    parser.add_argument("--output",   default="results.csv",
                        help="Output CSV file path (default: results.csv)")
    parser.add_argument("--snapshot", default="$last",
                        help="Snapshot ID or '$last' (default: $last)")
    parser.add_argument("--delay",    type=float, default=RATE_LIMIT_DELAY,
                        help=f"Seconds between API calls (default: {RATE_LIMIT_DELAY})")
    args = parser.parse_args()

    if not args.url:
        parser.error("IPF URL required: use --url or set IPF_URL env variable")
    if not args.token:
        parser.error("IPF token required: use --token or set IPF_TOKEN env variable")

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {args.input}")
        sys.exit(1)

    client = IPFClient(
        base_url=args.url,
        auth=args.token,
        snapshot_id=args.snapshot,
        verify=False,
        timeout=60,
    )
    print(f"Using ipfabric SDK  →  {args.url}  (snapshot: {args.snapshot})")

    # Read CSV
    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows   = list(reader)
    print(f"Loaded {len(rows)} flow(s) from {args.input}\n")

    out_fields   = list(rows[0].keys()) if rows else []
    has_expected = "expected" in out_fields  # optional intent column drives the verdict
    # Appended columns. Any input column (e.g. a free-text 'comment') is copied through as-is.
    new_fields   = ["status", "verdict", "details"] if has_expected else ["status", "details"]
    for field in new_fields:
        if field not in out_fields:
            out_fields.append(field)

    results = []
    for i, row in enumerate(rows, 1):
        label = (f"{row.get('srcIP','?')} → {row.get('dstIP','?')}  "
                 f"{row.get('protocol', DEFAULT_PROTOCOL)}/{row.get('dstPort', DEFAULT_DST_PORT)}")
        print(f"[{i}/{len(rows)}] {label} ...", end=" ", flush=True)

        out_row = dict(row)
        try:
            unicast        = build_unicast(row)
            data           = run_pathlookup(client, unicast, args.snapshot)
            status, detail = interpret_result(data)
        except Exception as e:
            status, detail = "ERROR", str(e)

        out_row["status"]  = status
        out_row["details"] = detail
        verdict = ""
        if has_expected:
            verdict = evaluate_expectation(row.get("expected"), status)
            out_row["verdict"] = verdict
        results.append(out_row)

        marker = STATUS_MARKER.get(status, "?")
        vtag   = f"[{verdict}] " if verdict else ""
        print(f"{marker} {status:<8} {vtag}{detail[:90]}{'…' if len(detail) > 90 else ''}")

        if i < len(rows):
            time.sleep(args.delay)

    # Write output
    output_path = Path(args.output)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=out_fields)
        writer.writeheader()
        writer.writerows(results)

    counts  = Counter(r["status"] for r in results)
    summary = "  ".join(f"{s}: {counts.get(s, 0)}" for s in STATUSES if counts.get(s, 0))
    line    = f"\n→ {args.output}   {summary or 'no results'}"
    if has_expected:
        vc = Counter(r.get("verdict", "") for r in results)
        checks = "  ".join(f"{v}: {vc[v]}" for v in ("MATCH", "MISMATCH", "ASSESS", "?", "n/a") if vc.get(v))
        line += f"   |  checks → {checks}" if checks else ""
    print(line)


if __name__ == "__main__":
    main()
