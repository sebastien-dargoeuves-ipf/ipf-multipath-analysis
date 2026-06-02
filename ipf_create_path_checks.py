#!/usr/bin/env python3
"""
Bulk-create IP Fabric saved path checks from a CSV file.

This script is separate from `ipf_pathlookup.py`:
  - `ipf_pathlookup.py` runs ad hoc path simulations and writes results.
  - `ipf_create_path_checks.py` creates saved "Path verification" checks in IP Fabric.

It uses the IP Fabric SDK to:
  1. build the correct path-lookup parameters via `ipfabric.diagrams.Unicast`
  2. call the saved-check API endpoints:
     - POST `graphs/path-lookup/checks/exists`
     - POST `graphs/path-lookup/checks`

Input CSV columns:
  srcIP       required
  dstIP       required
  srcPort     optional, default 1024-65535
  dstPort     optional, default 443
  protocol    optional, default tcp
  application optional
  security    optional, default drop
  expected    optional, mapped to expectedPassingTraffic
  comment     optional, copied to the output CSV only
"""

import argparse
import csv
import ipaddress
import os
import sys
import time
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).parent / ".env", override=True)
except ImportError:
    pass

try:
    from ipfabric import IPFClient
    from ipfabric.diagrams import OtherOptions, Unicast
except ImportError:
    print("ERROR: the 'ipfabric' SDK is required.\nRun: pip install ipfabric python-dotenv")
    sys.exit(1)


DEFAULT_SRC_PORT = "1024-65535"
DEFAULT_DST_PORT = "443"
DEFAULT_PROTOCOL = "tcp"
DEFAULT_SECURITY = "drop"
DEFAULT_DELAY = 0.2
MIN_PREFIX_LEN = 16

EXPECTED_ALL = {"allow", "allowed", "pass", "permit", "permitted", "reach", "reached", "yes", "ok", "all"}
EXPECTED_NONE = {"block", "blocked", "deny", "denied", "no", "none"}
EXPECTED_PART = {"part", "partial", "some"}


def validate_endpoint(value: str, field: str) -> None:
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            if net.prefixlen < MIN_PREFIX_LEN:
                raise ValueError(
                    f"{field} subnet {value} is larger than /{MIN_PREFIX_LEN} "
                    f"(got /{net.prefixlen})"
                )
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(str(exc) if field in str(exc) else f"{field} is not a valid IP/subnet: {value!r}")


def expected_passing_traffic(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw or raw in EXPECTED_ALL:
        return "all"
    if raw in EXPECTED_NONE:
        return "none"
    if raw in EXPECTED_PART:
        return "part"
    raise ValueError(
        "expected must map to one of: all / part / none "
        f"(got {value!r})"
    )


def build_unicast(row: dict) -> Unicast:
    src = (row.get("srcIP") or "").strip()
    dst = (row.get("dstIP") or "").strip()
    protocol = (row.get("protocol") or DEFAULT_PROTOCOL).strip().lower()
    src_port = (row.get("srcPort") or DEFAULT_SRC_PORT).strip()
    dst_port = (row.get("dstPort") or DEFAULT_DST_PORT).strip()
    app = (row.get("application") or "").strip()
    security = (row.get("security") or DEFAULT_SECURITY).strip().lower()

    if not src or not dst:
        raise ValueError("srcIP and dstIP are required")
    if protocol not in ("tcp", "udp", "icmp"):
        raise ValueError(f"protocol must be tcp/udp/icmp, got: {protocol!r}")

    validate_endpoint(src, "srcIP")
    validate_endpoint(dst, "dstIP")

    kwargs = {
        "startingPoint": src,
        "destinationPoint": dst,
        "protocol": protocol,
        "securedPath": security != "continue",
    }

    if protocol != "icmp":
        kwargs["srcPorts"] = src_port
        kwargs["dstPorts"] = dst_port

    if app:
        kwargs["otherOptions"] = OtherOptions(applications=app)
    elif protocol == "icmp":
        kwargs["otherOptions"] = OtherOptions(applications="(icmp|ping)")

    return Unicast(**kwargs)


def build_check_payload(row: dict) -> dict:
    unicast = build_unicast(row)
    return {
        "expectedPassingTraffic": expected_passing_traffic(row.get("expected")),
        "parameters": unicast.model_dump(by_alias=True, exclude_none=True),
    }


def path_label(row: dict) -> str:
    protocol = (row.get("protocol") or DEFAULT_PROTOCOL).strip().lower()
    comment = (row.get("comment") or "").strip()
    suffix = f" [{comment}]" if comment else ""
    if protocol == "icmp":
        service = "icmp"
    else:
        service = f"{protocol}/{(row.get('dstPort') or DEFAULT_DST_PORT).strip()}"
    return f"{row.get('srcIP', '?')} -> {row.get('dstIP', '?')} {service}{suffix}"


def parse_json_response(response):
    try:
        return response.json()
    except Exception:
        return {}


def check_exists(client: IPFClient, payload: dict) -> dict:
    response = client.post("graphs/path-lookup/checks/exists", json={"parameters": payload["parameters"]})
    data = parse_json_response(response)
    if response.status_code >= 400:
        raise RuntimeError(data.get("message") or response.text)
    return data


def create_check(client: IPFClient, payload: dict) -> dict:
    response = client.post("graphs/path-lookup/checks", json=payload)
    data = parse_json_response(response)
    if response.status_code >= 400:
        raise RuntimeError(data.get("message") or response.text)
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="Create saved IP Fabric path checks from a CSV")
    parser.add_argument("--input", required=True, help="Input CSV file path")
    parser.add_argument("--output", default="path_checks_results.csv", help="Output CSV file path")
    parser.add_argument("--url", default=os.getenv("IPF_URL"), help="IP Fabric base URL (env: IPF_URL)")
    parser.add_argument("--token", default=os.getenv("IPF_TOKEN"), help="IP Fabric API token (env: IPF_TOKEN)")
    parser.add_argument("--snapshot", default="$last", help="Snapshot ID for SDK context (default: $last)")
    parser.add_argument("--limit", type=int, default=0, help="Only process the first N rows")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Seconds between API calls")
    parser.add_argument(
        "--force-create",
        action="store_true",
        help="Create even if the same parameters already exist",
    )
    args = parser.parse_args()

    if not args.url:
        parser.error("IPF URL required: use --url or set IPF_URL")
    if not args.token:
        parser.error("IPF token required: use --token or set IPF_TOKEN")

    input_path = Path(args.input)
    if not input_path.exists():
        parser.error(f"Input file not found: {args.input}")

    with open(input_path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    if args.limit > 0:
        rows = rows[: args.limit]

    if not rows:
        print("No rows to process.")
        return

    client = IPFClient(
        base_url=args.url,
        auth=args.token,
        snapshot_id=args.snapshot,
        verify=False,
        timeout=60,
    )

    print(f"Using ipfabric SDK -> {args.url} (snapshot: {args.snapshot})")
    print(f"Loaded {len(rows)} row(s) from {args.input}\n")

    output_fields = list(rows[0].keys())
    for field in ("create_status", "exists", "check_id", "job_id", "expectedPassingTraffic", "details"):
        if field not in output_fields:
            output_fields.append(field)

    results = []
    for index, row in enumerate(rows, start=1):
        out_row = dict(row)
        label = path_label(row)
        print(f"[{index}/{len(rows)}] {label} ...", end=" ", flush=True)
        try:
            payload = build_check_payload(row)
            out_row["expectedPassingTraffic"] = payload["expectedPassingTraffic"]

            exists_data = check_exists(client, payload)
            exists = bool(exists_data.get("exists"))
            out_row["exists"] = str(exists).lower()

            if exists and not args.force_create:
                out_row["create_status"] = "SKIPPED"
                out_row["details"] = "Matching path check already exists"
                out_row["check_id"] = ""
                out_row["job_id"] = ""
                print("SKIPPED existing")
            else:
                created = create_check(client, payload)
                out_row["create_status"] = "CREATED"
                out_row["check_id"] = created.get("id", "")
                out_row["job_id"] = created.get("jobId", "")
                out_row["details"] = "Created saved path check"
                print(f"CREATED id={out_row['check_id']} job={out_row['job_id']}")
        except Exception as exc:
            out_row["create_status"] = "ERROR"
            out_row["details"] = str(exc)
            out_row["exists"] = out_row.get("exists", "")
            out_row["check_id"] = ""
            out_row["job_id"] = ""
            out_row["expectedPassingTraffic"] = out_row.get("expectedPassingTraffic", "")
            print(f"ERROR {exc}")

        results.append(out_row)
        if index < len(rows):
            time.sleep(args.delay)

    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=output_fields)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n-> {args.output}")


if __name__ == "__main__":
    main()
