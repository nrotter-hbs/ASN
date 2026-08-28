#!/usr/bin/env python3
"""Build Sentinel-ready IPv4/IPv6 prefix attribution CSVs from public data."""

from __future__ import annotations

import bisect
import csv
import ipaddress
import json
import math
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)

BGP_TABLE = "https://bgp.tools/table.jsonl"
BGP_ASNS = "https://bgp.tools/asns.csv"
RIRS = {
    "ARIN": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "RIPE": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "APNIC": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "LACNIC": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "AFRINIC": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}


def get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ASN-data-pipeline/1.0"})
    with urllib.request.urlopen(req, timeout=180) as response:
        return response.read()


def load_bgp() -> list[dict]:
    routes = []
    for line in get(BGP_TABLE).decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        cidr = obj.get("CIDR", "")
        asn = obj.get("ASN", "")
        if not cidr or not asn:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        routes.append({
            "network": network,
            "prefix": str(network),
            "mask_length": network.prefixlen,
            "ip_version": network.version,
            "asn": f"AS{asn}",
            "hits": obj.get("Hits", ""),
        })
    return routes


def load_asns() -> dict[str, str]:
    raw = get(BGP_ASNS).decode("utf-8", errors="replace")
    result = {}
    for row in csv.DictReader(raw.splitlines()):
        asn = row.get("asn", "").strip()
        name = row.get("name", "").strip()
        if asn:
            result[asn if asn.startswith("AS") else f"AS{asn}"] = name
    return result


def load_rir_allocations() -> list[dict]:
    allocations = []
    for rir, url in RIRS.items():
        try:
            raw = get(url).decode("utf-8", errors="replace")
        except Exception as exc:
            print(f"WARNING: {rir}: {exc}")
            continue
        for line in raw.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 7 or parts[0] == "2" or parts[2] not in {"ipv4", "ipv6"}:
                continue
            try:
                start = ipaddress.ip_address(parts[3])
                value = int(parts[4])
                if parts[2] == "ipv6":
                    prefixlen = value
                    network = ipaddress.ip_network(f"{start}/{prefixlen}", strict=False)
                else:
                    end = start + value - 1
                    networks = list(ipaddress.summarize_address_range(start, end))
                    for network in networks:
                        allocations.append({
                            "network": network,
                            "rir": rir,
                            "country": parts[1],
                        })
                    continue
            except (ValueError, TypeError):
                continue
            allocations.append({"network": network, "rir": rir, "country": parts[1]})
    allocations.sort(key=lambda x: (x["network"].version, int(x["network"].network_address), x["network"].prefixlen))
    return allocations


def make_indexes(allocations: list[dict]):
    indexes = {}
    for version in (4, 6):
        rows = [x for x in allocations if x["network"].version == version]
        rows.sort(key=lambda x: int(x["network"].network_address))
        indexes[version] = (rows, [int(x["network"].network_address) for x in rows])
    return indexes


def find_rir(network: ipaddress._BaseNetwork, indexes):
    rows, starts = indexes[network.version]
    target = int(network.network_address)
    pos = bisect.bisect_right(starts, target) - 1
    # Walk backward through the small set of possible overlapping allocations.
    for i in range(pos, max(-1, pos - 64), -1):
        candidate = rows[i]
        if target in candidate["network"]:
            return candidate
    return {"rir": "", "country": ""}


def write_combined(routes, asns, rir_indexes, filename: str, ipv6_only: bool = False):
    path = DATA / filename
    fields = ["prefix", "network", "mask_length", "ip_version", "asn", "organization", "rir", "country", "hits", "source"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(fields)
        for route in routes:
            if ipv6_only and route["ip_version"] != 6:
                continue
            rir = find_rir(route["network"], rir_indexes)
            writer.writerow([
                route["prefix"],
                str(route["network"].network_address),
                route["mask_length"],
                route["ip_version"],
                route["asn"],
                asns.get(route["asn"], ""),
                rir["rir"],
                rir["country"],
                route["hits"],
                "BGP+RIR",
            ])
    print(f"Wrote {path}")


if __name__ == "__main__":
    routes = load_bgp()
    asns = load_asns()
    allocations = load_rir_allocations()
    indexes = make_indexes(allocations)
    write_combined(routes, asns, indexes, "ip_ownership.csv")
    write_combined(routes, asns, indexes, "ipv6_ownership.csv", ipv6_only=True)
