#!/usr/bin/env python3
"""Build Sentinel-ready IPv4/IPv6 prefix attribution CSVs from public data."""
from __future__ import annotations
import bisect
import csv
import ipaddress
import json
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DATA.mkdir(parents=True, exist_ok=True)
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

def load_bgp():
    routes = []
    for line in get(BGP_TABLE).decode("utf-8", errors="replace").splitlines():
        if not line.strip(): continue
        try:
            obj = json.loads(line)
            cidr, asn = obj.get("CIDR", ""), obj.get("ASN", "")
            if not cidr or not asn: continue
            network = ipaddress.ip_network(cidr, strict=False)
            routes.append({"network": network, "prefix": str(network), "mask_length": network.prefixlen, "ip_version": network.version, "asn": f"AS{asn}", "hits": obj.get("Hits", "")})
        except (ValueError, TypeError, json.JSONDecodeError): continue
    return routes

def load_asns():
    result = {}
    for row in csv.DictReader(get(BGP_ASNS).decode("utf-8", errors="replace").splitlines()):
        asn, name = row.get("asn", "").strip(), row.get("name", "").strip()
        if asn: result[asn if asn.startswith("AS") else f"AS{asn}"] = name
    return result

def load_rir_allocations():
    allocations = []
    for rir, url in RIRS.items():
        try: raw = get(url).decode("utf-8", errors="replace")
        except Exception as exc:
            print(f"WARNING: {rir}: {exc}"); continue
        for line in raw.splitlines():
            if not line or line.startswith("#"): continue
            parts = line.split("|")
            if len(parts) < 7 or parts[0] == "2" or parts[2] not in {"ipv4", "ipv6"}: continue
            try:
                start, value = ipaddress.ip_address(parts[3]), int(parts[4])
                networks = [ipaddress.ip_network(f"{start}/{value}", strict=False)] if parts[2] == "ipv6" else ipaddress.summarize_address_range(start, start + value - 1)
                for network in networks: allocations.append({"network": network, "rir": rir, "country": parts[1]})
            except (ValueError, TypeError): continue
    allocations.sort(key=lambda x: (x["network"].version, int(x["network"].network_address)))
    return allocations

def make_indexes(allocations):
    indexes = {}
    for version in (4, 6):
        rows = [x for x in allocations if x["network"].version == version]
        indexes[version] = (rows, [int(x["network"].network_address) for x in rows])
    return indexes

def find_rir(network, indexes):
    rows, starts = indexes[network.version]
    target = int(network.network_address)
    pos = bisect.bisect_right(starts, target) - 1
    for i in range(pos, max(-1, pos - 128), -1):
        candidate = rows[i]
        if target >= int(candidate["network"].network_address) and target <= int(candidate["network"].broadcast_address):
            return candidate
    return {"rir": "", "country": ""}

def write_combined(routes, asns, rir_indexes, filename, ipv6_only=False):
    path = DATA / filename
    fields = ["prefix", "network", "mask_length", "ip_version", "asn", "organization", "rir", "country", "hits", "source"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh); writer.writerow(fields)
        for route in routes:
            if ipv6_only and route["ip_version"] != 6: continue
            rir = find_rir(route["network"], rir_indexes)
            writer.writerow([route["prefix"], str(route["network"].network_address), route["mask_length"], route["ip_version"], route["asn"], asns.get(route["asn"], ""), rir["rir"], rir["country"], route["hits"], "BGP+RIR"])
    print(f"Wrote {path}")

if __name__ == "__main__":
    routes = load_bgp(); asns = load_asns(); indexes = make_indexes(load_rir_allocations())
    write_combined(routes, asns, indexes, "ip_ownership.csv")
    write_combined(routes, asns, indexes, "ipv6_ownership.csv", ipv6_only=True)
