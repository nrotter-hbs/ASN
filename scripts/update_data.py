#!/usr/bin/env python3
"""Build compact Sentinel-ready IPv4 + IPv6 BGP attribution CSVs."""
from __future__ import annotations
import csv, json, pathlib, urllib.request, ipaddress

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DATA.mkdir(parents=True, exist_ok=True)
BGP_TABLE = "https://bgp.tools/table.jsonl"
BGP_ASNS = "https://bgp.tools/asns.csv"

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "ASN-data-pipeline/1.0"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()

def load_asns():
    result = {}
    for row in csv.DictReader(get(BGP_ASNS).decode("utf-8", "replace").splitlines()):
        asn = (row.get("asn") or "").strip()
        name = (row.get("name") or row.get("organization") or "").strip()
        if asn:
            result[asn if asn.startswith("AS") else "AS" + asn] = name
    return result

def load_routes():
    routes = []
    for line in get(BGP_TABLE).decode("utf-8", "replace").splitlines():
        try:
            o = json.loads(line)
            prefix = o.get("CIDR") or o.get("prefix")
            asn = o.get("ASN") or o.get("asn") or o.get("origin")
            if prefix and asn:
                net = ipaddress.ip_network(prefix, strict=False)
                routes.append((str(net), net.prefixlen, net.version, "AS" + str(asn).removeprefix("AS"), o.get("Hits", "")))
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
    return routes

def write_csv(name, routes, asns, ipv6_only=False):
    path = DATA / name
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["prefix", "mask_length", "ip_version", "asn", "organization", "hits", "source"])
        for prefix, mask, version, asn, hits in routes:
            if ipv6_only and version != 6:
                continue
            w.writerow([prefix, mask, version, asn, asns.get(asn, ""), hits, "BGP.tools"])
    size = path.stat().st_size / 1024 / 1024
    print(f"{path}: {size:.1f} MB")
    if size >= 95:
        raise RuntimeError(f"{path} is {size:.1f} MB; refusing to create a GitHub-over-100MB file")

if __name__ == "__main__":
    asns = load_asns()
    routes = load_routes()
    print(f"Loaded {len(routes):,} BGP routes")
    write_csv("ip_ownership.csv", routes, asns)
    write_csv("ipv6_ownership.csv", routes, asns, ipv6_only=True)
