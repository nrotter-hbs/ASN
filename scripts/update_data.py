#!/usr/bin/env python3
"""Build Sentinel-ready IPv4/IPv6 BGP attribution and Spamhaus ASN-DROP data."""
from __future__ import annotations
import csv, json, pathlib, urllib.request, ipaddress, datetime

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DATA.mkdir(parents=True, exist_ok=True)
BGP_TABLE = "https://bgp.tools/table.jsonl"
BGP_ASNS = "https://bgp.tools/asns.csv"
SPAMHAUS_ASNDROP = "https://www.spamhaus.org/drop/asndrop.json"

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "ASN-data-pipeline/1.0"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()

def load_asns():
    result = {}
    for row in csv.DictReader(get(BGP_ASNS).decode("utf-8", "replace").splitlines()):
        asn = (row.get("asn") or "").strip(); name = (row.get("name") or row.get("organization") or "").strip(); cc = (row.get("cc") or "").strip()
        if asn:
            key = asn if asn.startswith("AS") else "AS" + asn
            result[key] = (name, cc)
    return result

def load_routes():
    routes = []
    for line in get(BGP_TABLE).decode("utf-8", "replace").splitlines():
        try:
            o = json.loads(line); prefix = o.get("CIDR") or o.get("prefix"); asn = o.get("ASN") or o.get("asn") or o.get("origin")
            if prefix and asn:
                net = ipaddress.ip_network(prefix, strict=False)
                routes.append((str(net), net.prefixlen, net.version, "AS" + str(asn).removeprefix("AS"), o.get("Hits", "")))
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
    return routes

def write_csv(name, routes, asns):
    path = DATA / name
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["prefix", "mask_length", "ip_version", "asn", "organization", "country", "hits"])
        for prefix, mask, version, asn, hits in routes:
            org, cc = asns.get(asn, ("", "")); w.writerow([prefix, mask, version, asn, org, cc, hits])
    size = path.stat().st_size / 1024 / 1024; print(f"{path}: {size:.1f} MB")
    if size >= 95: raise RuntimeError(f"{path} is {size:.1f} MB; split the dataset before GitHub's 100 MB limit")

def load_spamhaus():
    raw = json.loads(get(SPAMHAUS_ASNDROP).decode("utf-8", "replace"))
    records = raw if isinstance(raw, list) else raw.get("data", raw.get("asns", []))
    out = []
    today = datetime.date.today().isoformat()
    for item in records:
        if isinstance(item, str):
            asn, reason = item, ""
        elif isinstance(item, dict):
            asn = item.get("asn") or item.get("AS") or item.get("as_number") or item.get("autnum") or ""
            reason = item.get("description") or item.get("reason") or item.get("rir") or ""
        else:
            continue
        asn = str(asn).strip()
        if asn and not asn.upper().startswith("AS"): asn = "AS" + asn
        if asn: out.append((asn, reason, today))
    return out

def write_malicious_asns(asns):
    path = DATA / "malicious_asns.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["asn", "organization", "malicious", "confidence", "category", "source", "source_url", "last_seen"])
        for asn, reason, seen in load_spamhaus():
            org, _ = asns.get(asn, ("", "")); w.writerow([asn, org, "true", "high", "Spamhaus ASN-DROP" if not reason else reason, "Spamhaus", SPAMHAUS_ASNDROP, seen])
    print(f"{path}: {path.stat().st_size / 1024 / 1024:.2f} MB")

if __name__ == "__main__":
    asns = load_asns(); routes = load_routes(); print(f"Loaded {len(routes):,} BGP routes")
    write_csv("ipv4_ownership.csv", [r for r in routes if r[2] == 4], asns)
    write_csv("ipv6_ownership.csv", [r for r in routes if r[2] == 6], asns)
    write_malicious_asns(asns)
