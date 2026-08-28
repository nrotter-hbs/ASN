#!/usr/bin/env python3
"""Download and normalize public BGP/RIR attribution data."""

from __future__ import annotations

import csv
import io
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
    with urllib.request.urlopen(req, timeout=120) as response:
        return response.read()


def write_routes() -> None:
    raw = get(BGP_TABLE).decode("utf-8", errors="replace")
    out = DATA / "routes.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["prefix", "origin_asn", "hits"])
        for line in raw.splitlines():
            if not line.strip():
                continue
            # BGP.tools JSONL is intentionally parsed without third-party dependencies.
            import json
            obj = json.loads(line)
            writer.writerow([
                obj.get("prefix", ""),
                obj.get("asn", obj.get("origin", "")),
                obj.get("hits", ""),
            ])


def write_asns() -> None:
    raw = get(BGP_ASNS).decode("utf-8", errors="replace")
    (DATA / "asns.csv").write_text(raw, encoding="utf-8")


def write_rir() -> None:
    out = DATA / "rir_delegated.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["rir", "registry", "cc", "type", "start", "value", "date", "status", "extensions"])
        for rir, url in RIRS.items():
            try:
                raw = get(url).decode("utf-8", errors="replace")
            except Exception as exc:
                print(f"WARNING: {rir}: {exc}")
                continue
            for line in raw.splitlines():
                if not line or line.startswith("2|" ) or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) < 7:
                    continue
                if parts[2] not in {"ipv4", "ipv6", "asn"}:
                    continue
                while len(parts) < 9:
                    parts.append("")
                writer.writerow([rir, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]])


if __name__ == "__main__":
    write_routes()
    write_asns()
    write_rir()
    print("ASN/IP data updated")
