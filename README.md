# ASN / IP Ownership Data

This repository builds a free, periodically updated IPv4/IPv6 network attribution dataset from public Internet routing and Regional Internet Registry (RIR) data.

## Data sources

- BGP.tools `table.jsonl`: currently visible BGP prefixes and origin ASNs.
- BGP.tools `asns.csv`: ASN-to-name mapping.
- ARIN, RIPE NCC, APNIC, LACNIC, and AFRINIC extended delegated statistics: RIR registration data.

The dataset deliberately keeps **routing attribution** and **RIR registration** separate. The ASN announcing a prefix is not necessarily the same organization that holds the underlying registration.

## Generated files

- `data/routes.csv` — routed prefix, origin ASN, and BGP visibility (`Hits`).
- `data/asns.csv` — ASN, organization/name, and BGP.tools class.
- `data/rir_delegated.csv` — normalized RIR delegated-resource records.

## Update locally

```bash
python scripts/update_data.py
```

No API key is required.

## Automated updates

GitHub Actions runs the update on a schedule and can also be started manually with **Actions → Update ASN/IP data → Run workflow**.

BGP.tools asks consumers to cache the routing table and not download it more often than every 30 minutes; this workflow therefore updates once per day.

## Example

An IPv6 address beginning with `2607:fb91:` can be matched against the routed-prefix dataset and ASN mapping to determine its current origin ASN and organization. Always prefer the most-specific matching BGP prefix when classifying an address.

## Attribution

This repository consumes publicly available data from the sources above. See each source's terms and documentation before redistributing the generated datasets.
