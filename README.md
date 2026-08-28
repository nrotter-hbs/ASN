# ASN / IP Ownership Data

Free, periodically updated IPv4 + IPv6 network attribution for Microsoft Sentinel/KQL.

## Generated data

- `data/ip_ownership.csv` — combined IPv4 + IPv6 BGP prefix attribution.
- `data/ipv6_ownership.csv` — IPv6-only copy for smaller Sentinel lookups.

CSV columns:

`prefix,mask_length,ip_version,asn,organization,hits,source`

The dataset is based on currently visible BGP routes from BGP.tools. BGP routing attribution answers which ASN is announcing a prefix; it is not necessarily the same as the RIR registration holder.

## Sentinel

Use `kql/lookup-ip.kql` for a unified IPv4/IPv6 lookup. It uses `ipv4_is_in_range()` and `ipv6_is_in_range()` and selects the most-specific matching prefix.

Use `kql/lookup-ipv6.kql` when only IPv6 is needed.

Raw CSV URL for Sentinel:

`https://raw.githubusercontent.com/nrotter-hbs/ASN/main/data/ip_ownership.csv`

## Update

The GitHub Actions workflow runs daily and can also be started manually. The generator intentionally keeps the CSV compact enough for normal GitHub repository file limits; it does not include the raw BGP table or expanded RIR allocations.

No API key is required.

## Source

BGP.tools provides machine-readable BGP prefix/origin ASN data and ASN name mapping. See its documentation for usage and caching guidance.
