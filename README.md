# ASN / IP Ownership Data

Free, periodically updated IPv4 + IPv6 network attribution for Microsoft Sentinel/KQL.

## Generated data

- `data/ipv4_ownership.csv` — currently visible IPv4 BGP prefix attribution.
- `data/ipv6_ownership.csv` — currently visible IPv6 BGP prefix attribution.
- `data/malicious_asns.csv` — threat-intelligence ASN schema/feed. This is an intelligence layer, not an authoritative statement that an ASN itself is malicious.

Ownership CSV columns:

`prefix,mask_length,ip_version,asn,organization,country,hits`

The dataset is based on currently visible BGP routes from BGP.tools. BGP routing attribution answers which ASN is announcing a prefix; it is not necessarily the same as the RIR registration holder. BGP.tools says its table export is refreshed about every 30 minutes and asks bulk consumers to cache it rather than repeatedly downloading it. citeturn0search0

## Sentinel

Use the IPv4 and IPv6 CSVs with `ipv4_is_in_range()` and `ipv6_is_in_range()` and select the most-specific matching prefix.

The intended enrichment chain is:

`SourceIP -> BGP prefix -> ASN -> organization/country -> malicious ASN intelligence`

## Malicious ASN intelligence

A malicious-ASN list is not an authoritative global registry. An ASN can host malicious infrastructure without the ASN operator being malicious. The intelligence dataset therefore retains confidence, category, source, source URL, and last-seen information rather than collapsing all intelligence into an unexplained boolean.

BGP.tools also publishes curated ASN tags, which can be useful contextual signals (for example VPN/hosting classifications), but these are not equivalent to maliciousness. citeturn0search0

## Update

GitHub Actions runs daily and can also be started manually. The generator keeps IPv4 and IPv6 in separate files so the global routing dataset does not hit GitHub's per-file size limit.

No API key is required for the BGP.tools exports.

## Source

BGP.tools provides machine-readable BGP prefix/origin ASN data and ASN name mapping. citeturn0search0
