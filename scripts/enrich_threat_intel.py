#!/usr/bin/env python3
"""Add BGP-origin ASN metadata to IP/prefix threat-intelligence datasets."""
from __future__ import annotations
import csv, pathlib, ipaddress, datetime, glob
import pytricia
ROOT=pathlib.Path(__file__).resolve().parents[1]; DATA=ROOT/'data'
NOW=datetime.datetime.now(datetime.timezone.utc).isoformat()
def build_tries():
 tries={4:pytricia.PyTricia(32),6:pytricia.PyTricia(128)}
 for version in (4,6):
  path=DATA/f'ipv{version}_ownership.csv'
  with path.open(encoding='utf-8',newline='') as f:
   for r in csv.DictReader(f):
    try: tries[version][r['prefix']]=(r['asn'],r['organization'],r['country'])
    except (KeyError,ValueError): pass
 return tries
def lookup(tries, value):
 try:
  obj=ipaddress.ip_network(value,strict=False) if '/' in value else ipaddress.ip_address(value)
  hit=tries[obj.version].get(str(obj.network_address if hasattr(obj,'network_address') else obj))
  return hit if hit else ('','','')
 except ValueError:return ('','','')
def enrich_ip_file(path,tries):
 rows=[]
 with path.open(encoding='utf-8',newline='') as f:
  for r in csv.DictReader(f):
   a,o,c=lookup(tries,r.get('ip',''));r.update(asn=a,organization=o,country=c);rows.append(r)
 if not rows:return
 fields=list(rows[0].keys())
 for x in ('asn','organization','country'):
  if x not in fields: fields.append(x)
 with path.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def enrich_prefix_file(path,tries):
 rows=[]
 with path.open(encoding='utf-8',newline='') as f:
  for r in csv.DictReader(f):
   a,o,c=lookup(tries,r.get('prefix',''));r.update(asn=a,organization=o,country=c);rows.append(r)
 if not rows:return
 fields=list(rows[0].keys())
 for x in ('asn','organization','country'):
  if x not in fields: fields.append(x)
 with path.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def main():
 tries=build_tries()
 for p in [DATA/'cins_malicious_ipv4.csv',DATA/'feodo_c2_ipv4.csv']+ [DATA/x for x in glob.glob('dshield_ipv4_*.csv',root_dir=DATA)]:
  if p.exists():enrich_ip_file(p,tries)
 for p in (DATA/'spamhaus_drop_ipv4.csv',DATA/'spamhaus_drop_ipv6.csv'):
  if p.exists():enrich_prefix_file(p,tries)
 print('Threat-intel ASN enrichment complete')
if __name__=='__main__':main()
