#!/usr/bin/env python3
"""Enrich threat-intel feeds with BGP ASN metadata and build normalized Sentinel indexes."""
from __future__ import annotations
import csv,pathlib,ipaddress,datetime,glob
import pytricia
ROOT=pathlib.Path(__file__).resolve().parents[1];DATA=ROOT/'data';NOW=datetime.datetime.now(datetime.timezone.utc).isoformat()
def norm_asn(a): return str(a or '').strip().upper().removeprefix('AS').strip()
def build_tries():
 tries={4:pytricia.PyTricia(32),6:pytricia.PyTricia(128)}
 for version in (4,6):
  with (DATA/f'ipv{version}_ownership.csv').open(encoding='utf-8',newline='') as f:
   for r in csv.DictReader(f):
    try: tries[version][r['prefix']]=(norm_asn(r.get('asn')),r.get('organization',''),r.get('country',''))
    except (KeyError,ValueError): pass
 return tries
def lookup(tries,value):
 try:
  obj=ipaddress.ip_network(value,strict=False) if '/' in value else ipaddress.ip_address(value)
  key=str(obj.network_address if hasattr(obj,'network_address') else obj)
  hit=tries[obj.version].get(key)
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
  if x not in fields:fields.append(x)
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
  if x not in fields:fields.append(x)
 with path.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def build_reputation():
 files=[DATA/'feodo_c2_ipv4.csv',DATA/'cins_malicious_ipv4.csv']+[DATA/x for x in glob.glob('dshield_ipv4_*.csv',root_dir=DATA)]
 seen={}
 for path in files:
  if not path.exists():continue
  with path.open(encoding='utf-8',newline='') as f:
   for r in csv.DictReader(f):
    ip=r.get('ip','').strip()
    if not ip:continue
    source=r.get('source','').strip() or ('Feodo Tracker' if path.name.startswith('feodo') else 'CINS Army' if path.name.startswith('cins') else 'DShield')
    if source=='Feodo Tracker':category='malware C2';confidence='high';malware=r.get('malware','')
    elif source=='CINS Army':category='malicious/scanner';confidence='medium';malware=''
    else:category='observed attacker';confidence='medium';malware=''
    key=(ip,source)
    seen[key]={'ip':ip,'asn':norm_asn(r.get('asn')),'organization':r.get('organization',''),'country':r.get('country',''),'malicious':'true','confidence':confidence,'category':category,'source':source,'first_seen':r.get('first_seen',''),'last_seen':r.get('last_seen','') or NOW,'malware':malware}
 out=DATA/'ip_reputation_ipv4.csv';fields=['ip','asn','organization','country','malicious','confidence','category','source','first_seen','last_seen','malware']
 with out.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(sorted(seen.values(),key=lambda x:(x['ip'],x['source'])))
 print(f'ip_reputation_ipv4.csv: {out.stat().st_size/1048576:.2f} MB ({len(seen):,} records)')
def build_high_fidelity():
 """Build one normalized table for high-confidence IPs plus malicious prefixes and ASN-derived BGP prefixes."""
 records=[]
 rep=DATA/'ip_reputation_ipv4.csv'
 if rep.exists():
  with rep.open(encoding='utf-8',newline='') as f:
   for r in csv.DictReader(f):
    if str(r.get('confidence','')).strip().lower()=='high' and r.get('ip'):
     records.append({'indicator':r['ip'],'indicator_type':'IP','ip_version':'4','prefix':'','asn':norm_asn(r.get('asn')),'organization':r.get('organization',''),'country':r.get('country',''),'malicious':'true','confidence':'high','category':r.get('category',''),'source':r.get('source',''),'first_seen':r.get('first_seen',''),'last_seen':r.get('last_seen',''),'malware':r.get('malware','')})
 for name,version in (('spamhaus_drop_ipv4.csv','4'),('spamhaus_drop_ipv6.csv','6')):
  path=DATA/name
  if not path.exists():continue
  with path.open(encoding='utf-8',newline='') as f:
   for r in csv.DictReader(f):
    if r.get('prefix'):
     records.append({'indicator':r['prefix'],'indicator_type':f'IPv{version}Prefix','ip_version':version,'prefix':r['prefix'],'asn':norm_asn(r.get('asn')),'organization':r.get('organization',''),'country':r.get('country',''),'malicious':'true','confidence':'high','category':'malicious netblock','source':r.get('source',''),'first_seen':'','last_seen':r.get('last_seen',''),'malware':''})

 # Expand Spamhaus ASN-DROP entries to their currently announced BGP prefixes.
 # Both IPv4 and IPv6 prefixes are included. Ownership is taken from the current
 # bgp.tools-derived ownership snapshots in ipv4_ownership.csv / ipv6_ownership.csv.
 malicious_asns=set()
 asn_file=DATA/'malicious_asns.csv'
 if asn_file.exists():
  with asn_file.open(encoding='utf-8',newline='') as f:
   for r in csv.DictReader(f):
    a=norm_asn(r.get('asn'))
    if str(r.get('malicious','')).strip().lower()=='true' and a:
     malicious_asns.add(a)

 asn_prefix_count={}
 for version in (4,6):
  path=DATA/f'ipv{version}_ownership.csv'
  if not path.exists():continue
  with path.open(encoding='utf-8',newline='') as f:
   for r in csv.DictReader(f):
    a=norm_asn(r.get('asn'));p=r.get('prefix','')
    if a in malicious_asns and p:
     records.append({'indicator':p,'indicator_type':f'MaliciousASNIPv{version}Prefix','ip_version':str(version),'prefix':p,'asn':a,'organization':r.get('organization',''),'country':r.get('country',''),'malicious':'true','confidence':'high','category':'malicious ASN associated prefix','source':'Spamhaus ASN-DROP + BGP','first_seen':'','last_seen':'','malware':''})
     asn_prefix_count[a]=asn_prefix_count.get(a,0)+1
 if malicious_asns:
  print(f'Spamhaus ASN-DROP ASNs: {len(malicious_asns):,}; associated BGP prefixes added: {sum(asn_prefix_count.values()):,}')

 out=DATA/'high_fidelity_indicators.csv';fields=['indicator','indicator_type','ip_version','prefix','asn','organization','country','malicious','confidence','category','source','first_seen','last_seen','malware']
 dedup={tuple(r[k] for k in ('indicator','source','category')):r for r in records}
 with out.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(sorted(dedup.values(),key=lambda x:(x['indicator_type'],x['indicator'],x['source'])))
 print(f'high_fidelity_indicators.csv: {out.stat().st_size/1048576:.2f} MB ({len(dedup):,} records)')
def main():
 tries=build_tries();ip_files=[DATA/'cins_malicious_ipv4.csv',DATA/'feodo_c2_ipv4.csv']+[DATA/x for x in glob.glob('dshield_ipv4_*.csv',root_dir=DATA)]
 for p in ip_files:
  if p.exists():enrich_ip_file(p,tries)
 for p in (DATA/'spamhaus_drop_ipv4.csv',DATA/'spamhaus_drop_ipv6.csv'):
  if p.exists():enrich_prefix_file(p,tries)
 build_reputation();build_high_fidelity();print('Threat-intel ASN enrichment and normalized reputation indexes complete')
if __name__=='__main__':main()
