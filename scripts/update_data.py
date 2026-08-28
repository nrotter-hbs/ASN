#!/usr/bin/env python3
"""Build Sentinel-ready BGP attribution and compact threat-intel datasets."""
from __future__ import annotations
import csv,json,pathlib,urllib.request,ipaddress,datetime,re,math
ROOT=pathlib.Path(__file__).resolve().parents[1];DATA=ROOT/'data';DATA.mkdir(parents=True,exist_ok=True)
BGP_TABLE='https://bgp.tools/table.jsonl';BGP_ASNS='https://bgp.tools/asns.csv'
SPAM={'ipv4':'https://www.spamhaus.org/drop/drop_v4.json','ipv6':'https://www.spamhaus.org/drop/drop_v6.json','asn':'https://www.spamhaus.org/drop/asndrop.json'}
FEODO='https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json';CINS='https://cinsscore.com/list/ci-badguys.txt';DSHIELD='https://feeds.dshield.org/feeds/daily_sources';FULL={'ipv4':'https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt','ipv6':'https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt'}
def get(url):
 r=urllib.request.Request(url,headers={'User-Agent':'ASN-Sentinel-data-pipeline/1.0'})
 with urllib.request.urlopen(r,timeout=180) as x:return x.read()
def load_asns():
 d={}
 for r in csv.DictReader(get(BGP_ASNS).decode('utf-8','replace').splitlines()):
  a=(r.get('asn')or'').strip();n=(r.get('name')or r.get('organization')or'').strip();c=(r.get('cc')or'').strip()
  if a:d[a if a.startswith('AS') else 'AS'+a]=(n,c)
 return d
def load_routes():
 out=[]
 for line in get(BGP_TABLE).decode('utf-8','replace').splitlines():
  try:
   o=json.loads(line);p=o.get('CIDR')or o.get('prefix');a=o.get('ASN')or o.get('asn')or o.get('origin')
   if p and a:
    n=ipaddress.ip_network(p,strict=False);out.append((str(n),n.prefixlen,n.version,'AS'+str(a).removeprefix('AS'),o.get('Hits','')))
  except(ValueError,TypeError,json.JSONDecodeError):continue
 return out
def write_owner(name,rs,ad):
 p=DATA/name
 with p.open('w',newline='',encoding='utf-8')as f:
  w=csv.writer(f);w.writerow(['prefix','mask_length','asn','organization','country','hits'])
  for pre,m,v,a,h in rs:n,c=ad.get(a,('',''));w.writerow([pre,m,a,n,c,h])
 s=p.stat().st_size/1048576;print(f'{name}: {s:.2f} MB')
 if s>=90:raise RuntimeError(f'{name} is {s:.1f} MB; refusing to approach GitHub 100 MB limit')
def spam_records(kind):
 t=get(SPAM[kind]).decode('utf-8','replace').strip()
 try:
  j=json.loads(t);return(j if isinstance(j,list)else j.get('data',j.get('asns',j.get('cidrs',[])))),j
 except json.JSONDecodeError:return[json.loads(x)for x in t.splitlines()if x.strip()],{}
def stamp(j):
 t=j.get('timestamp')if isinstance(j,dict)else None
 return datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat()if isinstance(t,(int,float))else datetime.datetime.now(datetime.timezone.utc).isoformat()
def write_spam(name,kind):
 rec,j=spam_records(kind);p=DATA/name;s=stamp(j)
 with p.open('w',newline='',encoding='utf-8')as f:
  w=csv.writer(f);w.writerow(['prefix','ip_version','sbl_id','source','source_url','last_seen'])
  for x in rec:
   if not isinstance(x,dict):continue
   q=x.get('cidr')or x.get('CIDR')or x.get('prefix');i=x.get('sblid')or x.get('SBLID')or x.get('id')or''
   if q:
    try:n=ipaddress.ip_network(q,strict=False);w.writerow([str(n),n.version,i,'Spamhaus DROP'if n.version==4 else'Spamhaus DROPv6',SPAM[kind],s])
    except ValueError:pass
 print(f'{name}: {p.stat().st_size/1048576:.2f} MB')
def write_spam_asn(ad):
 rec,j=spam_records('asn');p=DATA/'malicious_asns.csv';s=stamp(j)
 with p.open('w',newline='',encoding='utf-8')as f:
  w=csv.writer(f);w.writerow(['asn','organization','malicious','confidence','category','source','source_url','last_seen'])
  for x in rec:
   if isinstance(x,str):a,r=x,''
   elif isinstance(x,dict):a=x.get('asn')or x.get('AS')or x.get('as_number')or x.get('autnum')or'';r=x.get('description')or x.get('reason')or''
   else:continue
   a=str(a).strip();a=a if a.upper().startswith('AS')else'AS'+a
   if a:w.writerow([a,ad.get(a,('',''))[0],'true','high',r or'Spamhaus ASN-DROP','Spamhaus',SPAM['asn'],s])
def write_feodo(ad):
 p=DATA/'feodo_c2_ipv4.csv';data=json.loads(get(FEODO).decode('utf-8','replace'))
 with p.open('w',newline='',encoding='utf-8')as f:
  w=csv.writer(f);w.writerow(['ip','port','status','asn','organization','country','first_seen','last_seen','malware','source','source_url'])
  for x in data:
   a='AS'+str(x.get('as_number',''));n,c=ad.get(a,(x.get('as_name',''),x.get('country','')));w.writerow([x.get('ip_address',''),x.get('port',''),x.get('status',''),a,n,x.get('country',''),x.get('first_seen',''),x.get('last_online',''),x.get('malware',''),'Feodo Tracker',FEODO])
 print(f'feodo_c2_ipv4.csv: {p.stat().st_size/1048576:.2f} MB')
def write_text_ips(name,url,source,parts=1):
 data=get(url).decode('utf-8','replace').splitlines();items=[]
 for line in data:
  m=re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',line)
  if m:
   try:items.append(str(ipaddress.IPv4Address(m.group(0))))
   except ValueError:pass
 items=list(dict.fromkeys(items));parts=max(1,parts,math.ceil(len(items)/700000));chunk=math.ceil(len(items)/parts);now=datetime.datetime.now(datetime.timezone.utc).isoformat()
 for i in range(parts):
  vals=items[i*chunk:(i+1)*chunk]
  if not vals:continue
  path=DATA/(name.replace('.csv',f'_{i+1:02d}.csv') if parts>1 else name)
  with path.open('w',newline='',encoding='utf-8')as f:
   w=csv.writer(f);w.writerow(['ip','source','source_url','last_seen']);w.writerows((v,source,url,now)for v in vals)
  print(f'{path.name}: {path.stat().st_size/1048576:.2f} MB ({len(vals):,} IPs)')
def write_full(name,url,version):
 p=DATA/name;now=datetime.datetime.now(datetime.timezone.utc).isoformat();count=0
 with p.open('w',newline='',encoding='utf-8')as f:
  w=csv.writer(f);w.writerow(['prefix','ip_version','source','last_seen'])
  for line in get(url).decode('utf-8','replace').splitlines():
   line=line.strip()
   if not line or line.startswith('#'):continue
   try:n=ipaddress.ip_network(line,strict=False)
   except ValueError:continue
   if n.version==version:w.writerow([str(n),version,'Team Cymru Fullbogons',now]);count+=1
 print(f'{name}: {p.stat().st_size/1048576:.2f} MB ({count:,} prefixes)')
if __name__=='__main__':
 ad=load_asns();rs=load_routes();print(f'Loaded {len(rs):,} BGP routes');write_owner('ipv4_ownership.csv',[r for r in rs if r[2]==4],ad);write_owner('ipv6_ownership.csv',[r for r in rs if r[2]==6],ad);write_spam_asn(ad);write_spam('spamhaus_drop_ipv4.csv','ipv4');write_spam('spamhaus_drop_ipv6.csv','ipv6');write_feodo(ad);write_text_ips('cins_malicious_ipv4.csv',CINS,'CINS Army');write_text_ips('dshield_ipv4.csv',DSHIELD,'DShield daily sources',parts=5);write_full('fullbogons_ipv4.csv',FULL['ipv4'],4);write_full('fullbogons_ipv6.csv',FULL['ipv6'],6)
