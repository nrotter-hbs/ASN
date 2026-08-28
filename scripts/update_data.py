#!/usr/bin/env python3
"""Build Sentinel-ready IPv4/IPv6 BGP attribution and multi-source IP/ASN intelligence."""
from __future__ import annotations
import csv, json, pathlib, urllib.request, ipaddress, datetime, re
ROOT=pathlib.Path(__file__).resolve().parents[1]; DATA=ROOT/"data"; DATA.mkdir(parents=True,exist_ok=True)
BGP_TABLE="https://bgp.tools/table.jsonl"; BGP_ASNS="https://bgp.tools/asns.csv"
SPAMHAUS={"ipv4":"https://www.spamhaus.org/drop/drop_v4.json","ipv6":"https://www.spamhaus.org/drop/drop_v6.json","asn":"https://www.spamhaus.org/drop/asndrop.json"}
FEODO="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
CINS="https://cinsscore.com/list/ci-badguys.txt"
DSHIELD="https://feeds.dshield.org/feeds/daily_sources"
FULLBOGONS={"ipv4":"https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt","ipv6":"https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt"}
def get(url):
 r=urllib.request.Request(url,headers={"User-Agent":"ASN-data-pipeline/1.0"})
 with urllib.request.urlopen(r,timeout=180) as x:return x.read()
def load_asns():
 out={}
 for row in csv.DictReader(get(BGP_ASNS).decode("utf-8","replace").splitlines()):
  a=(row.get("asn")or"").strip(); n=(row.get("name")or row.get("organization")or"").strip(); c=(row.get("cc")or"").strip()
  if a: out[a if a.startswith("AS") else "AS"+a]=(n,c)
 return out
def load_routes():
 out=[]
 for line in get(BGP_TABLE).decode("utf-8","replace").splitlines():
  try:
   o=json.loads(line); p=o.get("CIDR")or o.get("prefix"); a=o.get("ASN")or o.get("asn")or o.get("origin")
   if p and a:
    net=ipaddress.ip_network(p,strict=False); out.append((str(net),net.prefixlen,net.version,"AS"+str(a).removeprefix("AS"),o.get("Hits","")))
  except(ValueError,TypeError,json.JSONDecodeError):continue
 return out
def write_csv(name,routes,asns):
 path=DATA/name
 with path.open("w",newline="",encoding="utf-8")as f:
  w=csv.writer(f); w.writerow(["prefix","mask_length","asn","organization","country","hits"])
  for p,m,v,a,h in routes:
   n,c=asns.get(a,("","")); w.writerow([p,m,a,n,c,h])
 size=path.stat().st_size/1024/1024; print(f"{path}: {size:.1f} MB")
 if size>=90: raise RuntimeError(f"{path} is {size:.1f} MB; refusing to approach GitHub's 100 MB limit")
def spamhaus_records(kind):
 text=get(SPAMHAUS[kind]).decode("utf-8","replace").strip()
 try:
  raw=json.loads(text)
  if isinstance(raw,list):return raw,{}
  if isinstance(raw,dict):return raw.get("data",raw.get("asns",raw.get("cidrs",[]))),raw
 except json.JSONDecodeError: pass
 rec=[]
 for line in text.splitlines():
  try: rec.append(json.loads(line))
  except json.JSONDecodeError: pass
 return rec,{}
def seen(raw):
 t=raw.get("timestamp")if isinstance(raw,dict)else None
 return datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat()if isinstance(t,(int,float))else datetime.datetime.now(datetime.timezone.utc).isoformat()
def parse_drop(kind):
 records,raw=spamhaus_records(kind); s=seen(raw); out=[]
 for x in records:
  if not isinstance(x,dict):continue
  p=x.get("cidr")or x.get("CIDR")or x.get("prefix"); i=x.get("sblid")or x.get("SBLID")or x.get("id")or""
  if p:
   try:n=ipaddress.ip_network(p,strict=False);out.append((str(n),n.version,i,s))
   except ValueError:pass
 return out
def parse_asndrop():
 records,raw=spamhaus_records("asn");s=seen(raw);out=[]
 for x in records:
  if isinstance(x,str):a,r=x,""
  elif isinstance(x,dict):a=x.get("asn")or x.get("AS")or x.get("as_number")or x.get("autnum")or"";r=x.get("description")or x.get("reason")or""
  else:continue
  a=str(a).strip();a=a if a.upper().startswith("AS")else"AS"+a
  if a:out.append((a,r,s))
 return out
def write_drop(name,kind):
 path=DATA/name
 with path.open("w",newline="",encoding="utf-8")as f:
  w=csv.writer(f);w.writerow(["prefix","ip_version","sbl_id","source","source_url","last_seen"])
  for p,v,i,s in parse_drop(kind):w.writerow([p,v,i,"Spamhaus DROP"if v==4 else"Spamhaus DROPv6",SPAMHAUS[kind],s])
 print(f"{path}: {path.stat().st_size/1024/1024:.2f} MB")
def write_malicious_asns(asns):
 path=DATA/"malicious_asns.csv"
 with path.open("w",newline="",encoding="utf-8")as f:
  w=csv.writer(f);w.writerow(["asn","organization","malicious","confidence","category","source","source_url","last_seen"])
  for a,r,s in parse_asndrop():w.writerow([a,asns.get(a,("",))[0],"true","high",r or"Spamhaus ASN-DROP","Spamhaus",SPAMHAUS["asn"],s])
 print(f"{path}: {path.stat().st_size/1024/1024:.2f} MB")
def write_feodo(asns):
 path=DATA/"feodo_c2_ipv4.csv"; data=json.loads(get(FEODO).decode("utf-8","replace"))
 with path.open("w",newline="",encoding="utf-8")as f:
  w=csv.writer(f);w.writerow(["ip","port","status","asn","organization","country","first_seen","last_seen","malware","source","source_url"])
  for x in data:
   a="AS"+str(x.get("as_number"));w.writerow([x.get("ip_address",""),x.get("port",""),x.get("status",""),a,asns.get(a,(x.get("as_name",""),x.get("country","")))[0],x.get("country",""),x.get("first_seen",""),x.get("last_online",""),x.get("malware",""),"Feodo Tracker",FEODO])
 print(f"{path}: {path.stat().st_size/1024/1024:.2f} MB")
def write_cins():
 path=DATA/"cins_malicious_ipv4.csv"; now=datetime.datetime.now(datetime.timezone.utc).isoformat(); rows=[]
 for line in get(CINS).decode("utf-8","replace").splitlines():
  line=line.strip()
  if not line or line.startswith("#"):continue
  m=re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",line)
  if m:
   try:ip=ipaddress.ip_address(m.group(0));rows.append((str(ip),line,now))
   except ValueError:pass
 with path.open("w",newline="",encoding="utf-8")as f:
  w=csv.writer(f);w.writerow(["ip","raw_entry","source","last_seen"])
  for ip,raw,s in rows:w.writerow([ip,raw,"CINS Army",s])
 print(f"{path}: {path.stat().st_size/1024/1024:.2f} MB ({len(rows):,} IPs)")
def write_dshield():
 path=DATA/"dshield_ipv4.csv"; now=datetime.datetime.now(datetime.timezone.utc).isoformat(); rows=[]
 for line in get(DSHIELD).decode("utf-8","replace").splitlines():
  line=line.strip()
  if not line or line.startswith("#"):continue
  m=re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",line)
  if m:
   try:ip=ipaddress.ip_address(m.group(0));rows.append((str(ip),line,now))
   except ValueError:pass
 with path.open("w",newline="",encoding="utf-8")as f:
  w=csv.writer(f);w.writerow(["ip","raw_entry","source","last_seen"])
  for ip,raw,s in rows:w.writerow([ip,raw,"DShield daily sources",s])
 print(f"{path}: {path.stat().st_size/1024/1024:.2f} MB ({len(rows):,} IPs)")
def write_fullbogons(version):
 name=f"fullbogons_ipv{version}.csv"; path=DATA/name; now=datetime.datetime.now(datetime.timezone.utc).isoformat(); rows=[]
 for line in get(FULLBOGONS["ipv4" if version==4 else "ipv6"]).decode("utf-8","replace").splitlines():
  line=line.strip()
  if not line or line.startswith("#"):continue
  try:
   n=ipaddress.ip_network(line,strict=False)
   if n.version==version:rows.append(str(n))
  except ValueError:continue
 with path.open("w",newline="",encoding="utf-8")as f:
  w=csv.writer(f);w.writerow(["prefix","ip_version","source","last_seen"])
  for p in rows:w.writerow([p,version,"Team Cymru Fullbogons",now])
 print(f"{path}: {path.stat().st_size/1024/1024:.2f} MB ({len(rows):,} prefixes)")
if __name__=="__main__":
 asns=load_asns();routes=load_routes();print(f"Loaded {len(routes):,} BGP routes")
 write_csv("ipv4_ownership.csv",[r for r in routes if r[2]==4],asns);write_csv("ipv6_ownership.csv",[r for r in routes if r[2]==6],asns)
 write_malicious_asns(asns);write_drop("spamhaus_drop_ipv4.csv","ipv4");write_drop("spamhaus_drop_ipv6.csv","ipv6")
 write_feodo(asns);write_cins();write_dshield();write_fullbogons(4);write_fullbogons(6)
