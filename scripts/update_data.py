#!/usr/bin/env python3
"""Build compact Sentinel-ready IPv4/IPv6 BGP attribution and Spamhaus intelligence."""
from __future__ import annotations
import csv, json, pathlib, urllib.request, ipaddress, datetime
ROOT=pathlib.Path(__file__).resolve().parents[1]; DATA=ROOT/"data"; DATA.mkdir(parents=True,exist_ok=True)
BGP_TABLE="https://bgp.tools/table.jsonl"; BGP_ASNS="https://bgp.tools/asns.csv"
SPAMHAUS={"ipv4":"https://www.spamhaus.org/drop/drop_v4.json","ipv6":"https://www.spamhaus.org/drop/drop_v6.json","asn":"https://www.spamhaus.org/drop/asndrop.json"}
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
if __name__=="__main__":
 asns=load_asns();routes=load_routes();print(f"Loaded {len(routes):,} BGP routes")
 write_csv("ipv4_ownership.csv",[r for r in routes if r[2]==4],asns);write_csv("ipv6_ownership.csv",[r for r in routes if r[2]==6],asns)
 write_malicious_asns(asns);write_drop("spamhaus_drop_ipv4.csv","ipv4");write_drop("spamhaus_drop_ipv6.csv","ipv6")
