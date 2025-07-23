#!/usr/bin/env python3
from __future__ import annotations
import argparse, base64, csv, ipaddress, json, os, re, socket, subprocess, tempfile, textwrap, time
from pathlib import Path
from urllib import request, parse

SUB_URL = ("https://raw.githubusercontent.com/"
           "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
OUT = Path("output"); OUT.mkdir(exist_ok=True, parents=True)
TXT = OUT/"Server.txt"; CSV = OUT/"latency_full.csv"

MAX_RES, MAX_DELAY = 20, 250
PROBE_CNT, PROBE_TO, TOTAL_TO = 5, 12, 180    # счётчик ↑
_is_b64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_relay  = re.compile(r"relay", re.I)
_proto  = re.compile(r"^(?P<p>[a-z]+)://", re.I)

def b64d(t:str)->str: return base64.b64decode(t+"="*(-len(t)%4)).decode("utf-8","ignore")
def fetch(u:str)->list[str]:
    raw=request.urlopen(u,timeout=20).read().decode(errors="ignore")
    if raw.count("\n")<=1 and _is_b64(raw.strip()): raw=b64d(raw.strip())
    return [l.strip() for l in raw.splitlines() if l.strip()]

def is_relay(link:str)->bool:
    if _relay.search(link.split("#",1)[0].split("?",1)[0]): return True
    if link.lower().startswith("vmess://") and _is_b64(link[8:]):
        try: return _relay.search(json.loads(b64d(link[8:])).get("ps","")) is not None
        except Exception: pass
    return False

def host_port(link:str)->tuple[str,int]|None:
    m=_proto.match(link); p=m.group("p").lower() if m else ""
    if p=="vmess" and _is_b64(link[8:]):
        try:
            j=json.loads(b64d(link[8:]))
            return j.get("add"), int(j.get("port",0))
        except Exception: return None
    try:
        u=parse.urlsplit(link)
        return u.hostname, u.port or 0
    except Exception: return None

def private_ip(host:str)->bool:
    try: return ipaddress.ip_address(socket.gethostbyname(host)).is_private
    except Exception: return True

def probe(link:str)->float|None:
    if is_relay(link): return None
    hp=host_port(link)
    if not hp or private_ip(hp[0]): return None
    with tempfile.NamedTemporaryFile("w+",delete=False) as f:
        f.write(link+"\n"); f.flush()
        try:
            cmd=["sing-box","probe",f"file://{f.name}","--count",str(PROBE_CNT),
                 "--download-size","256KB"]
            d=json.loads(subprocess.run(cmd,capture_output=True,text=True,
                                        timeout=PROBE_TO).stdout or "{}")
            if d.get("success_cnt")!=PROBE_CNT: return None
            lat=d.get("avg_delay"); return lat if lat and lat<=MAX_DELAY else None
        except Exception: return None
        finally: os.unlink(f.name)

geo={}
def cc(host:str)->str|None:
    try: ip=socket.gethostbyname(host)
    except: return None
    if ip in geo: return geo[ip]
    try:
        c=request.urlopen(f"https://ipapi.co/{ip}/country/",timeout=6).read().decode().strip()
        geo[ip]=c; return c if len(c)==2 else None
    except: return None

def main():
    links=fetch(SUB_URL); print("получено:",len(links))
    scored,t0=[],time.time()
    for ln in links:
        if time.time()-t0>TOTAL_TO: break
        d=probe(ln); d and scored.append((d,ln))
    if not scored: print("0 пригодных"); return

    csv.writer(CSV.open("w")).writerows([("ms","link"),*scored])
    best,used_cc,used_ep=[],set(),set()
    for d,ln in sorted(scored):
        host,port=host_port(ln)
        if (host,port) in used_ep: continue
        country=cc(host) or "_"
        if country not in used_cc:
            best.append(ln); used_cc.add(country); used_ep.add((host,port))
        if len(best)==MAX_RES: break

    TXT.write_text("\n".join(best)+"\n",encoding="utf-8")
    print(textwrap.dedent(f"""
        ★ {len(best)} ссылок → {TXT}
        🌍 {', '.join(sorted(used_cc-{'_'}) or ['n/a'])}
    """).strip())

if __name__=="__main__": main()