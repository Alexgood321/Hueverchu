#!/usr/bin/env python3
import argparse, base64, csv, ipaddress, json, re, socket, subprocess, tempfile, textwrap, time
from pathlib import Path
from urllib import request, parse

SUB = ("https://raw.githubusercontent.com/"
       "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
OD  = Path("output"); OD.mkdir(exist_ok=True, parents=True)
TXT, CSV = OD/"Server.txt", OD/"latency_full.csv"

MAX_N, MAX_MS, CNT, P_TO, ALL_TO = 20, 250, 5, 12, 180
_b64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_relay = re.compile(r"relay", re.I)
_proto = re.compile(r"^(?P<p>[a-z]+)://", re.I)

def b64d(s): return base64.b64decode(s + '=' * (-len(s) % 4)).decode(errors='ignore')
def fetch(u):                             # подписка
    raw = request.urlopen(u, timeout=20).read().decode(errors='ignore')
    if raw.count('\n') <= 1 and _b64(raw.strip()): raw = b64d(raw.strip())
    return [l.strip() for l in raw.splitlines() if l.strip()]

def is_relay(l):
    if _relay.search(l.split('#',1)[0].split('?',1)[0]): return True
    if l.lower().startswith('vmess://') and _b64(l[8:]):
        try: return _relay.search(json.loads(b64d(l[8:])).get('ps','')) is not None
        except: pass
    return False

def host_port(l):
    m=_proto.match(l); p=m.group('p').lower() if m else ''
    if p=='vmess' and _b64(l[8:]):
        try:
            j=json.loads(b64d(l[8:])); return j.get('add'), int(j.get('port',0))
        except: return None
    try:
        u=parse.urlsplit(l); return u.hostname, u.port or 0
    except: return None

def private(h):                            # 10/8, 172.16/12, 192.168/16, 127/8 …
    try: return ipaddress.ip_address(socket.gethostbyname(h)).is_private
    except: return True

def probe(l):
    if is_relay(l): return None
    hp=host_port(l);  None if not hp else None
    if not hp or private(hp[0]): return None
    with tempfile.NamedTemporaryFile('w+',delete=False) as f:
        f.write(l+'\n'); f.flush()
        try:
            cmd=["sing-box","probe",f"file://{f.name}","--count",str(CNT),"--download-size","256KB"]
            j=json.loads(subprocess.run(cmd,capture_output=True,text=True,
                                        timeout=P_TO).stdout or "{}")
            if j.get('success_cnt')!=CNT: return None
            d=j.get('avg_delay'); return d if d and d<=MAX_MS else None
        except: return None

geo={}
def cc(h):
    try: ip=socket.gethostbyname(h)
    except: return None
    if ip in geo: return geo[ip]
    try:
        c=request.urlopen(f"https://ipapi.co/{ip}/country/",timeout=6).read().decode().strip()
        geo[ip]=c; return c if len(c)==2 else None
    except: return None

def main():
    links=fetch(SUB); print("строк:",len(links))
    scored,t0=[],time.time()
    for ln in links:
        if time.time()-t0>ALL_TO: break
        d=probe(ln); d and scored.append((d,ln))
    if not scored:
        print("0 годных"); return
    csv.writer(CSV.open('w')).writerows([("ms","link"),*scored])

    best,seen_cc,seen_ep=[],set(),set()
    for d,ln in sorted(scored):
        h,p=host_port(ln)
        if (h,p) in seen_ep: continue
        c=cc(h) or '_'
        if c not in seen_cc:
            best.append(ln); seen_cc.add(c); seen_ep.add((h,p))
        if len(best)==MAX_N: break

    TXT.write_text('\n'.join(best)+'\n',encoding='utf-8')
    print(textwrap.dedent(f"""
        ★ {len(best)} ссылок сохранено
        🌍 {', '.join(sorted(seen_cc-{'_'}) or ['n/a'])}
    """).strip())

if __name__=='__main__': main()