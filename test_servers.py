#!/usr/bin/env python3
import argparse, base64, csv, ipaddress, json, os, re, socket, subprocess, tempfile, textwrap, time
from pathlib import Path
from urllib import request, parse

URL = ("https://raw.githubusercontent.com/"
       "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
ODIR = Path("output"); ODIR.mkdir(exist_ok=True, parents=True)
F_TXT, F_CSV = ODIR / "Server.txt", ODIR / "latency_full.csv"

MAX_N, MAX_MS = 20, 250
COUNT, P_TIMEOUT, ALL_TIMEOUT = 5, 12, 180

_b64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_relay = re.compile(r"relay", re.I)
_proto = re.compile(r"^(?P<p>[a-z]+)://", re.I)

def b64d(t): return base64.b64decode(t + '=' * (-len(t) % 4)).decode(errors='ignore')

def fetch(u):
    txt = request.urlopen(u, timeout=20).read().decode(errors='ignore')
    if txt.count('\n') <= 1 and _b64(txt.strip()):
        txt = b64d(txt.strip())
    return [l.strip() for l in txt.splitlines() if l.strip()]

def is_relay(s):
    base = s.split('#',1)[0].split('?',1)[0]
    if _relay.search(base): return True
    if s.lower().startswith('vmess://') and _b64(s[8:]):
        try: return _relay.search(json.loads(b64d(s[8:])).get('ps','')) is not None
        except: pass
    return False

def host_port(link):
    m = _proto.match(link)
    if not m: return None
    p = m.group('p').lower()
    if p == 'vmess' and _b64(link[8:]):
        try:
            j = json.loads(b64d(link[8:]))
            return j.get('add'), int(j.get('port',0))
        except: return None
    try:
        u = parse.urlsplit(link)
        return u.hostname, u.port or 0
    except: return None

def is_private(host):
    try: return ipaddress.ip_address(socket.gethostbyname(host)).is_private
    except: return True

def probe(link):
    if is_relay(link): return None
    hp = host_port(link)
    if not hp or is_private(hp[0]): return None
    with tempfile.NamedTemporaryFile('w+', delete=False) as t:
        t.write(link+'\n'); t.flush()
        try:
            cmd = ["sing-box","probe",f"file://{t.name}",
                   "--count",str(COUNT),"--download-size","256KB"]
            js = json.loads(subprocess.run(cmd, capture_output=True, text=True,
                                           timeout=P_TIMEOUT).stdout or "{}")
            if js.get("success_cnt") != COUNT: return None
            d = js.get("avg_delay")
            return d if d and d <= MAX_MS else None
        except: return None
        finally: os.unlink(t.name)

geo={}
def cc(host):
    try: ip = socket.gethostbyname(host)
    except: return None
    if ip in geo: return geo[ip]
    try:
        c = request.urlopen(f"https://ipapi.co/{ip}/country/", timeout=6).read().decode().strip()
        geo[ip] = c
        return c if len(c)==2 else None
    except: return None

def main():
    links = fetch(URL); print("строк:", len(links))
    scored, t0 = [], time.time()
    for ln in links:
        if time.time()-t0 > ALL_TIMEOUT: break
        d = probe(ln); d and scored.append((d,ln))
    if not scored: print("0 прошли probe"); return

    csv.writer(F_CSV.open('w')).writerows([("ms","link"), *scored])

    best, used_cc, used_ep = [], set(), set()
    for d, ln in sorted(scored):
        h, p = host_port(ln)
        if (h,p) in used_ep: continue
        country = cc(h) or "_"
        if country not in used_cc:
            best.append(ln); used_cc.add(country); used_ep.add((h,p))
        if len(best) == MAX_N: break

    F_TXT.write_text('\n'.join(best)+'\n', encoding='utf-8')
    print(textwrap.dedent(f"""
        ★ {len(best)} ссылок сохранены
        🌍 {', '.join(sorted(used_cc-{'_'}) or ['n/a'])}
    """).strip())

if __name__ == "__main__":
    main()