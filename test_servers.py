#!/usr/bin/env python3
import argparse, base64, csv, json, os, re, socket, subprocess, tempfile, textwrap, time
from pathlib import Path
from urllib import parse, request

URL_DEFAULT = ("https://raw.githubusercontent.com/"
               "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
OUT_DIR = Path("output"); OUT_DIR.mkdir(exist_ok=True, parents=True)
FILE_TXT = OUT_DIR / "Server.txt"
FILE_CSV = OUT_DIR / "latency_full.csv"

MAX_RES   = 20
MAX_DELAY = 250          # мс
PROBE_CNT = 3
PROBE_TO  = 10           # сек/узел
TOTAL_TO  = 180          # сек/скрипт

_is_b64  = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_relay   = re.compile(r"relay", re.I)
_proto   = re.compile(r"^(?P<p>[a-z]+)://", re.I)

def b64d(t:str)->str: return base64.b64decode(t+"="*(-len(t)%4)).decode("utf-8","ignore")

def fetch(url:str)->list[str]:
    raw=request.urlopen(url,timeout=15).read().decode("utf-8","ignore")
    if raw.count("\n")<=1 and _is_b64(raw.strip()): raw=b64d(raw.strip())
    return [l.strip() for l in raw.splitlines() if l.strip()]

def is_relay(link:str)->bool:
    if _relay.search(link.split("#",1)[0].split("?",1)[0]):   # ← до ? или #
        return True
    if link.lower().startswith("vmess://") and _is_b64(link[8:]):
        try: return _relay.search(json.loads(b64d(link[8:])).get("ps","")) is not None
        except Exception: pass
    return False

def probe(link:str)->float|None:
    if is_relay(link): return None
    with tempfile.NamedTemporaryFile("w+",delete=False) as tmp:
        tmp.write(link+"\n"); tmp.flush()
        try:
            r=subprocess.run(
              ["sing-box","probe",f"file://{tmp.name}","--count",str(PROBE_CNT)],
              capture_output=True,text=True,timeout=PROBE_TO)
            d=json.loads(r.stdout or "{}")
            lat=d.get("avg_delay")
            if not d.get("success") or lat is None or lat>MAX_DELAY: return None
            return lat
        except (subprocess.TimeoutExpired,json.JSONDecodeError): return None
        finally: os.unlink(tmp.name)

def host_port(link:str)->tuple[str,int]|None:
    m=_proto.match(link); proto=m.group("p").lower() if m else ""
    if proto=="vmess" and _is_b64(link[8:]):
        try:
            j=json.loads(b64d(link[8:]))
            return j.get("add"), int(j.get("port",0))
        except Exception: pass
    try:
        u=parse.urlsplit(link)
        return u.hostname, u.port or 0
    except Exception:
        return None

geo_cache={}
def cc_for(host:str)->str|None:
    try: ip=socket.gethostbyname(host)
    except socket.gaierror: return None
    if ip in geo_cache: return geo_cache[ip]
    try:
        cc=request.urlopen(f"https://ipapi.co/{ip}/country/",timeout=5).read().decode().strip()
        geo_cache[ip]=cc; return cc if len(cc)==2 else None
    except Exception: return None

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--url",default=URL_DEFAULT)
    ap.add_argument("--output",default=str(FILE_TXT)); args=ap.parse_args()

    links=fetch(args.url); print(f"✓ получено: {len(links)}")
    scored,t0=[],time.time()
    for ln in links:
        if time.time()-t0> TOTAL_TO: print("⏳ stop by timeout"); break
        d=probe(ln); d and scored.append((d,ln))

    if not scored: print("⚠️ 0 пригодных узлов"); return
    with FILE_CSV.open("w",newline="") as f: csv.writer(f).writerows([("ms","link"),*scored])

    best,seen_cc,seen_ep=set(),set(),set()
    for d,ln in sorted(scored):
        hp=host_port(ln);  hp or continue
        host,port=hp
        if (host,port) in seen_ep: continue
        cc=cc_for(host) or "_"
        if cc not in seen_cc:
            best.add(ln); seen_cc.add(cc); seen_ep.add((host,port))
        if len(best)==MAX_RES: break
    if len(best)<MAX_RES:
        for _,ln in sorted(scored):
            if ln not in best:
                best.add(ln)
                if len(best)==MAX_RES: break

    Path(args.output).write_text("\n".join(best)+"\n",encoding="utf-8")
    print(textwrap.dedent(f"""
        ★ {len(best)} узлов сохранено
        🌍 страны: {', '.join(sorted(seen_cc-{'_'})) or 'n/a'}
    """).strip())

if __name__=="__main__": main()