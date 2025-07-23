#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтруем подписки из sources.txt.
По умолчанию: TCP-ping (3 c); флаг --probe http качает 100 KiB через прокси
и отбрасывает узлы со скоростью < 200 kB/s.
Сохраняем ≤ 20 лучших (по одному на страну).
"""
from __future__ import annotations
import argparse, asyncio, base64, re, time, json, ipaddress
from pathlib import Path
import aiohttp, async_timeout

# ──────────── CLI ────────────
P = argparse.ArgumentParser()
P.add_argument("--sources", required=True)
P.add_argument("--output",  required=True)
P.add_argument("--debug",   required=True)
P.add_argument("--max", type=int, default=20)
P.add_argument("--probe", choices=("tcp", "http"), default="tcp")
P.add_argument("--drop-ports", default="8880")
P.add_argument("--drop-proto", default="ss,ssr")
P.add_argument("--unique-country", action="store_true")
P.add_argument("--min-speed", type=int, default=200, help="kB/s для http-probe")
args = P.parse_args()

DROP_PORTS  = {int(p) for p in args.drop_ports.split(",") if p}
DROP_PROTO  = {p.lower() for p in args.drop_proto.split(",") if p}
URI_RE = re.compile(rb'(vmess|vless|trojan|ssr?|hysteria2?|socks5?|https?)://[^\s#]+', re.I)
TEST_URL = "https://speed.cloudflare.com/__down?bytes=100000"   # 100 KiB

# ──────────── utils ────────────
def decode_b64(s:str)->str:
    try: return base64.b64decode(s+'==').decode()
    except: return s

def host_port(uri:str):
    if uri.startswith("vmess://"):
        try:
            j=json.loads(decode_b64(uri[8:]))
            return j["add"], int(j["port"])
        except: return None
    h=uri.split("@")[-1].split("?")[0].split("#")[0]
    if ":" not in h: return None
    host, port = h.rsplit(":",1)
    try: port=int(port)
    except: return None
    return host, port

async def tcp_ping(host, port, timeout=3):
    try:
        t0=time.perf_counter()
        r,w=await asyncio.wait_for(asyncio.open_connection(host,port), timeout)
        w.close(); await w.wait_closed()
        return (time.perf_counter()-t0)*1000
    except: return None

async def http_speed(proxy:str, session:aiohttp.ClientSession, min_kB=200):
    try:
        with async_timeout.timeout(8):
            t0=time.perf_counter()
            async with session.get(TEST_URL, proxy=proxy, timeout=8) as r:
                await r.content.readexactly(100_000)
            t=time.perf_counter()-t0
        return 100_000/1024/t if t>0 else None
    except: return None

# ──────────── main ────────────
async def main():
    dbg = Path(args.debug); dbg.parent.mkdir(exist_ok=True, parents=True)
    out = Path(args.output); out.parent.mkdir(exist_ok=True, parents=True)
    dbg.write_text("")

    # 1) собираем все URI
    sources=[l.strip() for l in Path(args.sources).read_text().splitlines()
             if l.strip() and not l.lstrip().startswith("#")]

    async with aiohttp.ClientSession() as sess:
        blobs = await asyncio.gather(*(sess.get(u,timeout=15).then(lambda r:r.text())
                                       for u in sources), return_exceptions=True)
    uris=[]
    for txt in blobs:
        if isinstance(txt,Exception): continue
        for m in URI_RE.finditer(decode_b64_if_needed(txt:=txt if isinstance(txt,str) else "")):
            uri=m.group(0).decode()
            proto=uri.split("://",1)[0].lower()
            hp=host_port(uri)
            if not hp or proto in DROP_PROTO or hp[1] in DROP_PORTS: continue
            uris.append(uri)

    # 2) проверяем
    good=[]
    async with aiohttp.ClientSession() as sess:
        async def check(uri):
            proto=uri.split("://",1)[0].lower()
            host,port=host_port(uri)
            if args.probe=="tcp" or proto not in {"http","https","socks5"}:
                rtt=await tcp_ping(host,port)
                if rtt: good.append((rtt,uri))
            else:
                spd=await http_speed(uri, sess, args.min_speed)
                if spd and spd>=args.min_speed:
                    good.append((1000/spd,uri))   # обратная величина – «меньше лучше»
        await asyncio.gather(*(check(u) for u in uris))

    if not good:
        out.write_text(""); return
    good.sort()
    # 3) уникальная страна
    if args.unique_country:
        import ipaddress, json, urllib.request
        cc_cache={}
        def cc(ip):
            if ip in cc_cache: return cc_cache[ip]
            try:
                cc_cache[ip]=urllib.request.urlopen(
                    f"https://ipapi.co/{ip}/country/").read().decode().strip()
            except: cc_cache[ip]="__"
            return cc_cache[ip]

        chosen, seen=set(),[]
        for rtt,uri in good:
            host,_=host_port(uri); ip=socket.gethostbyname(host)
            c=cc(ip)
            if c not in chosen:
                chosen.add(c); seen.append((rtt,uri))
            if len(seen)==args.max: break
        good=seen
    else:
        good=good[:args.max]

    out.write_text("\n".join(u for _,u in good)+"\n")
    dbg.write_text("\n".join(f"{rtt:.0f} {u}" for rtt,u in good))

# helper for b64 detection
def decode_b64_if_needed(txt:str)->str:
    if txt.count("\n")<2 and re.fullmatch(r'[A-Za-z0-9+/]+=*', txt.strip()):
        return decode_b64(txt.strip())
    return txt

if __name__=="__main__":
    asyncio.run(main())