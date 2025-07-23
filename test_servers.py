#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
… (док-строка та же, урезал ради длины)
"""

from __future__ import annotations
import argparse, async_timeout, aiohttp, base64, csv, ipaddress, json
import os, re, socket, sys, time, urllib.parse, asyncio
from pathlib import Path
from typing import Sequence

URI_RE      = re.compile(r'(vless|vmess|trojan)://[^\s"<>]+', re.I)
RELAY_RE    = re.compile(r'relay', re.I)
B64_OK_RE   = re.compile(r'^[A-Za-z0-9+/]+={0,2}$').fullmatch
SPEED_TEST  = 'https://speed.hetzner.de/100MB.bin'

OUT = Path('output'); OUT.mkdir(exist_ok=True)
TXT, CSV, DBG = OUT / 'Server.txt', OUT / 'latency.csv', OUT / 'debug.log'

def log(line: str, *, end: str = '\n') -> None:
    DBG.open('a', encoding='utf-8').write(line + end)

# ───── base64 helper ───────────────────────────
def b64d(s: str) -> str:
    try:    return base64.b64decode(s + '===').decode()
    except Exception: return ''

# ───── sync helpers ────────────────────────────
def host_port(link: str) -> tuple[str,int] | None:
    if link.startswith('vmess://'):
        try:
            j = json.loads(b64d(link[8:]))
            return j['add'], int(j['port'])
        except Exception:
            return None
    u = urllib.parse.urlsplit(link)
    return u.hostname, u.port or 0

def is_private_host(host: str) -> bool:
    try:    return ipaddress.ip_address(socket.gethostbyname(host)).is_private
    except Exception: return True

def is_relay(link: str) -> bool:
    if RELAY_RE.search(link.split('#',1)[0]):                 return True
    if link.startswith('vmess://'):
        try:
            if RELAY_RE.search(json.loads(b64d(link[8:])).get('ps','')): return True
        except Exception: pass
    return False

# ───── async utils ─────────────────────────────
async def fetch_text(sess: aiohttp.ClientSession, url: str, *, timeout:int=15) -> str:
    try:
        async with async_timeout.timeout(timeout):
            async with sess.get(url) as r:
                blob = await r.read()
                txt  = blob.decode(errors='ignore')
                if txt.count('\n') < 2 and B64_OK_RE(txt.strip()):
                    txt = b64d(txt.strip())
                return txt
    except Exception as e:
        log(f'⚠️  fetch fail {url}: {e}')
        return ''

async def tcp_rtt(host:str, port:int, *, tries:int=3, per_try:int=3) -> float|None:
    results=[]
    for _ in range(tries):
        t0=time.perf_counter()
        try:
            with socket.create_connection((host,port), timeout=per_try):
                results.append((time.perf_counter()-t0)*1000)
        except Exception: pass
    return sum(results)/len(results) if len(results)>=2 else None

async def http_probe(sess: aiohttp.ClientSession, proxy:str, min_kbps:int) -> bool:
    connector = aiohttp.TCPConnector(ssl=False)
    try:
        async with sess.get(SPEED_TEST,
                            proxy=proxy,
                            headers={'Range':'bytes=0-204799'},
                            timeout=15,
                            connector=connector) as r:
            if r.status!=206: return False
            t0=time.perf_counter()
            _=await r.read()
            kbps=200/(time.perf_counter()-t0)
            return kbps>=min_kbps
    except Exception:
        return False
    finally:
        await connector.close()

# ───── main ────────────────────────────────────
async def main(argv:Sequence[str]=sys.argv[1:]) -> None:
    global DBG                       # ⬅️  объявляем ДО первого использования внутри функции

    p=argparse.ArgumentParser()
    p.add_argument('--sources',required=True)
    p.add_argument('--output', default=TXT, type=Path)
    p.add_argument('--debug',  default=DBG, type=Path)
    p.add_argument('--max',    type=int, default=20)
    p.add_argument('--probe',  choices=['tcp','http'], default='tcp')
    p.add_argument('--drop-ports', default='8880')
    p.add_argument('--drop-proto', default='ss,ssr')
    p.add_argument('--unique-country', action='store_true')
    p.add_argument('--min-speed', type=int, default=200)
    args=p.parse_args(argv)

    DBG = Path(args.debug)           # теперь можно переназначить
    DBG.unlink(missing_ok=True)

    drop_ports={int(x) for x in args.drop_ports.split(',') if x}
    drop_proto={x.lower() for x in args.drop_proto.split(',') if x}

    async with aiohttp.ClientSession() as sess:
        src_tasks=[fetch_text(sess,u.strip()) for u in Path(args.sources).read_text().splitlines() if u.strip()]
        src_texts=await asyncio.gather(*src_tasks)

    links=[m.group(0) for txt in src_texts for m in URI_RE.finditer(txt)]
    log(f'получено строк: {len(links)}')

    cand=[]
    for ln in links:
        scheme=ln.split('://',1)[0].lower()
        h,p=host_port(ln) or (None,None)
        if scheme in drop_proto or p in drop_ports or is_private_host(h or '') or is_relay(ln):
            continue
        cand.append(ln)

    if not cand:
        log('⚠️ 0 кандидатов'); args.output.write_text('')
        print('⚠️ 0 пригодных'); return

    scored=[]
    async with aiohttp.ClientSession() as sess:
        for ln in cand:
            h,p=host_port(ln)
            if not h: continue
            rtt = await tcp_rtt(h,p) if args.probe=='tcp' else \
                  (0 if await http_probe(sess,ln,args.min_speed) else None)
            log(f'{f"{rtt:.0f}" if rtt else "∞":>4}  {ln[:120]}')
            if rtt is not None and rtt<=400: scored.append((rtt,ln))

    if not scored:
        log('⚠️ 0 пригодных'); args.output.write_text('')
        print('⚠️ 0 пригодных'); return

    scored.sort()
    best, used_cc, used_ep=[],set(),set()
    for rtt,ln in scored:
        h,p=host_port(ln)
        if (h,p) in used_ep: continue
        cc='??'
        if args.unique_country:
            try:
                ip=socket.gethostbyname(h)
                async with aiohttp.ClientSession() as s2:
                    async with s2.get(f"https://ipapi.co/{ip}/country/",timeout=6) as r:
                        cc=(await r.text()).strip() or '??'
            except Exception: pass
            if cc in used_cc: continue
            used_cc.add(cc)
        best.append(ln); used_ep.add((h,p))
        if len(best)==args.max: break

    args.output.write_text('\n'.join(best)+'\n')
    print(f'✔ сохранено: {len(best)} | страны: {", ".join(sorted(used_cc)) or "—"}')

if __name__=='__main__':
    asyncio.run(main())