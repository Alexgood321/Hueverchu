#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтруем super-sub:
  • берём только публичные узлы (vless/vmess/ss/trojan)
  • 3 TCP-пинга, средний RTT ≤ 400 мс
  • не relay
  • не более одного узла на страну
Результаты:  output/Server.txt, latency.csv, debug.log
"""

from __future__ import annotations
import argparse, base64, csv, ipaddress, json, os, re, socket, sys, time
from pathlib import Path
from urllib import request, parse

SRC = ("https://raw.githubusercontent.com/"
       "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")

OUT = Path("output"); OUT.mkdir(parents=True, exist_ok=True)
TXT, CSV = OUT / "Server.txt", OUT / "latency.csv"
DBG = OUT / "debug.log"

MAX_LINKS   = 20          # сколько оставить
MAX_RTT     = 400         # мс
TRIES       = 3
SOCK_TO     = 3           # тайм-аут одного connect, c
TOTAL_TO    = 240         # общий лимит на работу скрипта, c

IS_PROTO = re.compile(r"^(vless|vmess|trojan|ss)://", re.I)
IS_RELAY = re.compile(r"relay", re.I)
B64_OK   = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch

dbg = DBG.open('w', encoding='utf-8', buffering=1)
def log(*a): print(*a, file=dbg, flush=True)

# ───────────────────────── ─────────────────────────
def b64d(s: str) -> str:
    try:   return base64.b64decode(s + '===').decode()
    except Exception: return ''

def fetch() -> list[str]:
    raw = request.urlopen(SRC, timeout=30).read().decode(errors='ignore')
    if raw.count('\n') < 2 and B64_OK(raw.strip()):   # base64-подписка
        raw = b64d(raw.strip())
    links = [l.strip() for l in raw.splitlines() if IS_PROTO.match(l)]
    log(f"получено строк: {len(links)}")
    return links

def host_port(link: str) -> tuple[str, int] | None:
    if link.startswith('vmess://'):
        try:
            j = json.loads(b64d(link[8:]))
            return j['add'], int(j['port'])
        except Exception: return None
    u = parse.urlsplit(link)
    return u.hostname, u.port or 0

def is_private(host: str) -> bool:
    try:
        ip = socket.gethostbyname(host)
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

def relay(link: str) -> bool:
    if IS_RELAY.search(link.split('#',1)[0]): return True
    if link.startswith('vmess://'):
        try:  return IS_RELAY.search(json.loads(b64d(link[8:])).get('ps','') ) is not None
        except Exception: pass
    return False

# ────── простой TCP-ping ──────
def tcp_ping(host: str, port: int) -> float | None:
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=SOCK_TO):
            return (time.perf_counter() - t0) * 1000
    except Exception:
        return None

def probe(link: str) -> float | None:
    if relay(link):             return None
    hp = host_port(link)
    if not hp or is_private(hp[0]):   return None

    rtts = []
    for _ in range(TRIES):
        r = tcp_ping(*hp)
        if r is not None: rtts.append(r)
    if len(rtts) < 2:           return None          # требуется ≥2 успешных
    rtt = sum(rtts) / len(rtts)
    if rtt > MAX_RTT:           return None
    return rtt

# ────── гео по IP (ipapi.co) с кэшом ──────
_geo: dict[str,str] = {}
def cc(host: str) -> str:
    try:
        ip = socket.gethostbyname(host)
        if ip in _geo: return _geo[ip]
        code = request.urlopen(f"https://ipapi.co/{ip}/country/", timeout=6).read().decode().strip()
        _geo[ip] = code if len(code)==2 else '__'
        return _geo[ip]
    except Exception:
        return '__'

# ────── main ──────
def main() -> None:
    links = fetch()
    scored, t0 = [], time.time()

    for ln in links:
        if time.time() - t0 > TOTAL_TO:   break
        rtt = probe(ln)
        log(f"{rtt or '∞':>6} ms  {ln[:80]}")
        if rtt is not None:
            scored.append((rtt, ln))

    scored.sort()
    if not scored:
        print("⚠️ 0 пригодных"); return

    csv.writer(CSV.open('w', newline='')).writerows([("rtt_ms","link"), *scored])

    best, used_cc, used_ep = [], set(), set()
    for rtt, ln in scored:
        host, port = host_port(ln)
        if (host, port) in used_ep: continue
        c = cc(host)
        if c not in used_cc:
            best.append(ln)
            used_cc.add(c)
            used_ep.add((host, port))
        if len(best) == MAX_LINKS: break

    TXT.write_text('\n'.join(best) + '\n', encoding='utf-8')
    print(f"✔ сохранено: {len(best)}  |  страны: {', '.join(sorted(used_cc - {'__'}) or ['—'])}")

if __name__ == "__main__":
    main()