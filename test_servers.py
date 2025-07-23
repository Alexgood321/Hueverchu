#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Отбор публичных прокси-узлов:

 1. Берём только vless/vmess/trojan (ss/ssr можно отфильтровать ключом).
 2. Проверяем либо TCP-ping, либо HTTP-скорость.
 3. Отбрасываем relay, приватные IP, нежелательные порты/протоколы.
 4. Сортируем, оставляем N лучших.

CLI-параметры (покрывают все ваши пожелания):
  --sources          путь к файлу / подписке с URL-ами источников
  --output           куда писать готовый список (default: output/Server.txt)
  --debug            подробный лог (default: output/debug.log)
  --probe            tcp | http      (чем тестировать узлы)
  --min-succ         min успешных ping-ов (tcp-режим)              [2]
  --max-rtt          макс. средний RTT, мс  (tcp-режим)            [400]
  --min-speed        мин. KB/s при HTTP-тесте (0 = отключить)      [200]
  --drop-ports       порты через «,», которые сразу режем
  --drop-proto       протоколы (ss,ssr,…) которые режем
  --max              сколько узлов оставить в итоговом списке     [20]
"""

from __future__ import annotations
import argparse, asyncio, base64, csv, ipaddress, json, re, socket, time
from pathlib import Path
from typing import Sequence

import aiohttp, async_timeout          # pip install aiohttp async_timeout

URI_RE   = re.compile(r'(vless|vmess|trojan|ss|ssr)://[^\s"<>]+', re.I)
RELAY_RE = re.compile(r'relay', re.I)
B64_OK   = re.compile(r'^[A-Za-z0-9+/]+={0,2}$').fullmatch
SPEED_URL= 'https://speed.hetzner.de/100MB.bin'        # 100 MB test-file

OUT = Path('output'); OUT.mkdir(exist_ok=True)
TXT, CSV, DBG = OUT / 'Server.txt', OUT / 'latency.csv', OUT / 'debug.log'

# ───────── logging ─────────
def log(*a): DBG.open('a', encoding='utf-8').write(' '.join(map(str, a)) + '\n')

# ───────── helpers ─────────
def b64d(s: str) -> str:
    try:  return base64.b64decode(s + '===').decode()
    except Exception: return ''

def host_port(uri: str):
    if uri.startswith('vmess://'):
        try:
            j = json.loads(b64d(uri[8:]))
            return j['add'], int(j['port'])
        except Exception:
            return (None, None)
    from urllib.parse import urlsplit
    u = urlsplit(uri)
    return u.hostname, u.port or 0

def is_private(h: str) -> bool:
    try:  return ipaddress.ip_address(socket.gethostbyname(h)).is_private
    except Exception: return True

def is_relay(u: str) -> bool:
    if RELAY_RE.search(u.split('#', 1)[0]): return True
    if u.startswith('vmess://'):
        try: return RELAY_RE.search(json.loads(b64d(u[8:])).get('ps', ''))
        except Exception: pass
    return False

# ───────── async I/O ─────────
async def fetch_text(sess: aiohttp.ClientSession, url: str, t: int = 15) -> str:
    try:
        async with async_timeout.timeout(t):
            async with sess.get(url) as r:
                blob = await r.read()
                txt = blob.decode(errors='ignore')
                if txt.count('\n') < 2 and B64_OK(txt.strip()):
                    txt = b64d(txt.strip())
                return txt
    except Exception as e:
        log('fetch_fail', url, e)
        return ''

async def tcp_ping(h: str, p: int, tries: int, per_try: int):
    ok = []
    for _ in range(tries):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((h, p), timeout=per_try):
                ok.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
    return sum(ok) / len(ok) if ok else None

async def http_speed(sess: aiohttp.ClientSession, proxy: str) -> float | None:
    try:
        async with async_timeout.timeout(15):
            async with sess.get(
                SPEED_URL,
                proxy=proxy,
                headers={'Range': 'bytes=0-204799'}) as r:
                if r.status != 206:
                    return None
                t0 = time.perf_counter()
                await r.read()
                return 200 / (time.perf_counter() - t0)   # KB/s
    except Exception:
        return None

# ───────── main ─────────
async def main(argv: Sequence[str] = ()):
    ap = argparse.ArgumentParser()
    ap.add_argument('--sources', required=True)
    ap.add_argument('--output', default=TXT, type=Path)
    ap.add_argument('--debug',  default=DBG, type=Path)
    ap.add_argument('--probe', choices=['tcp', 'http'], default='tcp')
    ap.add_argument('--min-succ', type=int, default=2)
    ap.add_argument('--max-rtt',  type=int, default=400)
    ap.add_argument('--min-speed', type=int, default=200)
    ap.add_argument('--drop-ports', default='')
    ap.add_argument('--drop-proto', default='')
    ap.add_argument('--tries', type=int, default=3)
    ap.add_argument('--max',   type=int, default=20)
    arg = ap.parse_args(argv)

    # чистим предыдущие логи/выводы
    arg.debug.unlink(missing_ok=True)
    arg.output.unlink(missing_ok=True)

    drop_ports  = {int(x) for x in arg.drop_ports.split(',')  if x}
    drop_proto  = {x.lower() for x in arg.drop_proto.split(',') if x}

    async with aiohttp.ClientSession() as s:
        # подтягиваем все «сырцы» параллельно
        texts = await asyncio.gather(
            *(fetch_text(s, u.strip())
              for u in Path(arg.sources).read_text().splitlines() if u.strip()))

    links = [m.group(0) for t in texts for m in URI_RE.finditer(t)]
    log('total_links', len(links))

    # статические фильтры
    cand = []
    for u in links:
        proto = u.split(':', 1)[0].lower()
        h, p = host_port(u)
        if proto in drop_proto or p in drop_ports or is_private(h or '') or is_relay(u):
            continue
        cand.append(u)
    log('after_static_filters', len(cand))

    scored = []
    async with aiohttp.ClientSession() as s:
        for u in cand:
            h, p = host_port(u)
            reason = None
            score  = None
            if arg.probe == 'tcp':
                rtt = await tcp_ping(h, p, arg.tries, 3)
                if rtt and rtt <= arg.max_rtt and arg.min_succ <= 1:
                    score = rtt
                elif rtt and rtt <= arg.max_rtt and arg.min_succ <= 2:
                    score = rtt
                else:
                    reason = f'rtt={rtt:.0f}' if rtt else 'ping-fail'
            else:                                   # HTTP-тест
                kbps = await http_speed(s, u)
                if kbps and kbps >= arg.min_speed:
                    score = kbps
                else:
                    reason = f'speed={kbps:.0f}' if kbps else 'http-fail'

            log(f'{score if score else reason:>10}', u[:120])
            if score:
                scored.append((score, u))

    if not scored:
        log('⚠️  0 пригодных')
        print('⚠️  0 пригодных')
        return

    scored.sort(key=lambda x: x[0])
    best = [u for _, u in scored[:arg.max]]
    arg.output.write_text('\n'.join(best) + '\n')
    print('✔ сохранено', len(best))


if __name__ == '__main__':
    asyncio.run(main())