#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтруем подписки:
  • публичные vless/vmess/trojan (ss и ssr исключены)
  • RTT ≤ 400 мс (3 TCP-пинга, нужно ≥2 попадания)
  • исключаем relay-узлы и порты 8880
  • не более одного узла на страну
  • максимальный размер итогового списка — 20
  • при --probe http пытаемся скачать 200 КБ с https://speed.hetzner.de/100MB.bin
    — если средняя скорость < 200 КБ/с, узел отбрасываем
Результаты:  output/Server.txt, output/latency.csv, output/debug.log
"""

from __future__ import annotations
import argparse, async_timeout, aiohttp, base64, csv, ipaddress, json
import os, re, socket, sys, time, urllib.parse
from pathlib import Path
from typing import Iterable, Sequence

URI_RE      = re.compile(r'(vless|vmess|trojan)://[^\s"<>]+', re.I)
RELAY_RE    = re.compile(r'relay', re.I)
B64_OK_RE   = re.compile(r'^[A-Za-z0-9+/]+={0,2}$').fullmatch
SPEED_TEST  = 'https://speed.hetzner.de/100MB.bin'   # 100 МБ файл, качаем 200 КБ

OUT = Path('output'); OUT.mkdir(exist_ok=True)
TXT, CSV, DBG = OUT / 'Server.txt', OUT / 'latency.csv', OUT / 'debug.log'

def log(line: str, *, end: str = '\n') -> None:
    DBG.open('a', encoding='utf-8').write(line + end)

# ───── base64 helpers ──────────────────────────
def b64d(s: str) -> str:
    try:
        return base64.b64decode(s + '===').decode()
    except Exception:
        return ''

# ───── tiny sync utils ─────────────────────────
def host_port(link: str) -> tuple[str, int] | None:
    if link.startswith('vmess://'):
        try:
            j = json.loads(b64d(link[8:]))
            return j['add'], int(j['port'])
        except Exception:
            return None
    u = urllib.parse.urlsplit(link)
    return u.hostname, u.port or 0

def is_private_host(host: str) -> bool:
    try:
        ip = socket.gethostbyname(host)
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

def is_relay(link: str) -> bool:
    if RELAY_RE.search(link.split('#',1)[0]):  # быстрая проверка строки
        return True
    if link.startswith('vmess://'):
        try:
            if RELAY_RE.search(json.loads(b64d(link[8:])).get('ps', '')):
                return True
        except Exception:
            pass
    return False

# ───── async helpers ───────────────────────────
async def fetch_text(session: aiohttp.ClientSession, url: str, *, timeout: int = 15) -> str:
    try:
        async with async_timeout.timeout(timeout):
            async with session.get(url) as r:
                blob = await r.read()
                txt  = blob.decode(errors='ignore')
                # подписка может быть base64
                if txt.count('\n') < 2 and B64_OK_RE(txt.strip()):
                    txt = b64d(txt.strip())
                return txt
    except Exception as e:
        log(f'⚠️  fetch fail {url}: {e}')
        return ''

async def tcp_ping(host: str, port: int, *, tries: int, timeout: int) -> float | None:
    times: list[float] = []
    for _ in range(tries):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                times.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
    if len(times) < 2:
        return None
    return sum(times) / len(times)

async def http_probe(session: aiohttp.ClientSession, link: str, min_speed: int) -> bool:
    """Скачиваем первые 200 КБ файла и считаем скорость (КБ/с)."""
    host, _ = host_port(link)
    if not host:
        return False
    proxy_url = link.strip()
    connector = aiohttp.TCPConnector(ssl=False)
    try:
        async with session.get(SPEED_TEST, proxy=proxy_url,
                               headers={'Range': 'bytes=0-204799'},
                               timeout=15, connector=connector) as r:
            if r.status != 206:
                return False
            t0 = time.perf_counter()
            _ = await r.read()          # 200 КБ
            speed = 200 / (time.perf_counter() - t0)  # КБ/с
            return speed >= min_speed
    except Exception:
        return False
    finally:
        await connector.close()

# ───── main ────────────────────────────────────
async def main(argv: Sequence[str] = sys.argv[1:]) -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--sources', required=True, help='файл со списками-источниками (по одному URL в строке)')
    p.add_argument('--output',  default=TXT, type=Path)
    p.add_argument('--debug',   default=DBG, type=Path)
    p.add_argument('--max',     type=int, default=20)
    p.add_argument('--probe',   choices=['tcp','http'], default='tcp')
    p.add_argument('--drop-ports', default='8880')
    p.add_argument('--drop-proto', default='ss,ssr')
    p.add_argument('--unique-country', action='store_true')
    p.add_argument('--min-speed', type=int, default=200, help='КБ/с для HTTP-probe')
    args = p.parse_args(argv)

    # сохраняем имя debug-файла (чтобы workflow мог его прочесть)
    global DBG; DBG = Path(args.debug); DBG.unlink(missing_ok=True)

    drop_ports  = {int(x) for x in args.drop_ports.split(',') if x}
    drop_proto  = {x.lower() for x in args.drop_proto.split(',') if x}

    # ─ fetch all sources ─
    async with aiohttp.ClientSession() as sess:
        tasks = [fetch_text(sess, u.strip()) for u in Path(args.sources).read_text().splitlines() if u.strip()]
        raw_sources = await asyncio.gather(*tasks)

    links: list[str] = []
    for src_txt in raw_sources:
        links.extend(m.group(0) for m in URI_RE.finditer(src_txt))

    log(f'получено строк: {len(links)}')

    # ─ preliminary filtering ─
    cand: list[str] = []
    for ln in links:
        scheme = ln.split('://',1)[0].lower()
        h, p_ = host_port(ln) or (None, None)
        if (scheme in drop_proto or p_ in drop_ports or is_private_host(h or '') or is_relay(ln)):
            continue
        cand.append(ln)

    if not cand:
        log('⚠️ 0 кандидатов после предварительного фильтра'); args.output.write_text('')
        print('⚠️ 0 пригодных'); return

    # ─ probe RTT/скорость ─
    scored: list[tuple[float,str]] = []
    async with aiohttp.ClientSession() as sess:
        for ln in cand:
            h, p_ = host_port(ln)
            if not h: continue
            rtt = await tcp_ping(h, p_, tries=3, timeout=3) if args.probe=='tcp' \
                  else (0 if await http_probe(sess, ln, args.min_speed) else None)
            log(f'{f"{rtt:.0f}" if rtt else "∞":>4}  {ln[:120]}')
            if rtt is not None and rtt <= 400:
                scored.append((rtt, ln))

    if not scored:
        log('⚠️ 0 пригодных'); args.output.write_text('')
        print('⚠️ 0 пригодных'); return

    scored.sort()
    used_cc, used_ep, best = set(), set(), []

    for rtt, ln in scored:
        h, p_ = host_port(ln)
        if (h,p_) in used_ep: continue
        cc = '??'
        if args.unique_country:
            try: cc = (await aiohttp.ClientSession().get(f'https://ipapi.co/{socket.gethostbyname(h)}/country/')).text
            except Exception: pass
            if cc in used_cc: continue
            used_cc.add(cc)
        best.append(ln); used_ep.add((h,p_))
        if len(best) == args.max: break

    args.output.write_text('\n'.join(best) + '\n')
    print(f'✔ сохранено: {len(best)} | страны: {", ".join(sorted(used_cc)) or "—"}')

if __name__ == '__main__':
    import asyncio, asyncio.events
    asyncio.run(main())