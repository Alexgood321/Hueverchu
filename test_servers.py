#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр публичных прокси (vless/vmess/trojan/…).

  ▸ URL-источники в --sources (по строке на каждой)
  ▸ режем схемы из --drop-proto и порты из --drop-ports
  ▸ проверяем:
        tcp  – TCP-ping  (3 с timeout)            [по-умолчанию]
        http – скачиваем 100 KiB через прокси,
                скорость ≥ --min-speed kB/s
  ▸ ≤ --max узлов, по одному на страну (--unique-country)
  ▸ если «живых» нет – output/Server.txt перезаписывается пустым
  ▸ лог         → --debug
"""
from __future__ import annotations
import argparse, asyncio, base64, ipaddress, json, re, socket, time
from pathlib import Path

import aiohttp, async_timeout

# ─────────────────────────── CLI ────────────────────────────
cli = argparse.ArgumentParser()
cli.add_argument("--sources", required=True)
cli.add_argument("--output",  required=True)
cli.add_argument("--debug",   required=True)
cli.add_argument("--max", type=int, default=20)
cli.add_argument("--probe", choices=("tcp", "http"), default="tcp")
cli.add_argument("--min-speed", type=int, default=200, help="kB/s, для http-probe")
cli.add_argument("--drop-ports", default="8880")
cli.add_argument("--drop-proto", default="ss,ssr")
cli.add_argument("--unique-country", action="store_true")
args = cli.parse_args()

DROP_PORTS = {int(p) for p in args.drop_ports.split(",") if p}
DROP_PROTO = {p.lower() for p in args.drop_proto.split(",") if p}
MAX_KEEP   = args.max
TEST_URL   = "https://speed.cloudflare.com/__down?bytes=100000"   # ≈100 KiB

URI_RE = re.compile(rb'(vless|vmess|trojan|hysteria2?|socks5?|https?)://[^\s#]+', re.I)

# ───────────────────── helpers ──────────────────────
def b64_try(txt: str) -> str:
    txt = txt.strip()
    if re.fullmatch(r'[A-Za-z0-9+/]+=*', txt) and len(txt) % 4 == 0:
        try:
            return base64.b64decode(txt + '==').decode(errors="ignore")
        except Exception:
            pass
    return txt

def parse_source(text: str) -> list[str]:
    text = b64_try(text)
    return [m.group(0).decode() for m in URI_RE.finditer(text)]

def host_port(uri: str) -> tuple[str,int] | None:
    if uri.startswith("vmess://"):
        try:
            j = json.loads(base64.b64decode(uri[8:].split("#",1)[0] + '=='))
            return j["add"], int(j["port"])
        except Exception:
            return None
    host_port = uri.split("@")[-1].split("?",1)[0].split("#",1)[0]
    if ":" not in host_port: return None
    host, port = host_port.rsplit(":",1)
    try:
        return host, int(port)
    except ValueError:
        return None

async def tcp_ping(host:str, port:int, timeout=3) -> float|None:
    try:
        t0 = time.perf_counter()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        w.close(); await w.wait_closed()
        return (time.perf_counter() - t0) * 1000
    except Exception:
        return None

async def http_speed(proxy_uri:str,
                     sess:aiohttp.ClientSession,
                     min_kB:int) -> float|None:
    """kB/s или None (медленнее min_kB)"""
    try:
        async with async_timeout.timeout(8):
            t0 = time.perf_counter()
            async with sess.get(TEST_URL, proxy=proxy_uri) as r:
                await r.content.readexactly(100_000)
            t = time.perf_counter() - t0
        speed = 100_000/1024 / t if t else 0
        return speed if speed >= min_kB else None
    except Exception:
        return None

_geo: dict[str,str] = {}
async def country(ip:str, sess:aiohttp.ClientSession) -> str:
    if ip in _geo: return _geo[ip]
    try:
        async with async_timeout.timeout(6):
            async with sess.get(f"https://ipapi.co/{ip}/country/") as r:
                code = (await r.text()).strip()
    except Exception:
        code = "__"
    if len(code) != 2: code = "__"
    _geo[ip] = code
    return code

# ───────────────────── main ──────────────────────
async def main():
    dbg  = Path(args.debug);  dbg.parent.mkdir(parents=True, exist_ok=True)
    outf = Path(args.output); outf.parent.mkdir(parents=True, exist_ok=True)
    dbg.write_text("")
    outf.write_text("")

    src_urls = [l.strip() for l in Path(args.sources).read_text().splitlines()
                if l.strip() and not l.lstrip().startswith("#")]

    async with aiohttp.ClientSession() as sess:

        # 1) тянем источники (параллельно)
        async def grab(url:str) -> str:
            try:
                async with async_timeout.timeout(20):
                    async with sess.get(url) as r:
                        return await r.text()
            except Exception:
                return ""

        texts = await asyncio.gather(*(grab(u) for u in src_urls))

        # 2) вытаскиваем URI, первичная фильтрация
        cand = []
        for t in texts:
            cand.extend(parse_source(t))

        filtered = []
        for u in cand:
            proto = u.split("://",1)[0].lower()
            hp = host_port(u)
            if not hp:                 continue
            if proto in DROP_PROTO:    continue
            if hp[1] in DROP_PORTS:    continue
            filtered.append(u)

        # 3) проверяем
        good:list[tuple[float,str]] = []

        async def check(u:str):
            proto = u.split("://",1)[0].lower()
            hp = host_port(u); host,port = hp
            if args.probe == "http" and proto not in {"vmess","vless","trojan"}:
                spd = await http_speed(u, sess, args.min_speed)
                if spd is not None:
                    good.append((1000/spd, u))   # speed → pseudo-latency
            else:
                rtt = await tcp_ping(host, port)
                if rtt is not None:
                    good.append((rtt, u))

        await asyncio.gather(*(check(u) for u in filtered))

        if not good:
            dbg.write_text("0 пригодных\n", encoding="utf8")
            return

        good.sort()

        # 4) по одной стране
        final, used_cc = [], set()
        if args.unique_country:
            for rtt,u in good:
                host,_ = host_port(u)
                try:
                    ip = socket.gethostbyname(host)
                except Exception:
                    continue
                cc = await country(ip, sess)
                if cc not in used_cc:
                    used_cc.add(cc)
                    final.append((rtt,u))
                if len(final) == MAX_KEEP: break
        else:
            final = good[:MAX_KEEP]

        outf.write_text("\n".join(u for _,u in final) + "\n", encoding="utf8")
        dbg.write_text("\n".join(f"{rtt:.0f} {u}" for rtt,u in final) + "\n",
                       encoding="utf8")

if __name__ == "__main__":
    asyncio.run(main())