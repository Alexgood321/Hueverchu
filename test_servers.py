#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр публичных прокси-узлов.

Из источников (--sources) вытягиваются URI
(vless / vmess / trojan / hysteria / socks / http):

  • отбрасываем схемы из --drop-proto  (по-умолчанию ss, ssr)
  • отбрасываем узлы на портах --drop-ports  (по-умолчанию 8880)
  • проверка (--probe):
        tcp   – три TCP-connect-ping’а (3 с timeout), средний RTT
        http  – скачиваем 100 KiB через прокси, скорость ≥ --min-speed kB/s
  • --unique-country   – оставляем по одному узлу на страну (по Geo-IP)
  • --max              – итоговое число узлов (по умолчанию 20)

Результаты:
  • output/Server.txt  – рабочие URI
  • output/debug.log   – лог/диагностика
Если пригодных нет – `Server.txt` затирается пустым.

Пример вызова из workflow:
    python test_servers.py \
        --sources sources.txt \
        --output  output/Server.txt \
        --debug   output/debug.log \
        --probe   http \
        --min-speed 200 \
        --drop-ports 8880 \
        --drop-proto ss,ssr \
        --unique-country
"""
from __future__ import annotations
import argparse, asyncio, ipaddress, json, re, socket, time
from base64 import b64decode, urlsafe_b64decode
from pathlib import Path

import aiohttp, async_timeout

# ─────────────────────────── CLI ────────────────────────────
p = argparse.ArgumentParser()
p.add_argument("--sources", required=True, help="файл со списком URL-источников")
p.add_argument("--output",  required=True, help="куда писать Server.txt")
p.add_argument("--debug",   required=True, help="файл подробного лога")
p.add_argument("--max", type=int, default=20, help="максимум узлов")
p.add_argument("--probe", choices=("tcp", "http"), default="tcp")
p.add_argument("--min-speed", type=int, default=200, help="kB/s для http-probe")
p.add_argument("--drop-ports", default="8880")
p.add_argument("--drop-proto", default="ss,ssr")
p.add_argument("--unique-country", action="store_true")
args = p.parse_args()

DROP_PORTS = {int(x) for x in args.drop_ports.split(",") if x}
DROP_PROTO = {x.lower() for x in args.drop_proto.split(",") if x}
MAX_KEEP   = args.max
TEST_URL   = "https://speed.cloudflare.com/__down?bytes=100000"   # ≈100 KiB

URI_RE = re.compile(
    r'(vless|vmess|trojan|hysteria2?|socks5?|https?)://[^\s#]+',
    re.I
)

# ───────────────────────── helpers ──────────────────────────
def _maybe_b64(txt: str) -> str:
    """Попытаться декодировать «голую» подписку (обычн./url-safe base64)."""
    if re.fullmatch(r'[\w\-+/]+=*', txt):
        pad = '=' * (-len(txt) % 4)
        for dec in (b64decode, urlsafe_b64decode):
            try:
                return dec(txt + pad).decode(errors="ignore")
            except Exception:
                pass
    return txt

def parse_source(text: str) -> list[str]:
    """Вернуть список URI из текста источника / подписки."""
    text = _maybe_b64(text.strip())
    return [m.group(0) for m in URI_RE.finditer(text)]

def host_port(uri: str) -> tuple[str, int] | None:
    """Извлечь (host, port) из ссылки; для VMess – из JSON-пейлоуда."""
    if uri.startswith("vmess://"):
        try:
            raw = uri[8:].split("#", 1)[0]
            padding = '=' * (-len(raw) % 4)
            j = json.loads(urlsafe_b64decode(raw + padding))
            return j.get("add"), int(j.get("port", 0))
        except Exception:
            return None
    try:
        host_port = uri.split("@")[-1].split("?", 1)[0].split("#", 1)[0]
        host, port = host_port.rsplit(":", 1)
        return host, int(port)
    except Exception:
        return None

async def tcp_ping(host: str, port: int, timeout=3) -> float | None:
    """Возвращает RTT (мс) или None."""
    try:
        t0 = time.perf_counter()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        w.close(); await w.wait_closed()
        return (time.perf_counter() - t0) * 1000
    except Exception:
        return None

async def http_speed(proxy_uri: str, sess: aiohttp.ClientSession,
                     min_kB: int) -> float | None:
    """kB/s или None, если скорость ниже min_kB."""
    try:
        async with async_timeout.timeout(8):
            t0 = time.perf_counter()
            async with sess.get(TEST_URL, proxy=proxy_uri) as r:
                await r.content.readexactly(100_000)
            speed = 100_000/1024 / (time.perf_counter() - t0)
        return speed if speed >= min_kB else None
    except Exception:
        return None

_geo_cache: dict[str, str] = {}
async def country(ip: str, sess: aiohttp.ClientSession) -> str:
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        async with async_timeout.timeout(6):
            async with sess.get(f"https://ipapi.co/{ip}/country/") as r:
                code = (await r.text()).strip()
    except Exception:
        code = "__"
    if len(code) != 2:
        code = "__"
    _geo_cache[ip] = code
    return code

# ────────────────────────── main ────────────────────────────
async def main() -> None:
    dbg  = Path(args.debug);  dbg.parent.mkdir(parents=True, exist_ok=True)
    outf = Path(args.output); outf.parent.mkdir(parents=True, exist_ok=True)
    dbg.write_text("")          # очистить лог
    outf.write_text("")         # очистить результат

    # 1) URL-источники
    src_urls = [l.strip() for l in Path(args.sources).read_text().splitlines()
                if l.strip() and not l.lstrip().startswith("#")]

    async with aiohttp.ClientSession() as sess:

        async def grab(url: str) -> str:
            try:
                async with async_timeout.timeout(20):
                    async with sess.get(url) as r:
                        return await r.text()
            except Exception:
                return ""

        texts = await asyncio.gather(*(grab(u) for u in src_urls))

        # 2) извлекаем URI + первичная фильтрация
        cand: list[str] = []
        for t in texts:
            cand.extend(parse_source(t))

        pre: list[str] = []
        for u in cand:
            proto = u.split("://", 1)[0].lower()
            hp = host_port(u)
            if not hp:                 continue
            if proto in DROP_PROTO:    continue
            if hp[1] in DROP_PORTS:    continue
            pre.append(u)

        # 3) проверка пригодности
        good: list[tuple[float, str]] = []

        async def check(u: str):
            proto = u.split("://", 1)[0].lower()
            host, port = host_port(u)
            if args.probe == "http" and proto in {"vmess", "vless", "trojan"}:
                spd = await http_speed(u, sess, args.min_speed)
                if spd is not None:
                    good.append((1000 / spd, u))      # speed → псевдо-RTT
            else:
                rtt = await tcp_ping(host, port)
                if rtt is not None and rtt > 0:
                    good.append((rtt, u))

        await asyncio.gather(*(check(u) for u in pre))

        if not good:
            dbg.write_text("⚠️ 0 пригодных\n", encoding="utf8")
            return

        good.sort(key=lambda t: t[0])                  # по «RTT»

        # 4) уникальность по странам
        final: list[str] = []
        if args.unique_country:
            used_cc = set()
            for rtt, u in good:
                host, _ = host_port(u)
                try:
                    ip = socket.gethostbyname(host)
                except Exception:
                    continue
                cc = await country(ip, sess)
                if cc not in used_cc:
                    used_cc.add(cc)
                    final.append(u)
                if len(final) == MAX_KEEP:
                    break
        else:
            final = [u for _, u in good[:MAX_KEEP]]

        outf.write_text("\n".join(final) + ("\n" if final else ""),
                        encoding="utf8")
        dbg.write_text(
            "\n".join(f"{rtt:.0f} ms  {u}" for rtt, u in good),
            encoding="utf8"
        )

if __name__ == "__main__":
    asyncio.run(main())