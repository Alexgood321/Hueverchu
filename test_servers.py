#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтруем super-sub:
  • берём только публичные узлы (vless/vmess/trojan/ss)
  • TCP-ping: ≥ 2 успешных, средний RTT ≤ 400 мс
  • исключаем relay-узлы, порты 8880 и протоколы ss/ssr
  • не более одного узла на страну
Результат → output/Server.txt   + latency.csv + debug.log
"""

from __future__ import annotations
import argparse, base64, csv, ipaddress, json, os, re, socket, sys, time, asyncio
from pathlib import Path
from urllib import request, parse
import aiohttp                       # requirements.txt: aiohttp  python-whois

###############################################################################
# ─── аргументы CLI ───────────────────────────────────────────────────────────
###############################################################################

parser = argparse.ArgumentParser(prog="test_servers.py")
parser.add_argument("--sources", required=True, help="файл со списком URL")
parser.add_argument("--output",  default="output/Server.txt")
parser.add_argument("--debug",   default="output/debug.log")
parser.add_argument("--probe",   choices=("tcp", "http"), default="tcp")
parser.add_argument("--min-succ", type=int, default=2)
parser.add_argument("--max-rtt",  type=int, default=400)
parser.add_argument("--min-speed", type=int, default=0)     # KiB/s (только для http)
parser.add_argument("--drop-ports", default="")
parser.add_argument("--drop-proto", default="ss,ssr")
parser.add_argument("--tries", type=int, default=3)
parser.add_argument("--max",   type=int, default=20)
parser.add_argument("--unique-country", action="store_true")

###############################################################################
# ─── константы / регэкспы ────────────────────────────────────────────────────
###############################################################################

IS_PROTO = re.compile(r"^(vless|vmess|trojan|ss)://", re.I)
IS_RELAY = re.compile(r"relay", re.I)
URI_RE   = re.compile(rb"(?:vless|vmess|trojan|ss)://[^\s]+")
B64_OK   = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch

MAX_RTT   = 400
SOCK_TO   = 3
TOTAL_TO  = 240

###############################################################################
# ─── util-функции ────────────────────────────────────────────────────────────
###############################################################################

def b64d(s: str) -> str:
    try:   return base64.b64decode(s + "===").decode()
    except Exception: return ""

def host_port(link: str) -> tuple[str, int] | None:
    if link.startswith("vmess://"):
        try:
            j = json.loads(b64d(link[8:]))
            return j["add"], int(j["port"])
        except Exception:
            return None
    u = parse.urlsplit(link)
    return u.hostname, u.port or 0

def relay(link: str) -> bool:
    if IS_RELAY.search(link.split("#", 1)[0]): return True
    if link.startswith("vmess://"):
        try:
            return IS_RELAY.search(json.loads(b64d(link[8:])).get("ps", "")) is not None
        except Exception:
            pass
    return False

def is_private(host: str) -> bool:
    try:
        ip = socket.gethostbyname(host)
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

###############################################################################
# ─── TCP ping ────────────────────────────────────────────────────────────────
###############################################################################

def tcp_ping(host: str, port: int) -> float | None:
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=SOCK_TO):
            return (time.perf_counter() - t0) * 1000
    except Exception:
        return None

async def http_speed(sess: aiohttp.ClientSession, url: str) -> float | None:
    """Качаем 256 KiB и считаем скорость (KiB/s)."""
    try:
        t0 = time.perf_counter()
        async with sess.get(url, timeout=15) as r:
            blob = await r.content.read(262_144)
            if len(blob) < 262_144:
                return None
        dt = time.perf_counter() - t0
        return 256 / dt
    except Exception:
        return None

###############################################################################
# ─── чтение источников ───────────────────────────────────────────────────────
###############################################################################

async def parse_source(url: str) -> list[str]:
    async with aiohttp.ClientSession() as sess:
        async with sess.get(url, timeout=30) as r:
            raw = await r.read()
    if raw.count(b"\n") < 2 and B64_OK(raw.strip().decode(errors="ignore")):
        raw = base64.b64decode(raw.strip() + b"===")
    return [m.decode() for m in URI_RE.findall(raw)]

def read_sources_file(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

###############################################################################
# ─── main ────────────────────────────────────────────────────────────────────
###############################################################################

def main() -> None:
    args = parser.parse_args()

    # ── подготовка путей ───────────────────────────────────
    out_txt = Path(args.output)
    out_txt.parent.mkdir(parents=True, exist_ok=True)
    global DBG
    DBG = Path(args.debug)
    DBG.unlink(missing_ok=True)
    dbg = DBG.open("w", encoding="utf-8", buffering=1)
    log = lambda *a: print(*a, file=dbg, flush=True)

    # ── читаем URL-ы для скачивания ────────────────────────
    urls = read_sources_file(args.sources)
    if not urls:
        print("⚠️  sources.txt пуст"); return

    cand: list[str] = []
    asyncio.run(_fill_candidates(urls, cand, log))

    if not cand:
        print("⚠️  0 ссылок со всех источников"); return

    # ── фильтруем / измеряем ───────────────────────────────
    scored, t0 = [], time.time()
    for ln in cand:
        if time.time() - t0 > TOTAL_TO: break
        if relay(ln):                  continue
        hp = host_port(ln)
        if not hp or is_private(hp[0]): continue
        if str(hp[1]) in args.drop_ports.split(","): continue
        if ln.split("://",1)[0] in args.drop_proto.split(","): continue

        if args.probe == "tcp":
            rtts = [tcp_ping(*hp) for _ in range(args.tries)]
            rtts = [r for r in rtts if r is not None]
            if len(rtts) < args.min_succ: continue
            rtt = sum(rtts) / len(rtts)
            if rtt > args.max_rtt: continue
            scored.append((rtt, ln))

        else:  # http probe
            spd = asyncio.run(_http_probe(ln, args.min_speed))
            if spd: scored.append((1000/spd, ln))      # меньший rtt = выше скорость

    if not scored:
        print("⚠️ 0 пригодных"); return
    scored.sort()

    # ── выбираем best N ────────────────────────────────────
    best, used_cc, used_ep = [], set(), set()
    for rtt, ln in scored:
        host, port = host_port(ln)
        if (host, port) in used_ep: continue
        if args.unique_country:
            code = cc(host)
            if code in used_cc: continue
            used_cc.add(code)
        best.append(ln); used_ep.add((host, port))
        if len(best) == args.max: break

    out_txt.write_text("\n".join(best) + "\n", encoding="utf-8")
    print(f"✔ сохранено: {len(best)}  |  страны: {', '.join(sorted(used_cc) or ['—'])}")

async def _fill_candidates(urls: list[str], cand: list[str], log) -> None:
    async with aiohttp.ClientSession() as sess:
        tasks = [sess.get(u, timeout=30) for u in urls]
        for task, url in zip(asyncio.as_completed(tasks), urls):
            try:
                resp = await task
                raw  = await resp.read()
                links = [m.decode() for m in URI_RE.findall(raw)]
                log(f"✔ {url} — {len(links)} ссылок")
                cand.extend(links)
            except Exception as e:
                log(f"✖ {url} — {e}")

async def _http_probe(link: str, min_speed: int) -> float | None:
    hp = host_port(link)
    if not hp: return None
    host, port = hp
    url = f"http://{host}:{port}"
    async with aiohttp.ClientSession() as sess:
        spd = await http_speed(sess, url)
        if spd and spd >= min_speed: return spd
    return None

# ─── гео-кэш ──────────────────────────────────────────────
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

if __name__ == "__main__":
    main()