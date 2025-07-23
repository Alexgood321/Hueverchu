#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Собирает подписки из:
  • зашитого списка SOURCES;
  • файла sources.txt (одна ссылка на строку, # — комментарии);
  • аргументов командной строки (дополнительно).

Фильтрует URI:
  • схема vmess / vless / trojan / ss / ssr / hysteria / hysteria2;
  • PORT ∉ BLOCKED_PORTS  (по умолчанию 8880);
  • тестирует TCP-ping, оставляет TOP_N самых быстрых.

Результат → output/Server.txt, полный лог → output/debug.log
"""

from __future__ import annotations
import asyncio, base64, re, socket, sys, time
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

# ——— настройки ——————————————————————————————————————————— #
TOP_N          = 20          # сколько лучших сохранить
CONCURRENCY    = 400         # одновременных ping'ов
BLOCKED_PORTS  = {8880}      # здесь можно добавить другие порты
HTTP_TIMEOUT   = aiohttp.ClientTimeout(total=30)

SOURCES: list[str] = [
    # «умолчания» — можно убрать или оставить:
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/README.md",
]

# ——— рабочие файлы/директории ———————————————————————— #
ROOT        = Path(__file__).resolve().parent
OUTPUT_DIR  = ROOT / "output"; OUTPUT_DIR.mkdir(exist_ok=True)
SERVER_FILE = OUTPUT_DIR / "Server.txt"
DEBUG_FILE  = OUTPUT_DIR / "debug.log"

URI_RX  = re.compile(rb'\b([a-zA-Z][\w.+-]+://[^\s"\'<>]+)')
SCHEMES = {"vmess", "vless", "trojan", "ss", "ssr", "hysteria", "hysteria2"}


# ——— вспомогательные функции —————————————————————————— #
def debug(msg: str) -> None:
    line = f"{time.strftime('%H:%M:%S')}  {msg}"
    print(line, flush=True)
    DEBUG_FILE.write_text(DEBUG_FILE.read_text() + line + "\n" if DEBUG_FILE.exists() else line + "\n")


def is_b64(txt: str) -> bool:
    txt = txt.strip()
    return len(txt) % 4 == 0 and re.fullmatch(r'[A-Za-z0-9+/=]+', txt) is not None


def decode_subscription(data: str) -> list[str]:
    if is_b64(data):
        try:
            data = base64.b64decode(data + '===').decode(errors='ignore')
        except Exception:
            return []
    return [l.strip() for l in data.splitlines()
            if l.strip() and l.split('://',1)[0].lower() in SCHEMES]


async def fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    async with session.get(url) as r:
        r.raise_for_status()
        return await r.text()


async def download_all(urls: list[str]) -> str:
    async with aiohttp.ClientSession(timeout=HTTP_TIMEOUT) as s:
        tasks = [fetch_text(s, u) for u in urls]
        texts = await asyncio.gather(*tasks, return_exceptions=True)

    blob = ""
    for u, t in zip(urls, texts):
        if isinstance(t, Exception):
            debug(f"⚠️  {u} — {t}")
        else:
            debug(f"✔ {u} — {len(t):,} симв.")
            blob += t + "\n"
    return blob


def extract_uris(blob: str | bytes) -> list[str]:
    if isinstance(blob, str):
        blob = blob.encode()
    seen, uris = set(), []
    for m in URI_RX.finditer(blob):
        uri = m.group(1).decode(errors='ignore')
        scheme = uri.split('://',1)[0].lower()
        if scheme in SCHEMES and uri not in seen:
            seen.add(uri); uris.append(uri)
    return uris


def host_port(uri: str) -> tuple[str,int] | None:
    try:
        p = urlparse(uri)
        port = p.port or (443 if p.scheme in {'vless','trojan','hysteria','hysteria2'} else 80)
        return p.hostname, port
    except Exception:
        return None


async def tcp_ping(host: str, port: int, timeout: float = 3.0) -> float | None:
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.close(); await writer.wait_closed()
        return (time.perf_counter() - t0) * 1000
    except Exception:
        return None


async def score(uri: str, sem: asyncio.Semaphore) -> tuple[str,float|None]:
    hp = host_port(uri);  None if hp else None
    if not hp: return uri, None
    host, port = hp
    if port in BLOCKED_PORTS:
        return uri, None
    async with sem:
        rtt = await tcp_ping(host, port)
    return uri, rtt


async def ping_all(uris: list[str]) -> list[tuple[str,float]]:
    sem = asyncio.Semaphore(CONCURRENCY)
    coros = [score(u, sem) for u in uris]
    results = []
    for f in asyncio.as_completed(coros):
        uri, rtt = await f
        if rtt is not None:
            results.append((uri, rtt))
            debug(f"{rtt:5.0f} мс  {uri[:90]}")
    return sorted(results, key=lambda x: x[1])


def save(best: list[str]) -> None:
    SERVER_FILE.write_text("\n".join(best)+'\n', encoding='utf-8')
    debug(f"💾 сохранено {len(best)} URI → {SERVER_FILE}")


# ——— главная функция ———————————————————————————————— #
def main(extra: list[str]) -> None:
    # дополняем SOURCES содержимым sources.txt
    txt = Path("sources.txt")
    if txt.exists():
        extra_urls = [l.strip() for l in txt.read_text().splitlines()
                      if l.strip() and not l.lstrip().startswith('#')]
        SOURCES.extend(extra_urls)
        debug(f"📄 sources.txt — добавлено {len(extra_urls)} ссылок")

    SOURCES.extend(extra)

    if not SOURCES:
        sys.exit("❌ нет источников подписок")

    blob = asyncio.run(download_all(SOURCES))
    uris = extract_uris(blob)
    debug(f"Всего URI: {len(uris)}")

    scored = asyncio.run(ping_all(uris))
    if not scored:
        sys.exit("❌ пригодных 0")

    best = [u for u, _ in scored[:TOP_N]]
    save(best)

    debug(f"✔ готово: {len(best)} лучших ссылок, min ping {scored[0][1]:.0f} мс")


# ——— точка входа ————————————————————————————————————————— #
if __name__ == "__main__":
    try:
        main(sys.argv[1:])       # аргументы = дополнительные URL/файлы
    except KeyboardInterrupt:
        debug("Прервано пользователем")