#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтрует подписки с прокси-серверами, проверяет доступность
и сохраняет пригодные ссылки в output/Server.txt

Изменения 2025-07-23
--------------------
* always truncate output/Server.txt (empty file when 0 servers)
* drop all Shadowsocks-family links (ss://, ssr:// …)
"""
from __future__ import annotations

import argparse
import asyncio
import pathlib
import re
import sys
import textwrap
from typing import Iterable

import aiohttp

# ----------------------------------------------------------------------
ALLOWED_SCHEMES = {"vmess", "vless", "trojan",
                   "hysteria", "hysteria2",
                   "tuic", "vlessh2", "vlessh3"}          # ♦ Shadowsocks убран
DENIED_PORTS = {8880}                                     # задаётся также из YAML

URL_RE = re.compile(r'([a-z0-9]+)://[^\s\'"<>]+', re.I)

# ----------------------------------------------------------------------
async def fetch_text(session: aiohttp.ClientSession, url: str) -> str:
    async with session.get(url, timeout=20) as resp:
        resp.raise_for_status()
        return await resp.text()


def iter_urls(text: str) -> Iterable[str]:
    """вернёт все ссылки из произвольного текста"""
    for m in URL_RE.finditer(text):
        yield m.group(0)


def is_allowed(url: str) -> bool:
    """фильтр схем и портов"""
    scheme, rest = url.split("://", 1)
    scheme = scheme.lower()

    if scheme not in ALLOWED_SCHEMES:
        return False

    # грубый порт-парсер: ...:PORT? или ...:PORT#
    m = re.search(r':(\d{2,5})(?:[/?#]|$)', rest)
    if m and int(m.group(1)) in DENIED_PORTS:
        return False
    return True


async def probe(session: aiohttp.ClientSession, url: str) -> bool:
    """
    Простейший «пинг»: TCP-connect + сразу закрываем.
    Для vmess/vless не аутентифицируемся — нам достаточно,
    что порт открыт и SYN/ACK получен.
    """
    scheme, rest = url.split("://", 1)
    host_port = rest.split("@")[-1] if "@" in rest else rest
    host, _, port = host_port.partition(":")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, int(port), ssl=False), timeout=3)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def collect_good(sources: list[str]) -> list[str]:
    good: list[str] = []
    async with aiohttp.ClientSession() as session:
        texts = await asyncio.gather(*(fetch_text(session, u) for u in sources),
                                     return_exceptions=True)

        # ➊ из всех текстов достаём ссылки, ➋ первичный фильтр
        candidates = [u for txt in texts if isinstance(txt, str)
                      for u in iter_urls(txt) if is_allowed(u)]

        # ➌ проверяем доступность параллельно, но ограничим ↯
        sem = asyncio.Semaphore(200)

        async def _checked(u: str):
            async with sem:
                if await probe(session, u):
                    good.append(u)

        await asyncio.gather(*(_checked(u) for u in candidates))
    return good


# ----------------------------------------------------------------------
def parse_cli() -> argparse.Namespace:
    p = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent("""\
            Пример:
              python test_servers.py --sources sources.txt --output output/Server.txt
        """))
    p.add_argument("--sources", required=True, help="файл с перечнем URL-источников")
    p.add_argument("--output",  required=True, help="куда сохранить пригодные ссылки")
    p.add_argument("--debug",   help="отладочный лог (опц.)")
    return p.parse_args()


def main() -> None:
    ns = parse_cli()

    src_path = pathlib.Path(ns.sources)
    if not src_path.is_file():
        sys.exit(f"[ERR] файл {src_path} не найден")

    sources = [ln.strip() for ln in src_path.read_text().splitlines() if ln.strip()]
    print(f"➜ sources.txt — добавлено {len(sources)} ссылок")

    good = asyncio.run(collect_good(sources))
    print(f"✓ пригодных: {len(good)}")

    out_path = pathlib.Path(ns.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(good))      # ← **полная перезапись / truncate**

    if ns.debug:
        pathlib.Path(ns.debug).write_text(
            "\n".join(good) or "0 пригодных — см. логи фильтра\n")

    # non-zero exit when nothing found → GitHub Actions покажет «Failure»
    sys.exit(0 if good else 1)


if __name__ == "__main__":
    main()