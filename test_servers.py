#!/usr/bin/env python3
import asyncio, aiohttp, re, base64, sys, pathlib
from datetime import datetime

SOURCE_FILE   = pathlib.Path("sources.txt")
OUTPUT_FILE   = pathlib.Path("output/Server.txt")
DEBUG_LOG     = pathlib.Path("output/debug.log")
TIMEOUT       = aiohttp.ClientTimeout(total=8)          # сек на полный запрос
PORT_BLACKLIST = {"8880"}
PROTO_BLACKLIST = ("ss://",)                            # Shadowsocks

URI_RGX   = re.compile(r'(?:vless|vmess|trojan|hysteria2?)://[^ \n]+', re.I)
B64_RGX   = re.compile(r'base64:([A-Za-z0-9+/=]+)')

async def fetch_text(session, url):
    try:
        async with session.get(url, timeout=TIMEOUT) as r:
            return await r.text()
    except Exception as exc:
        return f"# ERR {exc}"

def decode_possible_b64(txt):
    for m in B64_RGX.finditer(txt):
        try:
            dec = base64.b64decode(m.group(1)).decode()
            txt = txt.replace(m.group(0), dec)
        except Exception:
            pass
    return txt

def filter_uri(uri: str) -> bool:
    if uri.lower().startswith(PROTO_BLACKLIST):
        return False
    # порт
    m = re.search(r':(\d+)', uri)
    if m and m.group(1) in PORT_BLACKLIST:
        return False
    return True

async def test_uri(uri: str) -> bool:
    """Очень упрощённая проверка – пытаемся открыть TCP-порт."""
    from asyncio import open_connection
    m = re.search(r'@([^:/]+):(\d+)', uri)
    if not m:                                   # если не нашли host:port
        return False
    host, port = m.group(1), int(m.group(2))
    try:
        r, w = await asyncio.wait_for(open_connection(host, port), 3)
        w.close(); await w.wait_closed()
        return True
    except Exception:
        return False

async def main():
    OUTPUT_FILE.parent.mkdir(exist_ok=True)
    OUTPUT_FILE.write_text("")                  # обнуляем файл каждой итерации

    sources = SOURCE_FILE.read_text().strip().splitlines()
    stamp   = datetime.utcnow().isoformat(timespec="seconds")
    dbg     = [f"{stamp} sources: {len(sources)}"]

    async with aiohttp.ClientSession() as sess:
        raw_txts = await asyncio.gather(*(fetch_text(sess, s) for s in sources))
    all_text   = "\n".join(raw_txts)
    all_text   = decode_possible_b64(all_text)

    uris = [u for u in URI_RGX.findall(all_text) if filter_uri(u)]
    dbg.append(f"total URI after filter: {len(uris)}")

    good = []
    for ok, uri in zip(await asyncio.gather(*(test_uri(u) for u in uris)), uris):
        if ok: good.append(uri)

    OUTPUT_FILE.write_text("\n".join(good))
    dbg.append(f"good URI: {len(good)}")

    DEBUG_LOG.write_text("\n".join(dbg))
    print("\n".join(dbg))

if __name__ == "__main__":
    asyncio.run(main())