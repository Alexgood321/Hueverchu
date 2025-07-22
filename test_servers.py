#!/usr/bin/env python3
"""
Фильтруем подписку V2Ray/VLESS/Trojan:
1. Скачиваем текст/базу64 по URL;
2. Извлекаем host, port и факт необходимости TLS;
3. Пингуем (TCP-handshake) + при need_tls завершаем TLS-handshake;
4. Берём 20 самых быстрых, пишем в output/Server.txt.
Дополнительно:
  • skipped.txt     — узлы, не прошедшие проверку;
  • ping_debug.txt  — RTT всех успешных;
  • clashx_pro.yaml — YAML (если установлен PyYAML).

Запуск:
    python test_servers.py --url <url> --output output/Server.txt
Все аргументы опциональны, см. --help.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib import parse, request

# ────────────────────────────── настройки ──────────────────────────────────
DEFAULT_URL = (
    "https://raw.githubusercontent.com/"
    "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"
)
OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
DEFAULT_OUT = OUTPUT_DIR / "Server.txt"

MAX_LINKS = 20
CONNECT_TIMEOUT = 3.0          # сек. на socket.connect
TLS_TIMEOUT = 3.0              # сек. на TLS-handshake
TOTAL_TIMEOUT = 60             # сек. на весь скрипт

# ────────────────────────── вспомогательные regex ──────────────────────────
_is_b64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_proto_re = re.compile(r"^(?P<proto>[a-z]+)://", re.I)

# ────────────────────────────── функции ────────────────────────────────────
def fetch_subscription(url: str) -> list[str]:
    """Скачиваем подписку; если это один base64-блок — декодируем."""
    data = request.urlopen(url, timeout=15).read()
    text = data.decode(errors="ignore")

    if text.count("\n") <= 1 and _is_b64(text.strip()):
        padded = text + "=" * (-len(text) % 4)
        text = base64.b64decode(padded).decode(errors="ignore")

    return [ln.strip() for ln in text.splitlines() if ln.strip()]

def b64_decode_segment(seg: str) -> str:
    padded = seg + "=" * (-len(seg) % 4)
    return base64.b64decode(padded).decode(errors="ignore")

def need_tls_for(link: str) -> bool:
    l = link.lower()
    return (
        "tls=" in l
        or "security=tls" in l
        or link.startswith("trojan://")
        or link.startswith("https://")
    )

def extract_host_port_tls(link: str) -> tuple[str, int, bool] | None:
    """Возвращаем (host, port, is_tls) или None."""
    # пропускаем явные relay-ноды
    if "relay" in link.lower():
        return None

    # sub://<b64>
    if link.startswith("sub://"):
        link = b64_decode_segment(link[6:])

    m = _proto_re.match(link)
    if not m:
        return None

    proto = m.group("proto").lower()

    # vmess://<b64>
    if proto == "vmess" and _is_b64(link[8:]):
        try:
            j = b64_decode_segment(link[8:]).encode()
            host = re.search(rb'"add"\s*:\s*"([^"]+)"', j)
            port = re.search(rb'"port"\s*:\s*"?(?P<p>\d+)"?', j)
            if host and port:
                return host.group(1).decode(), int(port.group("p")), need_tls_for(link)
        except Exception:
            return None

    # обычный URL-парсинг
    parsed = parse.urlsplit(link)
    if parsed.hostname and parsed.port:
        return parsed.hostname, parsed.port, need_tls_for(link)

    # fallback на @host:port
    body = link[link.find("://") + 3 :]
    m2 = re.search(r"@([^:\/]+):(\d+)", body)
    if m2:
        return m2.group(1), int(m2.group(2)), need_tls_for(link)

    return None

_ctx = ssl.create_default_context()
def handshake_ping(host: str, port: int, is_tls: bool) -> float | None:
    """TCP-handshake + (при is_tls) TLS-handshake. Возвращает RTT в мс."""
    t0 = time.time()
    try:
        sock = socket.create_connection((host, port), CONNECT_TIMEOUT)
        if is_tls:
            sock.settimeout(TLS_TIMEOUT)
            sock = _ctx.wrap_socket(sock, server_hostname=host)
        sock.close()
        return (time.time() - t0) * 1000
    except Exception:
        return None

# ────────────────────────────── main ───────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description="Filter fastest proxies")
    ap.add_argument("--url", default=DEFAULT_URL, help="subscription url")
    ap.add_argument("--output", default=str(DEFAULT_OUT), help="txt output file")
    args = ap.parse_args()

    links = fetch_subscription(args.url)
    print(f"✓ Получено строк: {len(links)}")

    # парсим host/port/tls
    hostmap = {
        ln: hp for ln in links if (hp := extract_host_port_tls(ln)) is not None
    }

    latencies: dict[str, float] = {}
    skipped: list[str] = []

    def _probe(item):
        link, (h, p, tls) = item
        return link, handshake_ping(h, p, tls)

    with cf.ThreadPoolExecutor(max_workers=80) as pool:
        futures = [pool.submit(_probe, it) for it in hostmap.items()]
        deadline = time.time() + TOTAL_TIMEOUT
        for fut in cf.as_completed(futures, timeout=TOTAL_TIMEOUT):
            link, rtt = fut.result()
            if rtt is None:
                skipped.append(link)
            else:
                latencies[link] = rtt
            if time.time() > deadline:
                break

    best = sorted(latencies.items(), key=lambda kv: kv[1])[:MAX_LINKS]
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(l for l, _ in best) + "\n", encoding="utf-8")

    # логи
    (OUTPUT_DIR / "skipped.txt").write_text("\n".join(skipped), encoding="utf-8")
    (OUTPUT_DIR / "ping_debug.txt").write_text(
        "\n".join(f"{l} | {lat:.1f} ms" for l, lat in latencies.items()),
        encoding="utf-8",
    )

    # Clash-yaml (если есть PyYAML)
    try:
        import yaml  # noqa: 402
        yaml_data = {
            "proxies": [l for l, _ in best],
            "proxy-groups": [
                {
                    "name": "AUTO",
                    "type": "url-test",
                    "proxies": [l for l, _ in best],
                    "url": "https://cp.cloudflare.com/generate_204",
                    "interval": 300,
                }
            ],
        }
        (OUTPUT_DIR / "clashx_pro.yaml").write_text(
            yaml.dump(yaml_data, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    except ModuleNotFoundError:
        pass

    print(
        f"★ Сохранено: {len(best)} → {out_path}\n"
        f"✗ Пропущено: {len(skipped)}"
    )

# ────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Interrupted by user")