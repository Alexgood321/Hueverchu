#!/usr/bin/env python3
"""
Скачиваем подписку (base64), проверяем доступность всех узлов,
выбираем 20 самых быстрых и сохраняем в output/Server.txt.
Дополнительно пишем:
  • skipped.txt     — мёртвые узлы
  • ping_debug.txt  — latency всех проверенных
  • clashx_pro.yaml — готовый YAML (если понадобился)
Запуск:
    python test_servers.py --url <url> --output output/Server.txt
Все параметры опциональны, см. --help.
"""

from __future__ import annotations
import argparse, base64, concurrent.futures, os, re, socket, sys, time
from pathlib import Path
from urllib import parse, request

# ---------- Параметры по-умолчанию ----------
DEFAULT_URL = (
    "https://raw.githubusercontent.com/"
    "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"
)
OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
DEFAULT_OUT = OUTPUT_DIR / "Server.txt"

MAX_LINKS = 20          # итоговое количество
CONNECT_TIMEOUT = 3.0   # сек. на socket.connect
TOTAL_TIMEOUT = 40      # сек. на весь скрипт

# ---------- Утилиты ----------
_is_b64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_proto_re = re.compile(r"^(?P<proto>[a-z]+)://")

def fetch_subscription(url: str) -> list[str]:
    """Скачиваем файл и, если нужно, раскодируем base64."""
    data = request.urlopen(url, timeout=15).read()
    text = data.decode(errors="ignore")

    # Если файл — одна длинная b64-строка, раскодируем
    if text.count("\n") <= 1 and _is_b64(text.strip()):
        missing = -len(text) % 4
        text = base64.b64decode(text + "=" * missing).decode(errors="ignore")

    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return lines

def extract_host_port(link: str) -> tuple[str, int] | None:
    """Извлекаем host:port из vmess/vless/trojan/ss/…"""
    try:
        # ссылка могла быть sub://<b64>, тогда сначала декодируем
        if link.startswith("sub://"):
            missing = -len(link[6:]) % 4
            link = base64.b64decode(link[6:] + "=" * missing).decode()
        m = _proto_re.match(link)
        if not m:
            return None
        url_part = link  # для urllib
        # vmess может быть vmess://<b64>
        if m.group("proto") == "vmess" and _is_b64(link[8:]):
            json_txt = base64.b64decode(link[8:] + "=" * (-len(link[8:]) % 4))
            host = re.search(rb'"add"\s*:\s*"([^"]+)"', json_txt)
            port = re.search(rb'"port"\s*:\s*"?(?P<port>\d+)"?', json_txt)
            if host and port:
                return host.group(1).decode(), int(port.group("port"))
            return None
        parsed = parse.urlsplit(url_part)
        host = parsed.hostname
        port = parsed.port
        if host and port:
            return host, port
        # fallback на regex
        rem = link[link.find("://") + 3 :]
        m2 = re.search(r"@([^:]+):(\d+)", rem)
        if m2:
            return m2.group(1), int(m2.group(2))
    except Exception:
        return None
    return None

def tcp_ping(host: str, port: int) -> float | None:
    """Возвращает RTT в мс или None."""
    start = time.time()
    try:
        with socket.create_connection((host, port), CONNECT_TIMEOUT):
            return (time.time() - start) * 1000
    except Exception:
        return None

# ---------- Основная логика ----------
def main():
    parser = argparse.ArgumentParser(description="Filter fastest proxies")
    parser.add_argument("--url", default=DEFAULT_URL, help="subscription url")
    parser.add_argument(
        "--output", default=str(DEFAULT_OUT), help="output txt for Shadowrocket"
    )
    args = parser.parse_args()

    links = fetch_subscription(args.url)
    print(f"✓ Получено строк: {len(links)}")

    hostmap: dict[str, tuple[str, int]] = {}
    for l in links:
        hp = extract_host_port(l)
        if hp:
            hostmap[l] = hp

    latencies: dict[str, float] = {}
    skipped: list[str] = []

    def _probe(item):
        link, (h, p) = item
        rtt = tcp_ping(h, p)
        return link, rtt

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        futures = [pool.submit(_probe, it) for it in hostmap.items()]
        end = time.time() + TOTAL_TIMEOUT
        for fut in concurrent.futures.as_completed(futures, timeout=TOTAL_TIMEOUT):
            link, rtt = fut.result()
            if rtt is None:
                skipped.append(link)
            else:
                latencies[link] = rtt
            if time.time() > end:
                break

    # ---------- сохраняем ----------
    best = sorted(latencies.items(), key=lambda kv: kv[1])[:MAX_LINKS]
    out_file = Path(args.output)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(l for l, _ in best) + "\n", encoding="utf-8")

    (OUTPUT_DIR / "skipped.txt").write_text("\n".join(skipped), encoding="utf-8")
    (OUTPUT_DIR / "ping_debug.txt").write_text(
        "\n".join(f"{l} | {lat:.1f} ms" for l, lat in latencies.items()), encoding="utf-8"
    )

    # mini-yaml для Clash/ClashX (по желанию)
    try:
        import yaml  # noqa: 402
        clash_yaml = {
            "proxies": [link for link, _ in best],
            "proxy-groups": [
                {
                    "name": "AUTO",
                    "type": "url-test",
                    "proxies": [link for link, _ in best],
                    "url": "https://cp.cloudflare.com/generate_204",
                    "interval": 300,
                }
            ],
        }
        (OUTPUT_DIR / "clashx_pro.yaml").write_text(
            yaml.dump(clash_yaml, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    except ModuleNotFoundError:
        pass

    print(
        f"★ Сохранено: {len(best)} лучших → {out_file.relative_to(Path.cwd())}\n"
        f"✗ Пропущено: {len(skipped)}"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Interrupted by user")