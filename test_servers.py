#!/usr/bin/env python3
"""
Фильтруем публичную подписку V2Ray/VLESS/Trojan.

Алгоритм:
1) sing-box probe (count=3) для всех ссылок;
2) отбрасываем, если success:false, avg_delay>250 мс или «RELAY» в имени;
3) сортируем по задержке;
4) выбираем ≤20 узлов, по одному на страну (ISO-2), запрашивая country
   через ipapi.co/<ip>/country/ (free 45k req/day на GitHub-runner);
5) сохраняем:
      • output/Server.txt         — итоговый список;
      • output/latency_full.csv   — delay,link для всех успешных.

Запуск локально:
    python test_servers.py --url <url> --output output/Server.txt
"""

from __future__ import annotations
import argparse, base64, csv, json, os, re, socket, subprocess, tempfile, textwrap, time
from pathlib import Path
from urllib import request, parse

# ───── настройки ────────────────────────────────────────────────────────────
DEFAULT_URL = ("https://raw.githubusercontent.com/"
               "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
OUTPUT_DIR = Path("output"); OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
OUT_FILE = OUTPUT_DIR / "Server.txt"
CSV_FILE = OUTPUT_DIR / "latency_full.csv"

MAX_FINAL   = 20          # итоговое число узлов
DELAY_LIMIT = 250         # мс – всё, что медленнее, игнорируем
PROBE_CNT   = 3
PROBE_TO    = 10          # cек. на один probe
TOTAL_TO    = 180         # cек. на весь скрипт

_is_b64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_relay  = re.compile(r"relay", re.I)
_url_re = re.compile(r"^(?P<proto>[a-z]+)://", re.I)

# ───── вспомогательные функции ──────────────────────────────────────────────
def b64_decode(txt: str) -> str:
    padded = txt + "=" * (-len(txt) % 4)
    return base64.b64decode(padded).decode(errors="ignore")

def fetch_subscription(url: str) -> list[str]:
    raw = request.urlopen(url, timeout=15).read().decode(errors="ignore")
    if raw.count("\n") <= 1 and _is_b64(raw.strip()):
        raw = b64_decode(raw.strip())
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]

def looks_like_relay(link: str) -> bool:
    if _relay.search(link.split("#", 1)[-1]):        # комментарий
        return True
    if link.lower().startswith("vmess://") and _is_b64(link[8:]):
        try:
            ps = json.loads(b64_decode(link[8:])).get("ps", "")
            if _relay.search(ps):
                return True
        except Exception:
            pass
    return False

def probe_delay(link: str) -> float | None:
    """sing-box probe, возвращает avg_delay в мс или None."""
    if looks_like_relay(link):
        return None
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write(link + "\n"); tmp.flush()
        try:
            res = subprocess.run(
                ["sing-box", "probe", f"file://{tmp.name}",
                 "--count", str(PROBE_CNT)],
                capture_output=True, text=True, timeout=PROBE_TO
            )
            data = json.loads(res.stdout or "{}")
            if not data.get("success"):
                return None
            d = data.get("avg_delay")
            if d is None or d > DELAY_LIMIT:
                return None
            return d
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return None
        finally:
            os.unlink(tmp.name)

# быстрый извлекатель host из ссылки
def extract_host(link: str) -> str | None:
    m = _url_re.match(link)
    if not m:
        return None
    proto = m.group("proto").lower()
    if proto == "vmess" and _is_b64(link[8:]):
        try:
            return json.loads(b64_decode(link[8:])).get("add")
        except Exception:
            return None
    try:
        u = parse.urlsplit(link)
        return u.hostname
    except Exception:
        return None

GEO_CACHE: dict[str,str] = {}
def country_code(host: str) -> str | None:
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        c = request.urlopen(f"https://ipapi.co/{ip}/country/", timeout=5).read().decode().strip()
        GEO_CACHE[ip] = c
        return c if len(c) == 2 else None
    except Exception:
        return None

# ───── main ────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--output", default=str(OUT_FILE))
    args = ap.parse_args()

    links = fetch_subscription(args.url)
    print(f"✓ Получено строк: {len(links)}")

    scored: list[tuple[float,str]] = []
    t_start = time.time()

    for link in links:
        if time.time() - t_start > TOTAL_TO:
            print("⏳ Истек общий таймаут, останавливаемся.")
            break
        d = probe_delay(link)
        if d is not None:
            scored.append((d, link))

    if not scored:
        print("⚠️  Ни один узел не прошёл probe — Server.txt не трогаем.")
        return

    # сохраняем полный CSV
    with CSV_FILE.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["delay_ms", "link"])
        writer.writerows(scored)

    # отбор по странам
    best: list[str] = []
    used_countries: set[str] = set()
    for delay, link in sorted(scored):
        host = extract_host(link)
        cc = country_code(host) if host else None
        if cc and cc not in used_countries:
            best.append(link); used_countries.add(cc)
        if len(best) == MAX_FINAL:
            break

    # если <20 стран – добиваем оставшимися быстрыми
    if len(best) < MAX_FINAL:
        for _, link in sorted(scored):
            if link not in best:
                best.append(link)
                if len(best) == MAX_FINAL:
                    break

    Path(args.output).write_text("\n".join(best)+"\n", encoding="utf-8")

    print(textwrap.dedent(f"""
        ★ Сохранено {len(best)} узлов → {args.output}
        🌍 Страны: {', '.join(sorted(used_countries)) or 'unknown'}
        ⏱  самый быстрый = {min(scored)[0]:.1f} мс
    """).strip())

if __name__ == "__main__":
    main()