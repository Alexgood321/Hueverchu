#!/usr/bin/env python3
"""
Фильтрация подписки V2Ray/VLESS/Trojan:

1. sing-box probe (count=3) для каждой ссылки.
2. Отбрасываем:
   • RELAY-узлы (по всей строке до '#', а также по полю ps для vmess);
   • задержку > 250 мс;
   • probe-ошибки.
3. Сортируем, берём ≤20 узлов, по одному на страну (ISO-2) и без дубликатов хоста.
4. Сохраняем:
   • output/Server.txt       — итог;
   • output/latency_full.csv — delay,link для проверки.
"""

from __future__ import annotations
import argparse, base64, csv, json, os, re, socket, subprocess, tempfile, textwrap, time
from pathlib import Path
from urllib import request, parse

# ───── настройки ───────────────────────────────────────────────────────────
DEFAULT_URL = ("https://raw.githubusercontent.com/"
               "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
OUTPUT_DIR  = Path("output"); OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
OUT_FILE    = OUTPUT_DIR / "Server.txt"
CSV_FILE    = OUTPUT_DIR / "latency_full.csv"

MAX_FINAL   = 20          # сколько ссылок выдаём
DELAY_LIMIT = 250         # мс — всё медленнее игнорируем
PROBE_CNT   = 3
PROBE_TO    = 10          # сек на один probe
TOTAL_TO    = 180         # сек на скрипт

_is_b64  = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_relay   = re.compile(r"relay", re.I)
_url_re  = re.compile(r"^(?P<proto>[a-z]+)://", re.I)

# ───── util ────────────────────────────────────────────────────────────────
def b64d(txt: str) -> str:
    return base64.b64decode(txt + "=" * (-len(txt) % 4)).decode("utf-8", "ignore")

def fetch_sub(url: str) -> list[str]:
    raw = request.urlopen(url, timeout=15).read().decode("utf-8", "ignore")
    if raw.count("\n") <= 1 and _is_b64(raw.strip()):
        raw = b64d(raw.strip())
    return [l.strip() for l in raw.splitlines() if l.strip()]

def looks_like_relay(link: str) -> bool:
    if _relay.search(link.split("#", 1)[0]):          # проверяем всё до комментария
        return True
    if link.lower().startswith("vmess://") and _is_b64(link[8:]):
        try:
            ps = json.loads(b64d(link[8:])).get("ps", "")
            return _relay.search(ps) is not None
        except Exception:
            pass
    return False

def probe(link: str) -> float | None:
    if looks_like_relay(link):
        return None
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write(link + "\n"); tmp.flush()
        try:
            res = subprocess.run(
                ["sing-box", "probe", f"file://{tmp.name}", "--count", str(PROBE_CNT)],
                capture_output=True, text=True, timeout=PROBE_TO
            )
            data = json.loads(res.stdout or "{}")
            delay = data.get("avg_delay")
            if not data.get("success") or delay is None or delay > DELAY_LIMIT:
                return None
            return delay
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return None
        finally:
            os.unlink(tmp.name)

def host_from(link: str) -> str | None:
    m = _url_re.match(link)
    if not m:
        return None
    proto = m.group("proto").lower()
    if proto == "vmess" and _is_b64(link[8:]):
        try: return json.loads(b64d(link[8:])).get("add")
        except Exception: return None
    try: return parse.urlsplit(link).hostname
    except Exception: return None

GEO_CACHE: dict[str, str] = {}
def country(host: str) -> str | None:
    try: ip = socket.gethostbyname(host)
    except socket.gaierror: return None
    if ip in GEO_CACHE: return GEO_CACHE[ip]
    try:
        cc = request.urlopen(f"https://ipapi.co/{ip}/country/", timeout=5).read().decode().strip()
        GEO_CACHE[ip] = cc
        return cc if len(cc) == 2 else None
    except Exception:
        return None

# ───── main ────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--output", default=str(OUT_FILE))
    args = ap.parse_args()

    links = fetch_sub(args.url)
    print(f"✓ получено строк: {len(links)}")

    scored, t0 = [], time.time()
    for ln in links:
        if time.time() - t0 > TOTAL_TO:
            print("⏳ превысили общий таймаут, стоп."); break
        d = probe(ln);  d and scored.append((d, ln))

    if not scored:
        print("⚠️ ни один узел не прошёл probe — файл не обновлён"); return

    # полный CSV-лог
    with CSV_FILE.open("w", newline="") as f:
        csv.writer(f).writerows([("delay_ms", "link"), *scored])

    best, used_cc, used_host = [], set(), set()
    for d, ln in sorted(scored):
        h = host_from(ln)
        if h in used_host:
            continue
        cc = country(h) or "_"
        if cc not in used_cc:
            best.append(ln); used_cc.add(cc); used_host.add(h)
        if len(best) == MAX_FINAL:
            break

    if len(best) < MAX_FINAL:                 # добиваем, если стран < 20
        for _, ln in sorted(scored):
            if ln not in best:
                best.append(ln)
                if len(best) == MAX_FINAL: break

    Path(args.output).write_text("\n".join(best) + "\n", encoding="utf-8")

    print(textwrap.dedent(f"""
        ★ сохранено {len(best)} узлов → {args.output}
        🌍 страны: {', '.join(sorted(c for c in used_cc if c != '_')) or 'n/a'}
        ⏱ min = {min(scored, key=lambda t: t[0])[0]:.1f} мс
    """).strip())

if __name__ == "__main__":
    main()