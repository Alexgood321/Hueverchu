#!/usr/bin/env python3
"""
Фильтрация подписки: полноценный sing-box probe, срез >250 мс, отбраковка
RELAY, выбор ≤20 узлов (по одному на страну). Сохранение результатов
и полного CSV-лога для проверки.
"""

from __future__ import annotations
import argparse, base64, csv, json, os, re, socket, subprocess, tempfile, textwrap, time
from pathlib import Path
from urllib import request, parse

# ───── константы ───────────────────────────────────────────────────────────
DEFAULT_URL = ("https://raw.githubusercontent.com/"
               "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
OUTPUT_DIR  = Path("output"); OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
OUT_FILE    = OUTPUT_DIR / "Server.txt"
CSV_FILE    = OUTPUT_DIR / "latency_full.csv"

MAX_FINAL   = 20
DELAY_LIMIT = 250    # мс
PROBE_CNT   = 3
PROBE_TO    = 10     # сек/узел
TOTAL_TO    = 180    # сек/скрипт

_is_b64  = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_relay   = re.compile(r"relay", re.I)
_url_re  = re.compile(r"^(?P<proto>[a-z]+)://", re.I)

# ───── helpers ─────────────────────────────────────────────────────────────
def b64_decode(txt: str) -> str:
    return base64.b64decode(txt + "=" * (-len(txt) % 4)).decode(errors="ignore")

def fetch_sub(url: str) -> list[str]:
    raw = request.urlopen(url, timeout=15).read().decode(errors="ignore")
    if raw.count("\n") <= 1 and _is_b64(raw.strip()):
        raw = b64_decode(raw.strip())
    return [l.strip() for l in raw.splitlines() if l.strip()]

def looks_like_relay(link: str) -> bool:
    if _relay.search(link.split("#", 1)[-1]):
        return True
    if link.lower().startswith("vmess://") and _is_b64(link[8:]):
        try:
            return _relay.search(json.loads(b64_decode(link[8:])).get("ps", "")) is not None
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
            d = data.get("avg_delay")
            if not data.get("success") or d is None or d > DELAY_LIMIT:
                return None
            return d
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return None
        finally:
            os.unlink(tmp.name)

def host_from(link: str) -> str | None:
    m = _url_re.match(link)
    if not m: return None
    proto = m.group("proto").lower()
    if proto == "vmess" and _is_b64(link[8:]):
        try: return json.loads(b64_decode(link[8:])).get("add")
        except Exception: return None
    try: return parse.urlsplit(link).hostname
    except Exception: return None

GEO: dict[str, str] = {}
def country(host: str) -> str | None:
    try: ip = socket.gethostbyname(host)
    except socket.gaierror: return None
    if ip in GEO: return GEO[ip]
    try:
        cc = request.urlopen(f"https://ipapi.co/{ip}/country/", timeout=5).read().decode().strip()
        GEO[ip] = cc
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
    print(f"✓ Получено строк: {len(links)}")

    scored, t0 = [], time.time()
    for ln in links:
        if time.time() - t0 > TOTAL_TO:
            print("⏳ Превышен общий таймаут, остановка."); break
        d = probe(ln);  d and scored.append((d, ln))

    if not scored:
        print("⚠️  Нет пригодных узлов — файл не изменён."); return

    # полный CSV
    with CSV_FILE.open("w", newline="") as f:
        csv.writer(f).writerows([("delay_ms", "link"), *scored])

    best, used = [], set()
    for d, ln in sorted(scored):
        cc = country(host_from(ln) or "") or "_"
        if cc not in used:
            best.append(ln); used.add(cc)
        if len(best) == MAX_FINAL: break
    if len(best) < MAX_FINAL:
        for _, ln in sorted(scored):
            if ln not in best:
                best.append(ln)
                if len(best) == MAX_FINAL: break

    Path(args.output).write_text("\n".join(best) + "\n", encoding="utf-8")
    print(textwrap.dedent(f"""
        ★ Сохранено {len(best)} узлов → {args.output}
        🌍 Страны: {', '.join(sorted(used - {'_'})) or 'n/a'}
        ⏱ min = {min(scored)[0]:.1f} мс
    """).strip())

if __name__ == "__main__":
    main()