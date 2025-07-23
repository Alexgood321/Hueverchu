#!/usr/bin/env python3
"""
Фильтруем публичную подписку V2Ray/VLESS/Trojan.
Берём 20 узлов, прошедших полноценный sing-box probe
(без «RELAY» в имени/комментарии) и пишем их в output/Server.txt.
"""

from __future__ import annotations
import argparse, base64, json, os, re, subprocess, tempfile, textwrap
from pathlib import Path
from urllib import request

# ────────── параметры ───────────────────────────────────────────────────────
DEFAULT_URL = (
    "https://raw.githubusercontent.com/"
    "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"
)
OUTPUT_DIR = Path("output"); OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
OUT_FILE = OUTPUT_DIR / "Server.txt"

MAX_LINKS      = 20
PROBE_TIMEOUT  = 8     # сек. на один sing-box probe
TOTAL_TIMEOUT  = 120   # сек. на весь скрипт

_is_b64  = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_relay   = re.compile(r"relay", re.I)

# ────────── утилиты ─────────────────────────────────────────────────────────
def decode_if_b64(txt: str) -> str:
    if _is_b64(txt.strip()):
        pad = txt + "=" * (-len(txt) % 4)
        try:
            return base64.b64decode(pad).decode(errors="ignore")
        except Exception:
            pass
    return txt

def fetch_list(url: str) -> list[str]:
    raw = request.urlopen(url, timeout=15).read().decode(errors="ignore")
    if raw.count("\n") <= 1 and _is_b64(raw.strip()):
        raw = decode_if_b64(raw)
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]

def looks_like_relay(link: str) -> bool:
    if link.lower().startswith("vmess://") and _is_b64(link[8:]):
        try:
            j = json.loads(decode_if_b64(link[8:]))
            if "ps" in j and _relay.search(j["ps"]):
                return True
        except Exception:
            pass
    if _relay.search(link.split("#", 1)[-1]):
        return True
    return False

def probe(link: str) -> float | None:
    """Возвращает avg_delay (мс) или None."""
    if looks_like_relay(link):
        return None

    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write(link + "\n"); tmp.flush()
        try:
            # новый синтаксис: probe <url>, без --url
            res = subprocess.run(
                ["sing-box", "probe", f"file://{tmp.name}", "--count", "2"],
                capture_output=True, text=True, timeout=PROBE_TIMEOUT
            )
            data = json.loads(res.stdout or "{}")
            return data.get("avg_delay")            # None, если поле отсутствует
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return None
        finally:
            os.unlink(tmp.name)

# ────────── main ────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--output", default=str(OUT_FILE))
    args = ap.parse_args()

    links = fetch_list(args.url)
    print(f"✓ Получено строк: {len(links)}")

    scored: list[tuple[float, str]] = []
    for lk in links:
        if PROBE_TIMEOUT * len(scored) > TOTAL_TIMEOUT:
            break
        d = probe(lk)
        if d is not None:
            scored.append((d, lk))

    if not scored:
        print("⚠️  Ни один узел не прошёл probe — файл Server.txt не обновлён")
        return  # exit 0, чтобы workflow не падал

    best = [lk for _, lk in sorted(scored)[:MAX_LINKS]]
    Path(args.output).write_text("\n".join(best) + "\n", encoding="utf-8")

    print(textwrap.dedent(f"""
        ★ Итог: {len(best)} узлов → {args.output}
        ⏱  ping(min) = {min(scored)[0]:.1f} мс
    """).strip())

if __name__ == "__main__":
    main()