#!/usr/bin/env python3
"""
Фильтруем подписку: берём 20 узлов, которые
* проходят полноценный sing-box probe (vmess/vless/trojan/ss/…),
* не содержат «RELAY» в псевдониме,
и пишем их в output/Server.txt.
"""

from __future__ import annotations
import argparse, base64, json, os, re, subprocess, tempfile, textwrap
from pathlib import Path
from urllib import request

# ───── настройки ────────────────────────────────────────────────────────────
DEFAULT_URL = (
    "https://raw.githubusercontent.com/"
    "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"
)
OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
OUT_FILE = OUTPUT_DIR / "Server.txt"

MAX_LINKS = 20
PROBE_TIMEOUT = 8        # секунд на sing-box probe одного узла
TOTAL_TIMEOUT = 120      # секунд на весь скрипт

# ───── вспомогательные функции ──────────────────────────────────────────────
_is_b64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch

def decode_if_b64(txt: str) -> str:
    if _is_b64(txt.strip()):
        padded = txt + "=" * (-len(txt) % 4)
        try:
            return base64.b64decode(padded).decode(errors="ignore")
        except Exception:
            return txt
    return txt

def fetch_list(url: str) -> list[str]:
    raw = request.urlopen(url, timeout=15).read().decode(errors="ignore")
    if raw.count("\n") <= 1 and _is_b64(raw.strip()):
        raw = decode_if_b64(raw)
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]

_relay = re.compile(r"relay", re.I)
def looks_like_relay(link: str) -> bool:
    # vmess://<b64> → смотрим ps в JSON
    if link.lower().startswith("vmess://") and _is_b64(link[8:]):
        try:
            j = json.loads(decode_if_b64(link[8:]))
            if "ps" in j and _relay.search(j["ps"]):
                return True
        except Exception:
            pass
    # комментарий после #
    hash_part = link.split("#", 1)[-1]
    return bool(_relay.search(hash_part))

def probe(link: str) -> float | None:
    """возвращает avg_delay (ms) или None"""
    if looks_like_relay(link):
        return None
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write(link + "\n")
        tmp.flush()
        try:
            res = subprocess.run(
                ["sing-box", "probe", "--url", f"file://{tmp.name}", "--count", "2"],
                capture_output=True, text=True, timeout=PROBE_TIMEOUT
            )
            data = json.loads(res.stdout or "{}")
            return data.get("avg_delay")
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return None
        finally:
            os.unlink(tmp.name)

# ───── основная логика ──────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description="Filter proxies via sing-box probe")
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--output", default=str(OUT_FILE))
    args = ap.parse_args()

    links = fetch_list(args.url)
    print(f"✓ Получено строк: {len(links)}")

    scored: list[tuple[float, str]] = []
    for lk in links:
        if PROBE_TIMEOUT * len(scored) > TOTAL_TIMEOUT * 1000:
            break
        delay = probe(lk)
        if delay is not None:
            scored.append((delay, lk))

    best = [lk for _, lk in sorted(scored, key=lambda x: x[0])[:MAX_LINKS]]
    Path(args.output).write_text("\n".join(best) + "\n", encoding="utf-8")
    print(textwrap.dedent(f"""
        ★ Итог: {len(best)} лучших узлов → {args.output}
        ⏱  Минимальный ping: {min(scored)[0]:.1f} мс
    """).strip())

if __name__ == "__main__":
    main()