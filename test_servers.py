#!/usr/bin/env python3
# coding: utf-8
"""
Фильтруем супер-подписку до 20 рабочих узлов (не relay, ≤400 мс, по-одному на страну).
Логи — output/debug.log, результаты — output/Server.txt и latency_full.csv
"""

from __future__ import annotations
import argparse, base64, csv, ipaddress, json, re, socket, subprocess, tempfile, textwrap, time
from pathlib import Path
from urllib import request, parse

SRC = ("https://raw.githubusercontent.com/"
       "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
OUT = Path("output"); OUT.mkdir(exist_ok=True, parents=True)
TXT, CSV = OUT / "Server.txt", OUT / "latency_full.csv"

MAX_LINKS, MAX_MS = 20, 400
COUNT, MIN_OK, PROBE_TO, TOTAL_TO = 3, 2, 15, 240   # ← поменяли!

B64_OK = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
IS_PROTO = re.compile(r"^(vless|vmess|trojan|ss)://", re.I)
IS_RELAY = re.compile(r"relay", re.I)

def b64d(s: str) -> str:
    return base64.b64decode(s + '=' * (-len(s) % 4)).decode(errors='ignore')

def fetch() -> list[str]:
    raw = request.urlopen(SRC, timeout=30).read().decode(errors='ignore')
    if raw.count('\n') <= 1 and B64_OK(raw.strip()):
        raw = b64d(raw.strip())
    # пропускаем комментарии/метаданные
    return [l.strip() for l in raw.splitlines()
            if IS_PROTO.match(l.strip())]

def host_port(link: str) -> tuple[str, int] | None:
    if link.startswith('vmess://'):
        try:
            j = json.loads(b64d(link[8:]))
            return j.get('add'), int(j.get('port', 0))
        except Exception:
            return None
    u = parse.urlsplit(link)
    return u.hostname, u.port or 0

def is_private(host: str) -> bool:
    try:
        info = socket.getaddrinfo(host, None)[0][4][0]
        return ipaddress.ip_address(info).is_private
    except Exception:
        return False          # DNS-ошибка ≠ приватный IP

def relay(link: str) -> bool:
    if IS_RELAY.search(link.split('#', 1)[0]):
        return True
    if link.startswith('vmess://'):
        try:
            return IS_RELAY.search(json.loads(b64d(link[8:])).get('ps', '')) is not None
        except Exception:
            pass
    return False

# ─── probe ──────────────────────────────────────────────────────────
def probe(link: str) -> float | None:
    if relay(link):                      return None
    hp = host_port(link)
    if not hp or is_private(hp[0]):      return None

    with tempfile.NamedTemporaryFile('w+', delete=False) as tf:
        tf.write(link + '\n'); tf.flush()
        try:
            cmd = ["sing-box", "probe", f"file://{tf.name}",
                   "--count", str(COUNT),
                   "--url", "https://cp.cloudflare.com/generate_204",
                   "--download-size", "256KB"]
            js = json.loads(subprocess.run(
                     cmd, capture_output=True, text=True,
                     timeout=PROBE_TO).stdout or "{}")
            if js.get('success_cnt', 0) < MIN_OK:   return None
            delay = js.get('avg_delay')
            if not delay or delay > MAX_MS:         return None
            return delay
        except Exception:
            return None
        finally:
            Path(tf.name).unlink(missing_ok=True)

# ─── гео-кэш ────────────────────────────────────────────────────────
_geo: dict[str, str] = {}
def cc(host: str) -> str | None:
    try:
        ip = socket.gethostbyname(host)
        if ip in _geo: return _geo[ip]
        code = request.urlopen(f"https://ipapi.co/{ip}/country/",
                               timeout=6).read().decode().strip()
        _geo[ip] = code if len(code) == 2 else '_'
        return _geo[ip]
    except Exception:
        return '_'

# ─── main ───────────────────────────────────────────────────────────
def main() -> None:
    links = fetch(); print("Получено строк:", len(links))
    scored, t0 = [], time.time()
    for ln in links:
        if time.time() - t0 > TOTAL_TO: break
        d = probe(ln); d and scored.append((d, ln))

    if not scored:
        print("⚠️ 0 пригодных"); return

    csv.writer(CSV.open('w')).writerows([("delay_ms", "link"), *scored])

    best, used_cc, used_ep = [], set(), set()
    for d, ln in sorted(scored):
        h, p = host_port(ln)
        if (h, p) in used_ep: continue
        c = cc(h)
        if c not in used_cc:
            best.append(ln); used_cc.add(c); used_ep.add((h, p))
        if len(best) == MAX_LINKS: break

    TXT.write_text('\n'.join(best) + '\n', encoding='utf-8')
    print(textwrap.dedent(f"""
        ✔ {len(best)} ссылок сохранены
        🌐 страны: {', '.join(sorted(used_cc - {'_'}) or ['—'])}
    """).strip())

if __name__ == "__main__":
    main()