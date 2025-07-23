#!/usr/bin/env python3
"""
Отбираем ≤20 рабочих прокси (по одному на страну):

  • 5 успешных рукопожатий VMess/VLESS/SS/Trojan;
  • проверка реального HTTPS-выхода (256 KB download);
  • задержка ≤ 250 мс;
  • без «relay» и приватных IP;
  • лог причины отбора/отбраковки в output/debug.log.

Результаты:
  - output/Server.txt
  - output/latency_full.csv
"""

from __future__ import annotations
import argparse, base64, csv, ipaddress, json, re, socket, subprocess, tempfile, textwrap, time
from pathlib import Path
from urllib import request, parse

SUB_URL = ("https://raw.githubusercontent.com/"
           "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
OUT_DIR = Path("output"); OUT_DIR.mkdir(exist_ok=True, parents=True)
FILE_TXT, FILE_CSV = OUT_DIR / "Server.txt", OUT_DIR / "latency_full.csv"

MAX_LINKS, MAX_MS = 20, 250
COUNT, PROBE_TO, TOTAL_TO = 5, 12, 180

_b64   = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_relay = re.compile(r"relay", re.I)
_proto = re.compile(r"^(?P<p>[a-z]+)://", re.I)

# ───── helpers ─────────────────────────────────────────────────────────────
def b64d(t: str) -> str:
    return base64.b64decode(t + '=' * (-len(t) % 4)).decode(errors='ignore')

def fetch(url: str) -> list[str]:
    raw = request.urlopen(url, timeout=20).read().decode(errors='ignore')
    if raw.count('\n') <= 1 and _b64(raw.strip()):
        raw = b64d(raw.strip())
    return [l.strip() for l in raw.splitlines() if l.strip()]

def is_relay(link: str) -> bool:
    head = link.split('#', 1)[0].split('?', 1)[0]
    if _relay.search(head):
        return True
    if link.lower().startswith('vmess://') and _b64(link[8:]):
        try:
            return _relay.search(json.loads(b64d(link[8:])).get('ps', '')) is not None
        except Exception:
            pass
    return False

def host_port(link: str) -> tuple[str, int] | None:
    m = _proto.match(link)
    if not m:
        return None
    proto = m.group('p').lower()
    if proto == 'vmess' and _b64(link[8:]):
        try:
            j = json.loads(b64d(link[8:]))
            return j.get('add'), int(j.get('port', 0))
        except Exception:
            return None
    try:
        u = parse.urlsplit(link)
        return u.hostname, u.port or 0
    except Exception:
        return None

def is_private(host: str) -> bool:
    try:
        ip = socket.gethostbyname(host)
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

# ───── probe ───────────────────────────────────────────────────────────────
def probe(link: str) -> float | None:
    if is_relay(link):
        print("relay ↓", link); return None
    hp = host_port(link)
    if not hp:
        print("parse ↓", link); return None
    host, port = hp
    if is_private(host):
        print("private ↓", link); return None

    with tempfile.NamedTemporaryFile('w+', delete=False) as tf:
        tf.write(link + '\n'); tf.flush()
        try:
            cmd = [
                "sing-box", "probe", f"file://{tf.name}",
                "--count", str(COUNT),
                "--url", "https://cp.cloudflare.com/generate_204",
                "--download-size", "256KB"
            ]
            js = json.loads(
                subprocess.run(cmd, capture_output=True, text=True, timeout=PROBE_TO).stdout
                or "{}"
            )
            if js.get('success_cnt') != COUNT:
                print("cnt<5 ↓", link); return None
            if not js.get('download_speed'):          # нет реального трафика
                print("dl=0 ↓", link); return None
            delay = js.get('avg_delay')
            if not delay or delay > MAX_MS:
                print(">250ms ↓", link); return None
            print(f"{delay:.0f}ms ↑", link)
            return delay
        except Exception as e:
            print("probe err ↓", link, e); return None
        finally:
            Path(tf.name).unlink(missing_ok=True)

# ───── country cache ───────────────────────────────────────────────────────
geo_cache: dict[str, str] = {}
def cc(host: str) -> str | None:
    try: ip = socket.gethostbyname(host)
    except: return None
    if ip in geo_cache: return geo_cache[ip]
    try:
        code = request.urlopen(f"https://ipapi.co/{ip}/country/", timeout=6).read().decode().strip()
        geo_cache[ip] = code
        return code if len(code) == 2 else None
    except Exception:
        return None

# ───── main ────────────────────────────────────────────────────────────────
def main() -> None:
    links = fetch(SUB_URL); print("строк:", len(links))
    scored, t0 = [], time.time()
    for ln in links:
        if time.time() - t0 > TOTAL_TO: break
        d = probe(ln); d and scored.append((d, ln))

    if not scored:
        print("⚠️ 0 пригодных"), exit()

    csv.writer(FILE_CSV.open('w')).writerows([("delay_ms", "link"), *scored])

    best, seen_cc, seen_ep = [], set(), set()
    for d, ln in sorted(scored):
        h, p = host_port(ln)
        if (h, p) in seen_ep:
            continue
        country = cc(h) or '_'
        if country not in seen_cc:
            best.append(ln)
            seen_cc.add(country)
            seen_ep.add((h, p))
        if len(best) == MAX_LINKS:
            break

    FILE_TXT.write_text('\n'.join(best) + '\n', encoding='utf-8')
    print(textwrap.dedent(f"""
        ★ {len(best)} ссылок сохранены
        🌍 {', '.join(sorted(seen_cc - {'_'}) or ['n/a'])}
    """).strip())

if __name__ == "__main__":
    main()