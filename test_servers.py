#!/usr/bin/env python3
import argparse, base64, csv, ipaddress, json, re, socket, subprocess, tempfile, textwrap, time
from pathlib import Path
from urllib import request, parse

SUB_URL = ("https://raw.githubusercontent.com/"
           "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
ODIR = Path("output"); ODIR.mkdir(exist_ok=True, parents=True)
F_TXT, F_CSV = ODIR / "Server.txt", ODIR / "latency_full.csv"

MAX_OUT, MAX_MS = 20, 250
COUNT, PROBE_TO, TOTAL_TO = 5, 12, 180

_b64   = re.compile(r"^[A-Za-z0-9+/]+={0,2}$").fullmatch
_relay = re.compile(r"relay", re.I)
_proto = re.compile(r"^(?P<p>[a-z]+)://", re.I)

# ───────────────── helpers ─────────────────
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
            data = json.loads(b64d(link[8:]))
            return data.get('add'), int(data.get('port', 0))
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

# ───────────────── probe ───────────────────
def probe(link: str) -> float | None:
    if is_relay(link):
        print("relay ↓", link)
        return None
    hp = host_port(link)
    if not hp:
        print("parse ↓", link)
        return None
    host, port = hp
    if is_private(host):
        print("private ↓", link)
        return None

    with tempfile.NamedTemporaryFile('w+', delete=False) as tf:
        tf.write(link + '\n'); tf.flush()
        try:
            cmd = ["sing-box", "probe", f"file://{tf.name}",
                   "--count", str(COUNT), "--download-size", "256KB"]
            js = json.loads(subprocess.run(cmd, capture_output=True, text=True,
                                           timeout=PROBE_TO).stdout or "{}")
            if js.get('success_cnt') != COUNT:
                print("cnt<5 ↓", link)
                return None
            d = js.get('avg_delay')
            if not d or d > MAX_MS:
                print(">250ms ↓", link)
                return None
            print(f"{d:.0f}ms ↑", link)
            return d
        except Exception as e:
            print("probe err ↓", link, e)
            return None
        finally:
            os.unlink(tf.name)

geo = {}
def cc(host: str) -> str | None:
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return None
    if ip in geo:
        return geo[ip]
    try:
        code = request.urlopen(f"https://ipapi.co/{ip}/country/", timeout=6).read().decode().strip()
        geo[ip] = code
        return code if len(code) == 2 else None
    except Exception:
        return None

# ───────────────── main ─────────────────────
def main() -> None:
    links = fetch(SUB_URL)
    print("получено:", len(links))

    scored, t0 = [], time.time()
    for link in links:
        if time.time() - t0 > TOTAL_TO:
            print("⏳ общий таймаут"); break
        d = probe(link)
        if d is not None:
            scored.append((d, link))

    if not scored:
        print("⚠️ 0 пригодных"), exit()

    csv.writer(F_CSV.open('w')).writerows([("delay_ms", "link"), *scored])

    best, seen_cc, seen_ep = [], set(), set()
    for d, link in sorted(scored):
        h, p = host_port(link)
        if (h, p) in seen_ep:
            continue
        country = cc(h) or '_'
        if country not in seen_cc:
            best.append(link)
            seen_cc.add(country)
            seen_ep.add((h, p))
        if len(best) == MAX_OUT:
            break

    F_TXT.write_text('\n'.join(best) + '\n', encoding='utf-8')
    print(textwrap.dedent(f"""
        ★ {len(best)} ссылок → {F_TXT}
        🌍 {', '.join(sorted(seen_cc - {'_'}) or ['n/a'])}
    """).strip())

if __name__ == "__main__":
    main()