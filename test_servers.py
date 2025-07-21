import urllib.request
import base64
import re
import socket
import time
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import yaml
from concurrent.futures import ThreadPoolExecutor
import json
import argparse
import os

MAX_PING = 150
MAX_PROXY_COUNT = 20

def get_timestamp():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

def decode_base64_if_sub(line, debug_log):
    if line.startswith("sub://"):
        encoded = line[6:].strip()
        try:
            decoded = base64.b64decode(encoded + "==").decode("utf-8")
            debug_log.append(f"[{get_timestamp()}] ✅ Base64 decoded: {len(decoded.splitlines())} lines")
            return decoded.splitlines()
        except Exception as e:
            debug_log.append(f"[{get_timestamp()}] ❌ Decode error: {str(e)}")
            return []
    return [line]

def extract_host_port(line, debug_log):
    try:
        clean_line = re.split(r"[?#]", line)[0]
        parsed = urlparse(clean_line)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            match = re.search(r"@([^\s:]+):(\d+)", clean_line)
            if match:
                host, port = match.groups()
                port = int(port)
        return (host, port) if host and port else (None, None)
    except Exception as e:
        debug_log.append(f"[{get_timestamp()}] ❌ Host/Port extract error: {str(e)}")
        return None, None

def check_server(host, port, timeout=5, retries=1):
    for attempt in range(retries + 1):
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            latency = (time.time() - start) * 1000
            return True, latency
        except:
            time.sleep(1)
    return False, 0

def convert_to_clash_format(line, debug_log):
    try:
        if line.startswith("vmess://"):
            raw = base64.b64decode(line[8:] + "==").decode("utf-8")
            j = json.loads(raw)
            return {
                "name": f"vmess-{j['add']}-{j['port']}",
                "type": "vmess",
                "server": j["add"],
                "port": int(j["port"]),
                "uuid": j["id"],
                "network": j.get("net", "tcp"),
                "tls": j.get("tls", "false") == "true"
            }
        elif line.startswith("trojan://"):
            parsed = urlparse(line)
            return {
                "name": f"trojan-{parsed.hostname}-{parsed.port}",
                "type": "trojan",
                "server": parsed.hostname,
                "port": parsed.port,
                "password": parsed.username,
                "tls": True
            }
        elif line.startswith("vless://"):
            parsed = urlparse(line)
            q = parse_qs(parsed.query)
            return {
                "name": f"vless-{parsed.hostname}-{parsed.port}",
                "type": "vless",
                "server": parsed.hostname,
                "port": parsed.port,
                "uuid": parsed.username,
                "network": q.get("type", ["tcp"])[0],
                "tls": "tls" in q.get("security", [""])[0]
            }
    except Exception as e:
        debug_log.append(f"[{get_timestamp()}] ❌ Format conversion error: {str(e)}")
    return None

def main(url):
    debug_log = [f"[{get_timestamp()}] 🚀 Starting scan..."]
    raw_proxies = []
    decoded = []
    working = []
    skipped = []
    yaml_proxies = []

    # Download
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            raw_proxies = r.read().decode().splitlines()
        debug_log.append(f"[{get_timestamp()}] ✅ Downloaded {len(raw_proxies)} entries")
    except Exception as e:
        debug_log.append(f"[{get_timestamp()}] ❌ Download error: {str(e)}")
        return save_all([], [], [], debug_log)

    # Decode
    for line in raw_proxies:
        decoded.extend(decode_base64_if_sub(line, debug_log))

    debug_log.append(f"[{get_timestamp()}] 🔍 Total decoded: {len(decoded)} lines")

    # Extract
    proxies_to_check = []
    for line in decoded:
        host, port = extract_host_port(line, debug_log)
        if host and port:
            proxies_to_check.append((line, host, port))
        else:
            skipped.append(line)
            debug_log.append(f"[{get_timestamp()}] ⚠️ Skipped line (bad format): {line[:60]}...")

    # Check
    for line, host, port in proxies_to_check:
        alive, latency = check_server(host, port)
        if alive and latency < MAX_PING:
            working.append((line, latency))
            debug_log.append(f"[{get_timestamp()}] ✅ Alive {host}:{port} - {latency:.1f}ms")
        else:
            skipped.append(line)
            debug_log.append(f"[{get_timestamp()}] ❌ Dead {host}:{port}")

    # Sort
    working.sort(key=lambda x: x[1])
    best = [line for line, _ in working[:MAX_PROXY_COUNT]]

    # Convert
    for proxy_line in best:
        conf = convert_to_clash_format(proxy_line, debug_log)
        if conf:
            yaml_proxies.append(conf)

    # Final log
    debug_log.append(f"[{get_timestamp()}] ✅ Working: {len(working)} / {len(proxies_to_check)}")
    debug_log.append(f"[{get_timestamp()}] ✅ Converted to YAML: {len(yaml_proxies)}")
    debug_log.append(f"[{get_timestamp()}] 💾 Writing files...")

    # Save everything
    save_all(best, skipped, yaml_proxies, debug_log)

def save_all(ok_list, skip_list, yaml_cfg, debug_log):
    with open("Server.txt", "w") as f:
        f.write("\n".join(ok_list) if ok_list else "")
    with open("skipped.txt", "w") as f:
        f.write("\n".join(skip_list) if skip_list else "")
    with open("ping_debug.txt", "w") as f:
        f.write("\n".join(debug_log))
    with open("clashx_pro.yaml", "w") as f:
        yaml.dump({"proxies": yaml_cfg}, f, sort_keys=False)

    print("🔁 Готово!")
    print(f"✅ Working: {len(ok_list)}")
    print(f"⚠️ Skipped: {len(skip_list)}")
    print(f"📄 Files: Server.txt, skipped.txt, ping_debug.txt, clashx_pro.yaml")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="Subscription URL", default="https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt")
    args = parser.parse_args()
    main(args.url)