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
import sys

DEFAULT_URL = "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"
MAX_PING = 150
MAX_PROXY_COUNT = 20

def get_timestamp():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

def decode_base64_if_sub(line):
    if line.startswith("sub://"):
        encoded = line[6:].strip()
        try:
            decoded = base64.b64decode(encoded + "==").decode("utf-8")
            return decoded.splitlines(), None
        except Exception as e:
            return None, f"[{get_timestamp()}] Decode error: {str(e)}"
    return [line], None

def extract_host_port(line):
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
        return host, port, None if host and port else f"Failed host/port: {line}"
    except Exception as e:
        return None, None, f"Parse error: {str(e)}"

def check_server(host, port, timeout=5, retries=1):
    for attempt in range(retries + 1):
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            latency = (time.time() - start) * 1000
            return True, latency, f"{host}:{port} ✅ {latency:.1f}ms"
        except:
            time.sleep(1)
    return False, 0, f"{host}:{port} ❌ timeout"

def convert_to_clash_format(line, debug):
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
        elif line.startswith("ss://"):
            part = line[5:].split("@")[0]
            decoded = base64.b64decode(part + "==").decode()
            method, pwd = decoded.split(":")
            parsed = urlparse(line)
            return {
                "name": f"ss-{parsed.hostname}-{parsed.port}",
                "type": "ss",
                "server": parsed.hostname,
                "port": parsed.port,
                "cipher": method,
                "password": pwd
            }
    except Exception as e:
        debug.append(f"[{get_timestamp()}] Conversion error: {str(e)}")
    return None

def check_servers_parallel(proxies):
    results = {}
    with ThreadPoolExecutor(max_workers=20) as exec:
        future_map = {exec.submit(check_server, h, p): (line, h, p) for line, h, p in proxies}
        for future in future_map:
            line, host, port = future_map[future]
            results[line] = future.result()
    return results

def main(proxy_url):
    debug = [f"[{get_timestamp()}] Started"]
    working = []
    skipped = []

    # Load proxy list
    try:
        with urllib.request.urlopen(proxy_url, timeout=10) as r:
            lines = r.read().decode().splitlines()
        debug.append(f"[{get_timestamp()}] Loaded {len(lines)} lines")
    except Exception as e:
        debug.append(f"[{get_timestamp()}] Load error: {str(e)}")
        save_files([], [], [], debug)
        return

    decoded = []
    for l in lines:
        res, err = decode_base64_if_sub(l)
        if res:
            decoded.extend(res)
        elif err:
            debug.append(err)

    proxies = []
    for line in decoded:
        host, port, err = extract_host_port(line)
        if host and port:
            proxies.append((line, host, port))
        elif err:
            debug.append(err)

    results = check_servers_parallel(proxies)
    for line, (alive, ping, status) in results.items():
        debug.append(f"[{get_timestamp()}] {status}")
        if alive and ping < MAX_PING:
            working.append((line, ping))
        else:
            skipped.append(line)

    working.sort(key=lambda x: x[1])
    top = [x[0] for x in working[:MAX_PROXY_COUNT]]
    configs = [convert_to_clash_format(p, debug) for p in top]
    configs = [c for c in configs if c]

    debug.append(f"[{get_timestamp()}] Finished — {len(top)} saved, {len(skipped)} skipped")
    save_files(top, skipped, configs, debug)

def save_files(ok, skip, yaml_cfg, log):
    with open("Server.txt", "w") as f:
        f.write("\n".join(ok))
    with open("skipped.txt", "w") as f:
        f.write("\n".join(skip))
    with open("ping_debug.txt", "w") as f:
        f.write("\n".join(log))
    with open("clashx_pro.yaml", "w") as f:
        yaml.dump({"proxies": yaml_cfg}, f, sort_keys=False)

    print(f"🟢 OK: {len(ok)} proxies saved")
    print(f"🟡 Skipped: {len(skip)}")
    print(f"📄 Files: Server.txt, skipped.txt, ping_debug.txt, clashx_pro.yaml")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Proxy checker & converter to ClashX Pro")
    parser.add_argument("--url", default=DEFAULT_URL, help="URL to subscription list")
    args = parser.parse_args()
    main(args.url)