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

# Настройки
MAX_PROXY_COUNT = 20      # Количество прокси
MAX_PING_MS = 150         # Максимально допустимый пинг в мс
CHECK_TIMEOUT = 10        # Таймаут сокета в секундах
RETRIES = 2               # Количество повторных попыток

def get_timestamp():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

def decode_base64_if_sub(line, debug_log):
    if line.startswith("sub://"):
        encoded = line[6:].strip()
        try:
            decoded = base64.b64decode(encoded + "==").decode("utf-8")
            debug_log.append(f"[{get_timestamp()}] ✅ Decoded base64 ({len(decoded.splitlines())} lines)")
            return decoded.splitlines()
        except Exception as e:
            debug_log.append(f"[{get_timestamp()}] ❌ Decode error: {str(e)}")
            return []
    return [line]

def extract_host_port(line, debug_log):
    try:
        parsed = urlparse(line)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            match = re.search(r"@([^\s:]+):(\d+)", line)
            if match:
                host, port = match.groups()
                port = int(port)
            else:
                query = parse_qs(parsed.query)
                host = query.get("host", [None])[0]
                port = int(query.get("port", [None])[0]) if query.get("port", [None])[0] else None
        return (host, port) if host and port else (None, None)
    except Exception as e:
        debug_log.append(f"[{get_timestamp()}] ❌ Extract error: {line} - {str(e)}")
        return None, None

def check_speed(host, port, timeout=CHECK_TIMEOUT, retries=RETRIES):
    for attempt in range(retries + 1):
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            start_dl = time.time()
            data = sock.recv(2048)
            sock.close()
            latency_ms = (start_dl - start) * 1000
            speed_kbps = (len(data) / 1024) / (time.time() - start_dl + 1e-6)
            return True, latency_ms, speed_kbps
        except Exception:
            if attempt == retries:
                return False, 0, 0
            time.sleep(1)
    return False, 0, 0

def convert_to_clash_format(line, debug_log):
    try:
        parsed = urlparse(line)
        query = parse_qs(parsed.query)
        host = parsed.hostname or re.search(r"@([^\s:]+)", line).group(1)
        port = parsed.port or int(re.search(r":(\d+)", line).group(1))

        if line.startswith("vmess://"):
            raw = base64.b64decode(line[8:] + "==").decode("utf-8")
            config = json.loads(raw)
            result = {
                "name": f"vmess-{config['add']}-{config['port']}",
                "type": "vmess",
                "server": config["add"],
                "port": int(config["port"]),
                "uuid": config["id"],
                "network": config.get("net", "tcp"),
                "tls": config.get("tls", "false").lower() == "true"
            }
            if "ws" in config.get("net", ""):
                result["ws-opts"] = {"path": config.get("path", "/")}
            debug_log.append(f"[{get_timestamp()}] ✅ Converted vmess: {line}")
            return result

        elif line.startswith("trojan://"):
            result = {
                "name": f"trojan-{host}-{port}",
                "type": "trojan",
                "server": host,
                "port": port,
                "password": parsed.username,
                "tls": True,
                "sni": query.get("sni", [host])[0]
            }
            if "ws" in query.get("type", [""])[0]:
                result["ws-opts"] = {"path": query.get("path", ["/"])[0]}
            debug_log.append(f"[{get_timestamp()}] ✅ Converted trojan: {line}")
            return result

        elif line.startswith("vless://"):
            result = {
                "name": f"vless-{host}-{port}",
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": parsed.username,
                "network": query.get("type", ["tcp"])[0],
                "tls": "tls" in query.get("security", [""])[0]
            }
            if result["network"] == "ws":
                result["ws-opts"] = {"path": query.get("path", ["/"])[0]}
            debug_log.append(f"[{get_timestamp()]} ✅ Converted vless: {line}")
            return result
    except Exception as e:
        debug_log.append(f"[{get_timestamp()}] ❌ Conversion error: {line} - {str(e)}")
        return None

def check_all_proxies(proxies, debug_log):
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_map = {
            executor.submit(check_speed, host, port): (line, host, port)
            for line, host, port in proxies if host and port
        }
        for future in future_map:
            line, host, port = future_map[future]
            alive, latency, speed = future.result()
            if alive and latency < MAX_PING_MS:
                results.append((line, latency, speed))
                debug_log.append(f"[{get_timestamp()}] ✅ {host}:{port} - {latency:.1f}ms - {speed:.1f} KB/s")
            else:
                debug_log.append(f"[{get_timestamp()}] ❌ {host}:{port} - {latency:.1f}ms or timeout")
    return results

def process_proxies(url, debug_log):
    raw_lines = []
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            raw_lines = response.read().decode().splitlines()
        debug_log.append(f"[{get_timestamp()}] ✅ Loaded {len(raw_lines)} entries")
    except Exception as e:
        debug_log.append(f"[{get_timestamp()}] ❌ Download error: {str(e)}")
        return [], [], []

    decoded = [line for line in sum([decode_base64_if_sub(l, debug_log) for l in raw_lines], []) if line]
    debug_log.append(f"[{get_timestamp()}] 🧪 Decoded {len(decoded)} lines")

    proxy_candidates = [(line, host, port) for line in decoded 
                       for host, port in [extract_host_port(line, debug_log)] if host and port]
    skipped = [line for line in decoded if not any(host for host, _ in [extract_host_port(line, debug_log)] if host)]
    debug_log.append(f"[{get_timestamp()}] 🕒 Checking {len(proxy_candidates)} candidates")

    checked = check_all_proxies(proxy_candidates, debug_log)
    checked.sort(key=lambda x: (x[1], -x[2]))  # Сортировка по пингу (восх) и скорости (убыв)
    top_proxies = checked[:MAX_PROXY_COUNT]  # Ограничение до 20

    best_lines = [line for line, _, _ in top_proxies]
    converted = [config for line in best_lines if (config := convert_to_clash_format(line, debug_log))]

    debug_log.append(f"[{get_timestamp()}] ✅ Selected {len(top_proxies)} top proxies")
    return best_lines, skipped, converted

def save_results(ok_list, skip_list, yaml_cfg, debug_log):
    debug_log.append(f"[{get_timestamp()}] 💾 Saving files: Server.txt, skipped.txt, ping_debug.txt, clashx_pro.yaml")
    with open("Server.txt", "w") as f:
        content = "\n".join(ok_list) if ok_list else "No working proxies found"
        f.write(content)
        debug_log.append(f"[{get_timestamp()}] 📝 Saved {len(ok_list)} proxies to Server.txt")
    with open("skipped.txt", "w") as f:
        content = "\n".join(skip_list) if skip_list else "No skipped proxies"
        f.write(content)
        debug_log.append(f"[{get_timestamp()}] 📝 Saved {len(skip_list)} skipped to skipped.txt")
    with open("ping_debug.txt", "w") as f:
        f.write("\n".join(debug_log))
        debug_log.append(f"[{get_timestamp()}] 📝 Saved debug log")
    with open("clashx_pro.yaml", "w") as f:
        content = {"proxies": yaml_cfg} if yaml_cfg else {"proxies": [], "note": "No proxies converted"}
        yaml.dump(content, f, sort_keys=False)
        debug_log.append(f"[{get_timestamp()}] 📝 Saved {len(yaml_cfg)} proxies to clashx_pro.yaml")
    print(f"\n📦 Done:")
    print(f"✅ Working: {len(ok_list)}")
    print(f"⚠️ Skipped: {len(skip_list)}")
    print(f"📄 Files: Server.txt, skipped.txt, ping_debug.txt, clashx_pro.yaml")

def main(url):
    debug_log = [f"[{get_timestamp()}] 🚀 Starting proxy scan"]
    best_lines, skipped, converted = process_proxies(url, debug_log)
    save_results(best_lines, skipped, converted, debug_log)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan and filter proxies for ClashX Pro")
    parser.add_argument("--url", default="https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt", help="URL of proxy list")
    args = parser.parse_args()
    main(args.url)