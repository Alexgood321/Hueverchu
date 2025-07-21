import os
import subprocess
import yaml
import re
import base64

# Пути
INPUT_FILE = "server.txt"
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

SHADOWROCKET_FILE = os.path.join(OUTPUT_DIR, "shadowrocket.txt")
CLASH_FILE = os.path.join(OUTPUT_DIR, "clash.yaml")
DEBUG_FILE = os.path.join(OUTPUT_DIR, "ping_debug.txt")

# Порог по ping
MAX_PING = 300

def extract_host(url):
    """Извлекает host из vless://, trojan://, ss://"""
    try:
        if url.startswith(("vless://", "trojan://")):
            match = re.search(r'@([\w\.-]+):(\d+)', url)
            return match.group(1) if match else None

        elif url.startswith("ss://"):
            url_clean = url.split("#")[0]
            raw = url_clean[5:]

            if "@" not in raw:
                raw += "=" * (-len(raw) % 4)  # padding
                decoded = base64.b64decode(raw).decode()
                parts = decoded.split("@")
            else:
                parts = raw.split("@")

            if len(parts) == 2:
                host_port = parts[1]
                host = host_port.split(":")[0]
                return host
    except Exception:
        return None

    return None

def ping(host):
    """Возвращает ping до host в мс, иначе 9999"""
    try:
        out = subprocess.check_output(["ping", "-c", "1", "-W", "1", host], universal_newlines=True)
        match = re.search(r'time=([\d.]+)', out)
        return float(match.group(1)) if match else 9999
    except:
        return 9999

def main():
    with open(INPUT_FILE, "r") as f:
        urls = [line.strip() for line in f if line.strip().startswith(("vless://", "trojan://", "ss://"))]

    valid_urls = []
    clash_proxies = []
    debug_log = []

    for i, url in enumerate(urls):
        proto = url.split("://")[0]
        host = extract_host(url)

        debug_log.append(f"[{i}] {proto.upper()} | URL: {url}")
        if not host:
            debug_log.append("  ⛔ Не удалось извлечь хост\n")
            continue

        latency = ping(host)
        debug_log.append(f"  ✅ Host: {host} | Ping: {latency} ms")

        if latency < MAX_PING:
            valid_urls.append(url)
            clash_proxies.append({
                "name": f"{proto}_{i}",
                "type": proto,
                "server": host,
                "port": 443,
                "udp": True
            })
            debug_log.append("  👍 Добавлен\n")
        else:
            debug_log.append("  ⚠️ Пропущен — высокий пинг\n")

    # Сохраняем результаты
    with open(SHADOWROCKET_FILE, "w") as f:
        f.write("\n".join(valid_urls))

    with open(CLASH_FILE, "w") as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True)

    with open(DEBUG_FILE, "w") as f:
        f.write("\n".join(debug_log))

if __name__ == "__main__":
    main()
