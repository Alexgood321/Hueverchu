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

# Настройки
PROXY_LIST_URL = "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"
MAX_PING = 150  # Максимальный пинг в мс
MAX_PROXY_COUNT = 20  # Желаемое количество прокси

# Время в формате UTC
def get_timestamp():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

# Декодирование base64
def decode_base64_if_sub(line):
    if line.startswith("sub://"):
        encoded_part = line[6:].strip()
        try:
            decoded = base64.b64decode(encoded_part).decode("utf-8")
            return decoded.splitlines(), None
        except Exception as e:
            return None, f"Failed to decode base64: {line} - {str(e)}"
    return [line], None

# Извлечение хоста и порта
def extract_host_port(line):
    try:
        if line.startswith(("vless://", "trojan://", "ss://", "vmess://")):
            clean_line = re.split(r"[?#]", line)[0]
            parsed = urlparse(clean_line)
            host = parsed.hostname
            port = parsed.port
            if not host:
                match = re.search(r"@([^\s:]+):(\d+)", clean_line)
                if match:
                    host, port = match.groups()
                    port = int(port)
            if not port:
                match = re.search(r":(\d+)", clean_line)
                port = int(match.group(1)) if match else None
            return host, port, None if host and port else f"Failed to parse host/port: {line}"
    except Exception as e:
        return None, None, f"Failed to parse: {line} - {str(e)}"
    return None, None, f"Invalid format: {line}"

# Проверка соединения с повторными попытками
def check_server(host, port, timeout=5, retries=2):
    for attempt in range(retries + 1):
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            latency = (time.time() - start_time) * 1000
            return True, latency, f"OK: {host}:{port} (Latency: {latency:.2f}ms)"
        except socket.timeout:
            if attempt == retries:
                return False, 0, f"Error: {host}:{port} - timed out"
            time.sleep(1)
        except Exception as e:
            return False, 0, f"Error: {host}:{port} - {str(e)}"
    return False, 0, f"Error: {host}:{port} - max retries reached"

# Конвертация в формат ClashX Pro
def convert_to_clash_format(proxy_line):
    try:
        parsed_url = urlparse(proxy_line)
        query_params = parse_qs(parsed_url.query)
        host = parsed_url.hostname or re.search(r"@([^:]+)", proxy_line).group(1)
        port = parsed_url.port or int(re.search(r":(\d+)", proxy_line).group(1))

        if proxy_line.startswith("vless://"):
            config = {
                "name": f"vless-{host}-{port}",
                "type": "vless",
                "server": host,
                "port": port,
                "uuid": parsed_url.username,
                "network": query_params.get("type", ["tcp"])[0],
                "tls": "tls" in query_params.get("security", [""])[0].lower()
            }
            return config

        elif proxy_line.startswith("trojan://"):
            config = {
                "name": f"trojan-{host}-{port}",
                "type": "trojan",
                "server": host,
                "port": port,
                "password": parsed_url.username,
                "tls": True
            }
            return config

        elif proxy_line.startswith("ss://"):
            base64_part = proxy_line[5:].split("@")[0]
            decoded = base64.b64decode(base64_part).decode("utf-8")
            method, password = decoded.split(":")
            return {
                "name": f"ss-{host}-{port}",
                "type": "ss",
                "server": host,
                "port": int(port),
                "cipher": method,
                "password": password
            }

        elif proxy_line.startswith("vmess://"):
            decoded = base64.b64decode(proxy_line[8:]).decode("utf-8")
            data = json.loads(decoded)
            config = {
                "name": f"vmess-{data['add']}-{data['port']}",
                "type": "vmess",
                "server": data["add"],
                "port": int(data["port"]),
                "uuid": data["id"],
                "network": data.get("net", "tcp"),
                "tls": data.get("tls", "false").lower() == "true"
            }
            return config
    except Exception:
        return None
    return None

# Параллельная проверка прокси
def check_servers_parallel(proxies):
    results = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_proxy = {executor.submit(check_server, host, port): (proxy, host, port) for proxy, host, port in proxies}
        for future in future_to_proxy:
            proxy, host, port = future_to_proxy[future]
            results[proxy] = future.result()
    return results

# Основная логика
def main():
    debug_log = [f"[{get_timestamp()}] Starting proxy check"]
    working_servers = []
    skipped_servers = set()

    # Загрузка прокси
    try:
        with urllib.request.urlopen(PROXY_LIST_URL, timeout=10) as response:
            proxy_lines = response.read().decode("utf-8").splitlines()
        debug_log.append(f"[{get_timestamp()}] Loaded {len(proxy_lines)} proxy entries")
    except Exception as e:
        debug_log.append(f"[{get_timestamp()}] Failed to load proxy list: {str(e)}")
        with open("ping_debug.txt", "w") as f:
            f.write("\n".join(debug_log))
        return

    # Подготовка прокси
    proxies_to_check = [(line, host, port) for line in sum([decode_base64_if_sub(l)[0] for l in proxy_lines if decode_base64_if_sub(l)[0]], []) 
                        for host, port, _ in [extract_host_port(line)] if host and port]

    # Проверка
    results = check_servers_parallel(proxies_to_check)
    for proxy, _, _ in proxies_to_check:
        is_alive, latency, status = results[proxy]
        debug_log.append(f"[{get_timestamp()}] {status}")
        if is_alive and latency < MAX_PING:
            working_servers.append((proxy, latency))
        else:
            skipped_servers.add(proxy)

    # Сортировка и отбор лучших
    if working_servers:
        working_servers.sort(key=lambda x: x[1])  # Сортировка по пингу
        best_proxies = [proxy for proxy, _ in working_servers[:MAX_PROXY_COUNT]]
    else:
        best_proxies = []

    # Генерация файлов
    clash_proxies = [p for p in [convert_to_clash_format(proxy) for proxy in best_proxies] if p]
    with open("Server.txt", "w") as f:  # Явная перезапись файла
        f.write("\n".join(best_proxies) if best_proxies else "")
    with open("skipped.txt", "w") as f:
        f.write("\n".join(sorted(skipped_servers)))
    with open("ping_debug.txt", "w") as f:
        f.write("\n".join(debug_log))
    with open("clashx_pro.yaml", "w") as f:
        yaml.dump({"proxies": clash_proxies}, f, default_flow_style=False, sort_keys=False)

    debug_log.append(f"[{get_timestamp()}] Completed: {len(best_proxies)} working, {len(skipped_servers)} skipped")

if __name__ == "__main__":
    main()