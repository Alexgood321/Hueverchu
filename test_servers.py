import urllib.request
import base64
import re
import socket
import time
from urllib.parse import urlparse
from datetime import datetime
import yaml

# URL с прокси
PROXY_LIST_URL = "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"

# Функция для получения текущего времени
def get_timestamp():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

# Функция для декодирования base64, если строка в формате sub://
def decode_base64_if_sub(line):
    if line.startswith("sub://"):
        encoded_part = line[6:].strip()
        try:
            decoded = base64.b64decode(encoded_part).decode("utf-8")
            return decoded.splitlines(), None
        except Exception as e:
            return None, f"Failed to decode base64: {line} - {str(e)}"
    return [line], None

# Функция для извлечения хоста и порта
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
            if host and port:
                return host, port, None
    except Exception as e:
        return None, None, f"Failed to parse: {line} - {str(e)}"
    return None, None, f"Invalid format: {line}"

# Функция для проверки TCP-соединения и измерения пинга
def check_server(host, port, timeout=5):
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        latency = (time.time() - start_time) * 1000  # В миллисекундах
        return True, latency, f"OK: {host}:{port} (Latency: {latency:.2f}ms)"
    except Exception as e:
        return False, 0, f"Error: {host}:{port} - {str(e)}"

# Функция для преобразования прокси в формат ClashX Pro
def convert_to_clash_format(proxy_line):
    if proxy_line.startswith("vless://"):
        parsed = urlparse(proxy_line)
        user_info = parsed.username
        host = parsed.hostname
        port = parsed.port or int(re.search(r":(\d+)", proxy_line).group(1))
        return {
            "name": f"vless-{host}-{port}",
            "type": "vless",
            "server": host,
            "port": port,
            "uuid": user_info,
            "network": "tcp",
            "tls": True
        }
    elif proxy_line.startswith("trojan://"):
        parsed = urlparse(proxy_line)
        host = parsed.hostname
        port = parsed.port or int(re.search(r":(\d+)", proxy_line).group(1))
        return {
            "name": f"trojan-{host}-{port}",
            "type": "trojan",
            "server": host,
            "port": port,
            "password": parsed.username,
            "network": "tcp",
            "tls": True
        }
    elif proxy_line.startswith("ss://"):
        # Простая поддержка Shadowsocks (нужна доработка для полного парсинга)
        match = re.match(r"ss://(?:[A-Za-z0-9+/]+)@([^:]+):(\d+)", proxy_line)
        if match:
            host, port = match.groups()
            return {
                "name": f"ss-{host}-{port}",
                "type": "ss",
                "server": host,
                "port": int(port),
                "cipher": "aes-256-gcm",  # Предполагаемый шифр, нужно уточнить
                "password": "password"    # Нужно извлечь из base64, доработка требуется
            }
    return None

# Основной процесс
def main():
    debug_log = [f"[{get_timestamp()}] Starting proxy check"]
    working_servers = set()  # Пинг < 300ms
    skipped_servers = set()
    clash_proxies = []

    # Загрузка списка прокси
    try:
        with urllib.request.urlopen(PROXY_LIST_URL, timeout=10) as response:
            proxy_lines = response.read().decode("utf-8").splitlines()
        debug_log.append(f"[{get_timestamp()}] Loaded {len(proxy_lines)} proxy entries")
    except Exception as e:
        debug_log.append(f"[{get_timestamp()}] Failed to load proxy list: {str(e)}")
        with open("ping_debug.txt", "w") as f:
            f.write("\n".join(debug_log))
        return

    # Обработка каждого прокси
    for line in proxy_lines:
        line = line.strip()
        if not line:
            continue

        lines_to_check, decode_error = decode_base64_if_sub(line)
        if decode_error:
            debug_log.append(f"[{get_timestamp()}] {decode_error}")
            skipped_servers.add(line)
            continue

        for decoded_line in lines_to_check:
            decoded_line = decoded_line.strip()
            if not decoded_line:
                continue

            host, port, parse_error = extract_host_port(decoded_line)
            if parse_error:
                debug_log.append(f"[{get_timestamp()}] {parse_error}")
                skipped_servers.add(decoded_line)
                continue

            is_alive, latency, status = check_server(host, port)
            debug_log.append(f"[{get_timestamp()}] {status}")
            if is_alive and latency < 300:  # Пинг < 300ms
                working_servers.add(decoded_line)
                clash_proxy = convert_to_clash_format(decoded_line)
                if clash_proxy:
                    clash_proxies.append(clash_proxy)
            else:
                skipped_servers.add(decoded_line)

    # Сохранение результатов
    with open("Server.txt", "w") as f:
        f.write("\n".join(sorted(working_servers)))
    with open("skipped.txt", "w") as f:
        f.write("\n".join(sorted(skipped_servers)))
    with open("ping_debug.txt", "w") as f:
        f.write("\n".join(debug_log))
    with open("clashx_pro.yaml", "w") as f:
        yaml.dump({"proxies": clash_proxies}, f, default_flow_style=False, sort_keys=False)

    debug_log.append(f"[{get_timestamp()}] Completed: {len(working_servers)} working, {len(skipped_servers)} skipped")

if __name__ == "__main__":
    main()
