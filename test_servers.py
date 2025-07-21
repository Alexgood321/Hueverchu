import urllib.request
import base64
import re
import socket
import time
from urllib.parse import urlparse
from datetime import datetime

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
            return decoded.splitlines()
        except Exception as e:
            return None, f"Failed to decode base64: {line} - {str(e)}"
    return [line], None

# Функция для извлечения хоста и порта
def extract_host_port(line):
    try:
        if line.startswith(("vless://", "trojan://", "ss://", "vmess://")):
            # Удаляем параметры после "?" или "#"
            clean_line = re.split(r"[?#]", line)[0]
            parsed = urlparse(clean_line)
            host = parsed.hostname
            port = parsed.port
            if not host:
                # Проверяем, есть ли хост в формате user@host:port
                match = re.search(r"@([^\s:]+):(\d+)", clean_line)
                if match:
                    host, port = match.groups()
                    port = int(port)
            if not port:
                # Проверяем порт в строке
                match = re.search(r":(\d+)", clean_line)
                port = int(match.group(1)) if match else None
            if host and port:
                return host, port
    except Exception as e:
        return None, None, f"Failed to parse: {line} - {str(e)}"
    return None, None, f"Invalid format: {line}"

# Функция для проверки TCP-соединения
def check_server(host, port, timeout=3):
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        latency = (time.time() - start_time) * 1000  # В миллисекундах
        return True, f"OK: {host}:{port} (Latency: {latency:.2f}ms)"
    except Exception as e:
        return False, f"Error: {host}:{port} - {str(e)}"

# Основной процесс
def main():
    debug_log = [f"[{get_timestamp()}] Starting proxy check"]
    working_servers = set()  # Используем set для исключения дубликатов
    skipped_servers = set()
    
    # Загрузка списка прокси
    try:
        with urllib.request.urlopen(PROXY_LIST_URL, timeout=10) as response:
            proxy_lines = response.read().decode("utf-8").splitlines()
        debug_log.append(f"[{get_timestamp()}] Loaded {len(proxy_lines)} proxy entries")
    except Exception as e:
        debug_log.append(f"[{get_timestamp()}] Failed to load proxy list: {str(e)}")
        # Сохраняем логи и завершаем
        with open("ping_debug.txt", "w") as f:
            f.write("\n".join(debug_log))
        return

    # Обработка каждого прокси
    for line in proxy_lines:
        line = line.strip()
        if not line:
            continue

        # Декодирование sub://
        lines_to_check, decode_error = decode_base64_if_sub(line)
        if decode_error:
            debug_log.append(f"[{get_timestamp()}] {decode_error}")
            skipped_servers.add(line)
            continue

        for decoded_line in lines_to_check:
            decoded_line = decoded_line.strip()
            if not decoded_line:
                continue

            # Извлечение хоста и порта
            host, port, parse_error = extract_host_port(decoded_line)
            if parse_error:
                debug_log.append(f"[{get_timestamp()}] {parse_error}")
                skipped_servers.add(decoded_line)
                continue

            # Проверка TCP-соединения
            is_alive, status = check_server(host, port)
            debug_log.append(f"[{get_timestamp()}] {status}")
            if is_alive:
                working_servers.add(decoded_line)
            else:
                skipped_servers.add(decoded_line)

    # Сохранение результатов
    with open("Server.txt", "w") as f:
        f.write("\n".join(sorted(working_servers)))
    with open("skipped.txt", "w") as f:
        f.write("\n".join(sorted(skipped_servers)))
    with open("ping_debug.txt", "w") as f:
        f.write("\n".join(debug_log))
    
    debug_log.append(f"[{get_timestamp()}] Completed: {len(working_servers)} working, {len(skipped_servers)} skipped")

if __name__ == "__main__":
    main()