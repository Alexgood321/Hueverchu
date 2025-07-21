import urllib.request
import base64
import re
import socket
import time
from urllib.parse import urlparse

# URL с прокси
PROXY_LIST_URL = "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt"

# Функция для декодирования base64, если строка в формате sub://
def decode_base64_if_sub(line):
    if line.startswith("sub://"):
        encoded_part = line[6:].strip()
        try:
            decoded = base64.b64decode(encoded_part).decode("utf-8")
            return decoded.splitlines()
        except Exception as e:
            return None
    return [line]

# Функция для извлечения хоста и порта
def extract_host_port(line):
    try:
        if line.startswith(("vless://", "trojan://", "ss://")):
            parsed = urlparse(line)
            host = parsed.hostname
            port = parsed.port
            if not port:
                # Попытка найти порт в строке, если он не в стандартном месте
                match = re.search(r':(\d+)', line)
                port = int(match.group(1)) if match else None
            return host, port
    except Exception:
        return None, None
    return None, None

# Функция для проверки TCP-соединения
def check_server(host, port, timeout=5):
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
    # Загрузка списка прокси
    with urllib.request.urlopen(PROXY_LIST_URL) as response:
        proxy_lines = response.read().decode("utf-8").splitlines()

    working_servers = []
    skipped_servers = []
    debug_log = []

    # Обработка каждого прокси
    for line in proxy_lines:
        lines_to_check = decode_base64_if_sub(line.strip())
        if not lines_to_check:
            debug_log.append(f"Failed to decode: {line}")
            skipped_servers.append(line)
            continue

        for decoded_line in lines_to_check:
            host, port = extract_host_port(decoded_line)
            if not host or not port:
                debug_log.append(f"Invalid format: {decoded_line}")
                skipped_servers.append(decoded_line)
                continue

            # Проверка TCP-соединения
            is_alive, status = check_server(host, port)
            debug_log.append(status)
            if is_alive:
                working_servers.append(decoded_line)
            else:
                skipped_servers.append(decoded_line)

    # Сохранение результатов
    with open("Server.txt", "w") as f:
        f.write("\n".join(working_servers))
    with open("skipped.txt", "w") as f:
        f.write("\n".join(skipped_servers))
    with open("ping_debug.txt", "w") as f:
        f.write("\n".join(debug_log))

if __name__ == "__main__":
    main() 
