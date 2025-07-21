import requests
import socket
import time
from urllib.parse import urlparse

URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300  # мс
TIMEOUT = 2     # секунды

r = requests.get(URL)
lines = r.text.strip().splitlines()
print(f"#DEBUG: загружено строк: {len(lines)}")

good_nodes = []
debug_log = ""

def extract_host(line):
    try:
        # Отрезаем схему (vless://, trojan://, ss://)
        line = line.strip()
        if "://" not in line:
            return None
        parsed = urlparse(line)
        if parsed.hostname:
            return parsed.hostname
        else:
            # Fallback: попытка вручную
            at_split = line.split("@")
            if len(at_split) == 2:
                host_port = at_split[1].split("/")[0]
                return host_port.split(":")[0]
    except Exception:
        return None

def tcp_ping(host: str, port: int = 443, timeout: int = TIMEOUT) -> float:
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            end = time.time()
        return (end - start) * 1000
    except Exception:
        return 9999

for i, line in enumerate(lines):
    if not line.strip():
        continue

    debug_log += f"\nОбработка строки #{i}:\n{line}\n"

    address = extract_host(line)
    if not address:
        debug_log += "❌ Не удалось извлечь адрес\n"
        continue

    ping_ms = tcp_ping(address)
    debug_log += f"Ping = {int(ping_ms)} ms\n"

    if ping_ms <= MAX_PING:
        good_nodes.append(line)
    else:
        debug_log += "Пропуск: высокий пинг\n"

# Запись файлов
with open("shadowrocket.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(good_nodes))

with open("clash.yaml", "w", encoding="utf-8") as f:
    clash_text = 'proxies:\n'
    for idx, node in enumerate(good_nodes):
        clash_text += f'- name: Proxy{idx + 1}\n  type: vless\n  url: {node}\n'
    f.write(clash_text)

with open("ping_debug.txt", "w", encoding="utf-8") as f:
    f.write(debug_log)

print("✅ Файлы созданы: shadowrocket.txt, clash.yaml, ping_debug.txt")
