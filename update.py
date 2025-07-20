import requests
import socket
import time

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300  # мс
TIMEOUT = 2     # секунды

# Получение списка ссылок
r = requests.get(URL)
lines = r.text.strip().splitlines()

print(f"#DEBUG: загружено строк: {len(lines)}")

good_nodes = []
debug_log = ""

def tcp_ping(host: str, port: int = 443, timeout: int = TIMEOUT) -> float:
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            end = time.time()
        return (end - start) * 1000  # ms
    except Exception:
        return 9999

for i, line in enumerate(lines):
    if not line.strip():
        continue

    debug_log += f"\nОбработка строки #{i}:\n{line}\n"

    try:
        address = line.split("@")[-1].split("/")[0].strip()
        ping_ms = tcp_ping(address)
        debug_log += f"Ping = {int(ping_ms)} ms\n"

        if ping_ms <= MAX_PING:
            good_nodes.append(line)
        else:
            debug_log += "Пропуск: высокий пинг\n"

    except Exception as e:
        debug_log += f"❌ Ошибка: {str(e)}\n"
        continue

# Shadowrocket
shadowrocket_text = "\n".join(good_nodes)

# Clash
clash_text = 'proxies:\n'
for idx, node in enumerate(good_nodes):
    clash_text += f'- name: Proxy{idx + 1}\n  type: vless\n  url: {node}\n'

# Сохранение файлов
with open("shadowrocket.txt", "w", encoding="utf-8") as f:
    f.write(shadowrocket_text)

with open("clash.yaml", "w", encoding="utf-8") as f:
    f.write(clash_text)

with open("ping_debug.txt", "w", encoding="utf-8") as f:
    f.write(debug_log)

print("✅ Файлы созданы: shadowrocket.txt, clash.yaml, ping_debug.txt")
