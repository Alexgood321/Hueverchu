import requests
import subprocess
import re

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300  # ms

# Получение списка ссылок
r = requests.get(URL)
lines = r.text.strip().splitlines()

print(f"#DEBUG: загружено строк: {len(lines)}")

good_nodes = []
debug_log = ""

def extract_host(line):
    try:
        # Поиск через регулярное выражение host:port после @
        match = re.search(r'@([a-zA-Z0-9\.\-\_]+):(\d+)', line)
        if match:
            return match.group(1)  # host
        # Альтернатива для ss:// без @, base64-хост
        if line.startswith("ss://"):
            decoded = requests.utils.unquote(line[5:])
            base64_part = decoded.split("#")[0].split("@")[-1]
            match = re.search(r'([a-zA-Z0-9\.\-]+):(\d+)', base64_part)
            if match:
                return match.group(1)
    except:
        pass
    return None

# Обработка каждой строки
for i, line in enumerate(lines):
    if not line.strip():
        continue

    debug_log += f"Обработка строки #{i}:\n{line}\n"

    address = extract_host(line)
    if not address:
        debug_log += "⚠️ Ошибка: не удалось извлечь адрес\n\n"
        continue

    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", address],
                                capture_output=True, text=True)
        ping_ms = 9999
        for line in result.stdout.splitlines():
            if "time=" in line:
                ping_ms = float(line.split("time=")[-1].split()[0])
                break
        debug_log += f"Ping = {ping_ms} ms\n"

        if ping_ms <= MAX_PING:
            good_nodes.append(line)
        else:
            debug_log += "Пропуск: высокий пинг\n"
    except Exception as e:
        debug_log += f"Ошибка: {str(e)}\n"
    debug_log += "\n"

# Формат для Shadowrocket
shadowrocket_text = "\n".join(good_nodes)

# Формат для Clash
clash_text = "proxies:\n"
for idx, node in enumerate(good_nodes):
    clash_text += f"- name: Proxy{idx + 1}\n  type: vless\n  url: {node}\n"

# Сохраняем файлы
with open("shadowrocket.txt", "w", encoding="utf-8") as f:
    f.write(shadowrocket_text)

with open("clash.yaml", "w", encoding="utf-8") as f:
    f.write(clash_text)

with open("ping_debug.txt", "w", encoding="utf-8") as f:
    f.write(debug_log)

print("✅ Файлы созданы: shadowrocket.txt, clash.yaml, ping_debug.txt")
