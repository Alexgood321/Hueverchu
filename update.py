import requests
import subprocess

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300

# Получение списка ссылок
r = requests.get(URL)
lines = r.text.strip().splitlines()

print(f"#DEBUG: загружено строк: {len(lines)}")

good_nodes = []
debug_log = ""

for i, line in enumerate(lines):
    if not line.strip():
        continue
    try:
        debug_log += f"\nОбработка строки #{i}:\n{line}\n"
        if "?" in line:
            address = line.split("?")[0].split("@")[-1]
        else:
            address = line.split("//")[1].split("@")[-1].split(":")[0]
        result = subprocess.run(["ping", "-c", "1", "-W", "1", address], capture_output=True, text=True)
        if "time=" in result.stdout:
            ping_ms = float(result.stdout.split("time=")[-1].split()[0])
        else:
            ping_ms = 9999

        debug_log += f"Ping = {ping_ms} мс\n"
        if ping_ms <= MAX_PING:
            good_nodes.append(line)
        else:
            debug_log += "Пропуск: высокий пинг\n"
    except Exception as e:
        debug_log += f"Ошибка: {str(e)}\n"
        continue

# Shadowrocket
shadowrocket_text = "\n".join(good_nodes)

# Clash
clash_text = "proxies:\n"
for idx, node in enumerate(good_nodes):
    clash_text += f"  - name: Proxy{idx + 1}\n    type: vless\n    url: {node}\n"

# Сохраняем файлы
print("Создаю файлы...")

with open("shadowrocket.txt", "w", encoding="utf-8") as f:
    f.write(shadowrocket_text)

with open("clash.yaml", "w", encoding="utf-8") as f:
    f.write(clash_text)

with open("ping_debug.txt", "w", encoding="utf-8") as f:
    f.write(debug_log)

print("✅ Файлы созданы: shadowrocket.txt, clash.yaml, ping_debug.txt")
