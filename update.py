import requests
import subprocess
import base64
import os

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300
OUTPUT_DIR = "output"
OUTPUT_FILE = "shadowrocket.txt"

# Получение списка ссылок
r = requests.get(URL)
lines = r.text.strip().splitlines()
print(f"#DEBUG: загружено строк: {len(lines)}")

valid_links = []

for i, line in enumerate(lines):
    try:
        if not line.startswith("vless://"):
            print(f"Пропуск: строка {i} не начинается с vless://")
            continue

        encoded = line.split("vless://")[1].split("@")[0]
        decoded = base64.b64decode(encoded + '==').decode('utf-8', errors='ignore')

        # Сразу ищем хост (после @)
        parts = line.split("@")
        if len(parts) < 2:
            raise Exception("URL не содержит @")

        address = parts[1].split("?")[0].split(":")[0]

        # Пинг сервера
        ping = subprocess.run(["ping", "-c", "1", "-W", "1", address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ping.stdout.decode()

        if "time=" in output:
            time_ms = float(output.split("time=")[1].split(" ")[0])
            if time_ms < MAX_PING:
                print(f"+ Добавлен: {address} ({time_ms} ms)")
                valid_links.append(line)
            else:
                print(f"- Превышен пинг: {address} ({time_ms} ms)")
        else:
            print(f"- Нет ответа: {address}")
    except Exception as e:
        print(f"Ошибка при обработке строки #{i}: {line}")
        print(f"Причина: {e}")

# Запись результата
os.makedirs(OUTPUT_DIR, exist_ok=True)
with open(f"{OUTPUT_DIR}/{OUTPUT_FILE}", "w") as f:
    for link in valid_links:
        f.write(link + "\n")

print(f"\nФайл {OUTPUT_FILE} создан. Всего подходящих ссылок: {len(valid_links)}")
