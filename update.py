import requests
import subprocess
import os

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300
OUTPUT_DIR = "output"
OUTPUT_FILE = "shadowrocket.txt"
LOG_FILE = "ping_debug.txt"

# Получение списка ссылок
r = requests.get(URL)
lines = r.text.strip().splitlines()
print(f"#DEBUG: загружено строк: {len(lines)}")

valid_links = []
log_lines = []

for i, line in enumerate(lines):
    try:
        if not line.startswith("vless://"):
            log_lines.append(f"[{i}] ❌ Пропуск — не начинается с vless:// → {line}")
            continue

        after_at = line.split("@")
        if len(after_at) < 2:
            log_lines.append(f"[{i}] ❌ Ошибка — отсутствует '@' в ссылке → {line}")
            continue

        address_port = after_at[1].split("?")[0].split("/")[0]
        address = address_port.split(":")[0]

        # Пинг
        ping = subprocess.run(["ping", "-c", "1", "-W", "1", address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ping.stdout.decode()

        if "time=" in output:
            time_ms = float(output.split("time=")[1].split(" ")[0])
            if time_ms < MAX_PING:
                valid_links.append(line)
                log_lines.append(f"[{i}] ✅ {address} — OK ({time_ms} ms)")
            else:
                log_lines.append(f"[{i}] ⚠️ {address} — Пинг слишком высокий: {time_ms} ms")
        else:
            log_lines.append(f"[{i}] ❌ {address} — нет ответа (timeout)")
    except Exception as e:
        log_lines.append(f"[{i}] ❌ Ошибка парсинга строки: {line}\nПричина: {e}")

# Сохраняем рабочие ссылки
os.makedirs(OUTPUT_DIR, exist_ok=True)
with open(f"{OUTPUT_DIR}/{OUTPUT_FILE}", "w") as f:
    for link in valid_links:
        f.write(link + "\n")

# Сохраняем лог
with open(f"{OUTPUT_DIR}/{LOG_FILE}", "w") as f:
    for log in log_lines:
        f.write(log + "\n")

print(f"\nСоздано:")
print(f"- {OUTPUT_FILE} — {len(valid_links)} строк")
print(f"- {LOG_FILE} — полный лог")
