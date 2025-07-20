import requests
import yaml

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300

# Получение списка ссылок
r = requests.get(URL)
lines = r.text.strip().splitlines()

print(f"DEBUG: загружено строк: {len(lines)}")

# Загрузка и фильтрация серверов по пингу
filtered = []
for i, line in enumerate(lines):
    try:
        print(f"DEBUG: строка #{i}: {line}")
        if not line.startswith("vless://"):
            continue
        vless_raw = line[8:]
        uuid_part, address_part = vless_raw.split("@")
        server_port_part = address_part.split("?")[0]
        server, port = server_port_part.split(":")
        port = int(port)

        # Пинг
        import subprocess
        result = subprocess.run(["ping", "-c", "1", "-W", "1", server], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        if "time=" in output:
            ping_time = float(output.split("time=")[1].split(" ")[0])
            if ping_time <= MAX_PING:
                filtered.append(line)
                print(f"✓ Пинг {ping_time}мс - OK: {server}")
            else:
                print(f"✗ Пинг {ping_time}мс - СЛИШКОМ ВЫСОКИЙ: {server}")
        else:
            print(f"✗ Сервер не отвечает: {server}")
    except Exception as e:
        print(f"✗ Ошибка при обработке строки #{i}: {line}")
        print("Причина:", e)

# Создание shadowrocket.txt
with open("output/shadowrocket.txt", "w") as f:
    for line in filtered:
        f.write(line + "\n")
print("Файл shadowrocket.txt создан.")

# Создание clash.yaml
proxies = []
for i, line in enumerate(filtered):
    try:
        vless_raw = line[8:]
        uuid_part, address_part = vless_raw.split("@")
        server_port_part = address_part.split("?")[0]
        server, port = server_port_part.split(":")
        port = int(port)
        proxies.append({
            "name": f"server{i}",
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid_part,
            "tls": True
        })
    except Exception as e:
        print(f"✗ Ошибка при создании proxy-конфига из строки #{i}: {line}")
        print("Причина:", e)

output_data = {
    "proxies": proxies,
    "proxy-groups": [
        {
            "name": "auto",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "proxies": [f"server{i}" for i in range(len(proxies))]
        }
    ]
}

with open("output/clash.yaml", "w") as f:
    yaml.dump(output_data, f, allow_unicode=True)
print("Файл clash.yaml создан.")
