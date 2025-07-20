import requests
import yaml
import os

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300

try:
    r = requests.get(URL)
    servers = r.text.strip().splitlines()
    print(f"DEBUG: загружено строк — {len(servers)}")
except Exception as e:
    print("Ошибка при загрузке Server.txt:", e)
    exit(1)

if not servers:
    print("Server.txt пустой. Завершение.")
    exit(1)

# Без фильтрации по ping
filtered = servers

# Подготовка config
config = {
    'proxies': [],
    'proxy-groups': [],
    'rules': []
}

for i, line in enumerate(filtered):
    try:
        url = line.split('//')[-1]
        addr_port = url.split('@')[-1].split(':')
        server = addr_port[0]
        port = int(addr_port[1].split('?')[0])

        uuid = url.split(':')[1].split('@')[0]

        config['proxies'].append({
            'name': f'server{i}',
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'tls': True
        })
    except Exception as e:
        print(f"Ошибка при обработке строки #{i}: {line}")
        print("Причина:", e)
        continue

# Проверка / создание директории output
if not os.path.exists('output'):
    os.makedirs('output')

try:
    with open('output/clash.yaml', 'w') as f:
        yaml.dump(config, f, sort_keys=False)
    print("Файл clash.yaml создан.")
except Exception as e:
    print("Ошибка при записи clash.yaml:", e)
    exit(1)

try:
    with open('output/shadowrocket.txt', 'w') as f:
        for s in filtered:
            f.write(s + '\n')
    print("Файл shadowrocket.txt создан.")
except Exception as e:
    print("Ошибка при записи shadowrocket.txt:", e)
    exit(1)
