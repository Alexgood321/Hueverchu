import requests
import yaml
import subprocess

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300

# Получаем список ссылок
r = requests.get(URL)
servers = r.text.strip().splitlines()

print(f"Загружено {len(servers)} строк")

# ⛔️ Временно отключаем фильтрацию по ping для отладки
filtered = servers

# Создание clash.yaml
config = {
    'proxies': [],
    'proxy-groups': [],
    'rules': []
}

for i, line in enumerate(filtered):
    parts = line.split('@')[-1].split(':')
    if len(parts) < 2:
        continue

    config['proxies'].append({
        'name': f'server{i}',
        'type': 'vless',
        'server': parts[0],
        'port': int(parts[1].split('?')[0]),
        'uuid': line.split('@')[0].split('//')[1].split(':')[1].split('-')[0],  # упрощённо
        'tls': True
    })

# Сохраняем clash.yaml
with open('output/clash.yaml', 'w') as f:
    yaml.dump(config, f, sort_keys=False)

# Сохраняем shadowrocket.txt
with open('output/shadowrocket.txt', 'w') as f:
    for s in filtered:
        f.write(s + '\n')
