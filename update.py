import requests
import subprocess
import yaml
import base64
import re

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300

# Получение списка ссылок
r = requests.get(URL)
servers = r.text.strip().splitlines()

# Функция пинга
def ping_server(url):
    try:
        match = re.search(r'@([\d\.]+):(\d+)', url)
        if not match:
            return False
        ip = match.group(1)
        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

# Фильтрация
filtered = [s for s in servers if ping_server(s)]

# Создание YAML
config = {
    'proxies': [],
    'proxy-groups': [],
    'rules': []
}

for i, line in enumerate(filtered):
    match = re.search(r'@([\d\.]+):(\d+)', line)
    if not match:
        continue
    server = match.group(1)
    port = match.group(2)
    config['proxies'].append({
        'name': f'server{i+1}',
        'type': 'vless',
        'server': server,
        'port': int(port),
        'uuid': '00000000-0000-0000-0000-000000000000',
        'tls': True,
        'network': 'ws',
        'ws-opts': {
            'path': '/',
            'headers': {
                'Host': 'example.com'
            }
        }
    })

# Сохранение файлов
with open('output/clash.yaml', 'w') as f:
    yaml.dump(config, f, sort_keys=False)

with open('output/shadowrocket.txt', 'w') as f:
    for s in filtered:
        f.write(s + '\n')
