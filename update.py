import requests
import yaml

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300  # мс

# Получаем список ссылок
r = requests.get(URL)
servers = r.text.strip().splitlines()

# Простая фильтрация: пропускаем только те, у кого IP пингуется
import subprocess

def ping_server(url):
    try:
        address = url.split('@')[-1].split(':')[0]
        result = subprocess.run(['ping', '-c', '1', '-W', '1', address], stdout=subprocess.PIPE)
        return result.returncode == 0
    except:
        return False

filtered = [s for s in servers if ping_server(s)]

# Создаем clash.yaml
config = {
    'proxies': [],
    'proxy-groups': [],
    'rules': []
}

for i, line in enumerate(filtered):
    config['proxies'].append({
        'name': f'server{i}',
        'type': 'vless',
        'server': line.split('@')[-1].split(':')[0],
        'port': int(line.split(':')[-1].split('?')[0]),
        'uuid': line.split('//')[1].split('@')[0],
        'tls': True
    })

# Сохраняем файлы
with open('output/clash.yaml', 'w') as f:
    yaml.dump(config, f, sort_keys=False)

with open('output/shadowrocket.txt', 'w') as f:
    for s in filtered:
        f.write(s + '\n')
