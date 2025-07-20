import requests
import yaml
import subprocess

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300  # Пока не используется

# Получаем список ссылок
r = requests.get(URL)
servers = r.text.strip().splitlines()

# Функция пинга: оставим для будущего
def ping_server(url):
    try:
        address = url.split('@')[-1].split(':')[0]
        print(f"Pinging: {address}")
        result = subprocess.run(['ping', '-c', '1', '-W', '1', address], stdout=subprocess.DEVNULL)
        print(f"Result: {result.returncode}")
        return result.returncode == 0
    except:
        return False

# Временно не фильтруем — используем всё
filtered = servers  # или: [s for s in servers if ping_server(s)]

# Создаем clash.yaml
config = {
    'proxies': [],
    'proxy-groups': [],
    'rules': []
}

for i, line in enumerate(filtered):
    config['proxies'].append({
        'name': f'server{i+1}',
        'type': 'vless',
        'server': line.split('@')[-1].split(':')[0],
        'port': int(line.split(':')[-1].split('?')[0]),
        'uuid': line.split('//')[1].split('@')[0].split(':')[1],
        'tls': True,
        'network': 'ws',
        'ws-opts': {
            'path': '/',
            'headers': {
                'Host': 'example.com'
            }
        }
    })

# Сохраняем файлы
with open('output/clash.yaml', 'w') as f:
    yaml.dump(config, f, sort_keys=False)

with open('output/shadowrocket.txt', 'w') as f:
    for s in filtered:
        f.write(s + '\n')
