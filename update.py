import requests
import subprocess
import yaml

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300  # мс

# Получение списка ссылок
r = requests.get(URL)
lines = r.text.strip().splitlines()

# Фильтрация рабочих серверов по ping
def ping(server):
    try:
        address = server.split('@')[1].split(':')[0]
        subprocess.check_output(['ping', '-c', '1', '-W', '1', address])
        return True
    except:
        return False

# Подготовка списка
filtered = []
for line in lines:
    if line.startswith('vless://') and '@' in line and ':' in line:
        if ping(line):
            filtered.append(line)

# Формируем clash.yaml
clash_config = {
    'proxies': [],
    'proxy-groups': [
        {
            'name': 'auto',
            'type': 'url-test',
            'proxies': [],
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300
        }
    ],
    'rules': ['MATCH,auto']
}

for i, line in enumerate(filtered):
    try:
        uuid = line.split('://')[1].split('@')[0]
        addr = line.split('@')[1].split(':')[0]
        port = line.split('@')[1].split(':')[1].split('?')[0]

        proxy = {
            'name': f'server{i+1}',
            'type': 'vless',
            'server': addr,
            'port': int(port),
            'uuid': uuid,
            'tls': True,
            'cipher': 'auto',
            'network': 'ws',
            'ws-opts': {
                'path': '/',
                'headers': {'Host': addr}
            }
        }

        clash_config['proxies'].append(proxy)
        clash_config['proxy-groups'][0]['proxies'].append(f'server{i+1}')

    except Exception as e:
        print(f"Ошибка парсинга строки: {line} — {e}")
        continue

# Сохранение файлов
with open('output/clash.yaml', 'w') as f:
    yaml.dump(clash_config, f, sort_keys=False)

with open('output/shadowrocket.txt', 'w') as f:
    for s in filtered:
        f.write(s + '\n')
