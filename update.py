import requests
import yaml
import subprocess
import base64

# Настройки
URL = "https://raw.githubusercontent.com/Alexgood321/proxy-config/main/Server.txt"
MAX_PING = 300  # мс

# Получаем список ссылок
r = requests.get(URL)
servers = r.text.strip().splitlines()

# Декодирование base64-ссылки и извлечение IP и порта
def parse_vless_url(vless_url):
    try:
        if not vless_url.startswith("vless://"):
            return None, None
        base64_part = vless_url.replace("vless://", "").split("?")[0]
        decoded = base64.b64decode(base64_part).decode('utf-8')
        # Пример результата: "none:uuid@185.18.250.188:8880"
        parts = decoded.split('@')
        ip = parts[1].split(':')[0]
        port = parts[1].split(':')[1]
        return ip, port
    except Exception as e:
        print(f"Ошибка разбора: {e}")
        return None, None

# Проверка пинга
def ping_server(ip):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False

# Фильтруем рабочие
filtered = []
for s in servers:
    ip, port = parse_vless_url(s)
    if ip and ping_server(ip):
        filtered.append(s)

# Создаём clash.yaml
config = {
    'proxies': [],
    'proxy-groups': [],
    'rules': []
}

for i, line in enumerate(filtered):
    ip, port = parse_vless_url(line)
    config['proxies'].append({
        'name': f'server{i+1}',
        'type': 'vless',
        'server': ip,
        'port': int(port),
        'uuid': '00000000-0000-0000-0000-000000000000',  # временный заглушка
        'tls': True,
    })

# Сохраняем clash.yaml
with open('output/clash.yaml', 'w') as f:
    yaml.dump(config, f, sort_keys=False)

# Сохраняем shadowrocket.txt
with open('output/shadowrocket.txt', 'w') as f:
    for s in filtered:
        f.write(s + '\n')
