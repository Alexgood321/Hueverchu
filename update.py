import os
import subprocess
import re
import requests
from urllib.parse import urlparse

# Загрузка сервера из ссылки
SERVER_LIST_URL = 'https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt'

response = requests.get(SERVER_LIST_URL)
response.raise_for_status()
urls = response.text.strip().splitlines()

output_dir = "output"
os.makedirs(output_dir, exist_ok=True)

shadowrocket_file = os.path.join(output_dir, "shadowrocket.txt")
ping_debug_file = os.path.join(output_dir, "ping_debug.txt")
skipped_file = os.path.join(output_dir, "skipped.txt")
clash_file = os.path.join(output_dir, "clash.yaml")

def extract_host(vmess_url):
    try:
        # Вырезаем host из VLESS, Trojan, Shadowsocks
        if vmess_url.startswith("vless://") or vmess_url.startswith("trojan://") or vmess_url.startswith("ss://"):
            after_scheme = vmess_url.split("://", 1)[1]
            host_port = re.findall(r'@([^:/?#]+)', after_scheme)
            if host_port:
                return host_port[-1]
            else:
                # fallback: пробуем вытащить просто host из url
                parsed = urlparse(vmess_url)
                return parsed.hostname
        return None
    except Exception:
        return None

def ping_host(host):
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True, text=True)
        if result.returncode == 0:
            match = re.search(r'time=(\d+\.?\d*) ms', result.stdout)
            if match:
                return float(match.group(1))
        return None
    except:
        return None

good_servers = []
ping_logs = []
skipped = []

for i, url in enumerate(urls, start=1):
    url = url.strip()
    if not url:
        continue
    host = extract_host(url)
    label = f"[{i}] {url.split('://')[0].upper()} | URL: {url}"

    if host:
        ping = ping_host(host)
        if ping is not None:
            if ping < 300:
                good_servers.append(url)
                ping_logs.append(f"{label}\n✅ Пинг: {ping} мс\n")
            else:
                ping_logs.append(f"{label}\n⚠️ Пропущен — высокий пинг\n")
        else:
            ping_logs.append(f"{label}\n❌ Не удалось узнать пинг\n")
            skipped.append(f"{label} => {url}")
    else:
        ping_logs.append(f"{label}\n❌ Не удалось узнать хост\n")
        skipped.append(f"{label} => {url}")

# Запись в файлы
with open(shadowrocket_file, "w", encoding="utf-8") as f:
    f.write("\n".join(good_servers))

with open(ping_debug_file, "w", encoding="utf-8") as f:
    f.write("\n".join(ping_logs))

with open(skipped_file, "w", encoding="utf-8") as f:
    f.write("\n".join(skipped))

# Генерация Clash-конфига
def generate_clash_yaml(servers):
    clash_config = "proxies:\n"
    for idx, url in enumerate(servers, start=1):
        scheme = url.split("://")[0].upper()
        server = extract_host(url)
        clash_config += f"  - name: {scheme}_{idx}\n"
        clash_config += f"    type: {scheme.lower()}\n"
        clash_config += f"    server: {server}\n"
        clash_config += f"    port: 443\n"
        clash_config += f"    uuid: uuid-placeholder\n"
        clash_config += f"    tls: true\n"
    return clash_config

with open(clash_file, "w", encoding="utf-8") as f:
    f.write(generate_clash_yaml(good_servers))
