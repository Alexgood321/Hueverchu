import os
import socket
import subprocess
import time

INPUT_FILE = "Server.txt"
SHADOWROCKET_OUTPUT = "output/shadowrocket.txt"
CLASH_OUTPUT = "output/clash.yaml"
PING_LOG = "output/ping_debug.txt"
SKIPPED_LOG = "output/skipped.txt"

os.makedirs("output", exist_ok=True)

def extract_host_from_url(url):
    try:
        if "@" in url:
            after_at = url.split("@")[1]
            return after_at.split(":")[0]
        elif "//" in url:
            main_part = url.split("//")[1]
            return main_part.split(":")[0].split("@")[-1]
    except Exception as e:
        return None
    return None

def ping_host(host):
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return None
    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", host],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        for line in output.splitlines():
            if "time=" in line:
                return float(line.split("time=")[1].split(" ")[0])
    except subprocess.CalledProcessError:
        return None
    return None

with open(INPUT_FILE, "r") as f:
    urls = [line.strip() for line in f if line.strip()]

good_urls = []
ping_results = []
skipped_urls = []

for idx, url in enumerate(urls):
    host = extract_host_from_url(url)
    if not host:
        skipped_urls.append((url, "❌ Не удалось извлечь host"))
        continue

    ping = ping_host(host)
    proto = "UNKNOWN"
    if url.startswith("vless://"):
        proto = "VLESS"
    elif url.startswith("trojan://"):
        proto = "TROJAN"
    elif url.startswith("ss://"):
        proto = "SS"

    if ping is None:
        ping_results.append(f"[{idx+1}] {proto} | URL: {url}\n  ❌ Не удалось узнать хост\n")
        skipped_urls.append((url, "❌ Не удалось узнать хост"))
        continue
    elif ping > 300:
        ping_results.append(f"[{idx+1}] {proto} | URL: {url}\n  ⚠️ Плохой ping: {ping:.0f} ms\n")
    else:
        ping_results.append(f"[{idx+1}] {proto} | URL: {url}\n  ✅ Пинг: {ping:.0f} ms\n")

    good_urls.append((url, proto))

# Запись Shadowrocket
with open(SHADOWROCKET_OUTPUT, "w") as f:
    for url, proto in good_urls:
        if proto in ["VLESS", "TROJAN", "SS"]:
            f.write(url + "\n")

# Запись Clash
with open(CLASH_OUTPUT, "w") as f:
    f.write("proxies:\n")
    # сюда можно вставить парсинг позже

# Запись отладочного пинга
with open(PING_LOG, "w") as f:
    f.writelines(ping_results)

# Запись отброшенных
with open(SKIPPED_LOG, "w") as f:
    for line, reason in skipped_urls:
        f.write(f"{reason} => {line}\n")

print("✅ Завершено. Прокси сохранены.")
