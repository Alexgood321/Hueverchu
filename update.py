import os
import yaml
import base64
import socket
from urllib.parse import urlparse

INPUT_FILE = "Server.txt"
CLASH_FILE = "output/clash.yaml"
SHADOWROCKET_FILE = "output/shadowrocket.txt"
PING_DEBUG_FILE = "output/ping_debug.txt"
SKIPPED_FILE = "output/skipped.txt"

def parse_server_line(line):
    line = line.strip()
    if line.startswith("vless://"):
        return "VLESS", line
    elif line.startswith("trojan://"):
        return "TROJAN", line
    elif line.startswith("ss://"):
        return "SS", line
    else:
        return None, line

def extract_hostname(url):
    parsed = urlparse(url)
    return parsed.hostname

def safe_get_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def write_file(filename, content):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

def main():
    if not os.path.exists("output"):
        os.makedirs("output")

    proxies = []
    shadowrocket_entries = []
    debug_logs = []
    skipped_logs = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for idx, line in enumerate(lines, 1):
        proto, url = parse_server_line(line)
        if not proto:
            skipped_logs.append(f"[{idx}] ❌ Неизвестный формат => {line.strip()}")
            continue

        host = extract_hostname(url)
        ip = safe_get_ip(host)

        if not ip:
            skipped_logs.append(f"[{idx}] ❌ Не удалось узнать хост => {url.strip()}")
            debug_logs.append(f"[{idx}] {proto} | URL: {url.strip()}\n❌ Не удалось узнать хост\n")
        else:
            debug_logs.append(f"[{idx}] {proto} | URL: {url.strip()}\n✅ Host: {host} | IP: {ip}\n")

        # В любом случае добавим
        proxies.append({"name": f"{proto}_{idx}", "type": "vless", "server": host, "port": 443, "uuid": "uuid-placeholder", "tls": True})
        shadowrocket_entries.append(url.strip())

    clash_yaml = yaml.dump({"proxies": proxies}, allow_unicode=True, sort_keys=False)

    write_file(CLASH_FILE, clash_yaml)
    write_file(SHADOWROCKET_FILE, "\n".join(shadowrocket_entries))
    write_file(PING_DEBUG_FILE, "\n".join(debug_logs))
    write_file(SKIPPED_FILE, "\n".join(skipped_logs))

    print(f"✅ Завершено. Найдено {len(proxies)} ссылок. Пропущено {len(skipped_logs)}.")

if __name__ == "__main__":
    main()
