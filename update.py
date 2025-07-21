import os
import subprocess

INPUT_FILE = "input/servers.txt"

def get_ping(ip):
    try:
        output = subprocess.check_output(["ping", "-c", "1", "-W", "1", ip], universal_newlines=True)
        for line in output.split('\n'):
            if "time=" in line:
                return float(line.split("time=")[1].split(" ")[0])
    except:
        return 9999
    return 9999

def extract_ip(vless_url):
    try:
        return vless_url.split('@')[1].split(':')[0]
    except:
        return None

with open(INPUT_FILE, "r") as file:
    proxies = [line.strip() for line in file if line.strip()]

with open("shadowrocket.txt", "w") as f_srk, open("clash.yaml", "w") as f_clash, open("ping_debug.txt", "w") as f_debug:
    f_clash.write("proxies:\n")

    for i, link in enumerate(proxies):
        ip = extract_ip(link)
        if not ip:
            continue

        ping = get_ping(ip)
        f_debug.write(f"Обработка строки #{i}:\n{link}\nPing = {ping} ms\n")

        if ping < 300:
            f_srk.write(link + "\n")
            f_clash.write(
                f"  - name: proxy{i}\n"
                f"    type: vless\n"
                f"    server: {ip}\n"
                f"    port: 443\n"
                f"    uuid: <your-uuid>\n"
                f"    tls: true\n"
            )
        else:
            f_debug.write("Пропуск: высокий пинг\n\n")
