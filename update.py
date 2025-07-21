import os
import subprocess

# Ручной список ссылок (можно заменить на чтение из файла или URL)
vless_links = [
    "vless://bm9uZTo1ODNjZWFiMy00MDIyLTQ1NTMtOTE1OC05YmVkYzYyNWFkNGVAMTg1LjE4LjI1MC4xODg6ODg4MA?path=/TelegramU0001F1E8U0001F1F3%2520@WangCai2%2520/?ed=2560&remarks=%25E2%259A%25A1%2520b2n.ir/v2ray-configs%2520%257C%2520279&obfsParam=ip.langmanshanxi.top&obfs=websocket%20%202",
    "vless://bm9uZTpmYWI3YmY5Yy1kZGI5LTQ1NjMtOGEwNC1mYjAxY2U2YzBmYmZANDUuMTU5LjIxNy42Mzo4ODgw?path=/Telegram%F0%9F%87%A8%F0%9F%87%B3%20@WangCai2%20/?ed=2560fp=chrome&remarks=%E2%9A%A1%20b2n.ir/v2ray-configs%20%7C%20888&obfsParam=jp.laoyoutiao.link&obfs=websocket",
    "vless://bm9uZTo1ODNjZWFiMy00MDIyLTQ1NTMtOTE1OC05YmVkYzYyNWFkNGVAMTkzLjkuNDkuMTg4Ojg4ODA?path=/Telegram%F0%9F%87%A8%F0%9F%87%B3%20@WangCai2%20/?ed=2560&remarks=%E2%9A%A1%20b2n.ir/v2ray-configs%20%7C%20645&obfsParam=ip.langmanshanxi.top&obfs=websocket",
    "vless://bm9uZTo2NWVlMjdiOC04OGI2LTQ1ZjUtYTJmOC04MzkyYzRhZmQ4MmRAMjEyLjE4My44OC4yOToyMDgz?path=/3BiOQ1rCgST9FvMj?ed=2560fp=chrome&remarks=%E2%9A%A1%20b2n.ir/v2ray-configs%20%7C%20806&obfsParam=POstwARE-2jm.PagES.DEv&obfs=websocket&tls=1&peer=POstwARE-2jm.PagES.DEv",
    "vless://bm9uZTo1ODNjZWFiMy00MDIyLTQ1NTMtOTE1OC05YmVkYzYyNWFkNGVAMjUuMjUuMjUuMTg2Ojg4ODA?path=/TelegramU0001F1E8U0001F1F3%20@WangCai2%20/?ed=2560&remarks=%E2%9A%A1%20b2n.ir/v2ray-configs%20%7C%20503&obfsParam=ip.langmanshanxi.top&obfs=websocket",
]

os.makedirs("output", exist_ok=True)

with open("output/shadowrocket.txt", "w") as f:
    for link in vless_links:
        f.write(link + "\n")

# Запуск ping для фильтрации и логирования
with open("output/ping_debug.txt", "w") as debug:
    for i, link in enumerate(vless_links):
        debug.write(f"\nОбработка строки #{i}:\n{link}\n")
        try:
            # Парсим адрес для ping (наивно, можно улучшить)
            after_at = link.split("@")[1]
            address_port = after_at.split("?")[0].split("/")[0]
            address = address_port.split(":")[0]

            response = subprocess.run(["ping", "-c", "1", "-W", "1", address], stdout=subprocess.PIPE)
            if response.returncode == 0:
                debug.write("Ping: OK\n")
            else:
                debug.write("Ping: ❌ (высокий пинг или не отвечает)\n")
        except Exception as e:
            debug.write(f"Ошибка разбора адреса: {e}\n")
