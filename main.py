import time
import json
import threading
import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import os
from dotenv import load_dotenv
import pytz
from datetime import datetime

app = FastAPI()

# -----------------------------
# Load .env
# -----------------------------
load_dotenv()
EXTERNAL_API = os.getenv("EXTERNAL_API")

KEY_FILE = "key.json"
IP_FILE = "m7ip.json"
INFO_FILE = "infom7.json"

# -----------------------------
# Create files if missing
# -----------------------------
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "w") as f:
        json.dump({"keys": {}}, f, indent=4)

if not os.path.exists(IP_FILE):
    with open(IP_FILE, "w") as f:
        json.dump({"blocked_ips": []}, f, indent=4)

if not os.path.exists(INFO_FILE):
    with open(INFO_FILE, "w") as f:
        json.dump({"visits": []}, f, indent=4)

# -----------------------------
# Read keys
# -----------------------------
def load_keys():
    try:
        with open(KEY_FILE, "r") as f:
            return json.load(f)
    except:
        return {"keys": {}}

# -----------------------------
# Save keys
# -----------------------------
def save_keys(data):
    with open(KEY_FILE, "w") as f:
        json.dump(data, f, indent=4)

# -----------------------------
# Check if IP is blocked
# -----------------------------
def is_ip_blocked(ip):
    with open(IP_FILE, "r") as f:
        data = json.load(f)
    return ip in data["blocked_ips"]

# -----------------------------
# Block IP
# -----------------------------
def block_ip(ip):
    with open(IP_FILE, "r") as f:
        data = json.load(f)

    if ip not in data["blocked_ips"]:
        data["blocked_ips"].append(ip)

        with open(IP_FILE, "w") as f:
            json.dump(data, f, indent=4)

    return JSONResponse({"error": "Your device has been blocked from using this API"}, status_code=403)

# -----------------------------
# Device type
# -----------------------------
def get_device_type(ua):
    ua = ua.lower()
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        return "PHONE"
    if "tablet" in ua or "ipad" in ua:
        return "TAP"
    return "PC"

# -----------------------------
# Log visitor info
# -----------------------------
def log_user_info(request: Request):
    ip = request.headers.get("X-Forwarded-For", request.client.host)
    if "," in ip:
        ip = ip.split(",")[0].strip()

    ua = request.headers.get("User-Agent", "Unknown")

    try:
        ipinfo = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,isp,proxy",
            timeout=3
        ).json()
        country = ipinfo.get("country", "Unknown")
        isp = ipinfo.get("isp", "Unknown")
        vpn = "Yes" if ipinfo.get("proxy") else "No"
    except:
        country = "Unknown"
        isp = "Unknown"
        vpn = "Unknown"

    device = get_device_type(ua)
    browser = ua.split("/")[0].title() if "/" in ua else ua[:20]

    jordan = pytz.timezone("Asia/Amman")
    now = datetime.now(jordan)
    time12 = now.strftime("%I:%M:%S %p")
    date = now.strftime("%Y-%m-%d")

    try:
        with open(INFO_FILE, "r") as f:
            data = json.load(f)
    except:
        data = {"visits": []}

    data["visits"].append({
        "ip": ip,
        "country": country,
        "vpn": vpn,
        "isp": isp,
        "device": device,
        "browser": browser,
        "time": time12,
        "date": date
    })

    with open(INFO_FILE, "w") as f:
        json.dump(data, f, indent=4)

# -----------------------------
# Before every request → logging + protection
# -----------------------------
@app.middleware("http")
async def strict_whitelist(request: Request, call_next):
    log_user_info(request)

    ip = request.client.host
    ua = request.headers.get("User-Agent", "").lower()

    if is_ip_blocked(ip):
        return JSONResponse({"error": "Your device has been blocked from using this API"}, status_code=403)

    if ua.strip() == "":
        print(f"[Warning] Empty User-Agent from {ip}")
        return await call_next(request)

    blocked_tools = [
        "curl","wget","httpie","powershell","postman","insomnia",
        "fiddler","burpsuite","nmap","nikto","acunetix","sqlmap",
        "arachni","wapiti","metasploit","zaproxy","hydra","medusa",
        "aircrack","ettercap","bettercap","sslscan","masscan",
        "node-fetch","got","dart-http","libcurl","nc","netcat",
        "python-urllib","okhttp","java-http-client","ruby-net-http",
        "perl-lwp","go-http-client","rust-reqwest","php-curl",
        "php-http","scrapy","selenium"
    ]

    for tool in blocked_tools:
        if tool in ua:
            return block_ip(ip)

    allowed_agents = [
        "chrome","chromium","firefox","safari","edge","edg","opera",
        "opera gx","brave","vivaldi","yandex","ucbrowser",

        "android","iphone","ipad","ipod","mobile","samsungbrowser",
        "miuibrowser","huawei","honorbrowser","realme","oppo",
        "puffin","duckduckgo","kiwi","phoenix","xbrowser",

        "wv","version","linux","windows nt","macintosh","mac os",
        "gecko","applewebkit",

        "discord","discordbot","telegram","whatsapp","facebook",
        "instagram","messenger","tiktok","snapchat",

        "python-requests","okhttp","axios","fetch","postman-runtime",

        "discord.py","discord.js","hikari","nextcord","py-cord",
        "discordgo","discordrb",

        "python-telegram-bot","telethon","pyrogram","aiogram","grammy",

        "flask","fastapi","uvicorn","werkzeug"
    ]

    if not any(a in ua for a in allowed_agents):
        print(f"[Warning] Unknown User-Agent from {ip}: {ua}")
        return await call_next(request)

    return await call_next(request)

# -----------------------------
# Key Expiration Thread
# -----------------------------
def key_checker():
    while True:
        keys_data = load_keys()
        changed = False
        jordan_now = time.time() + 3*3600

        for key, info in keys_data["keys"].items():
            if info.get("active") and "duration" in info and "expires_at" not in info:
                info["expires_at"] = jordan_now + info["duration"]
                changed = True

            if info.get("active") and "expires_at" in info:
                if jordan_now > info["expires_at"]:
                    info["active"] = False
                    changed = True

        if changed:
            save_keys(keys_data)

        time.sleep(0.5)

threading.Thread(target=key_checker, daemon=True).start()

# -----------------------------
# Main API
# -----------------------------
@app.get("/dvm7api/player")
async def player(request: Request):
    uid = request.query_params.get("uid")
    region = request.query_params.get("region")
    key = request.query_params.get("key")

    if not key:
        return JSONResponse({"status": "error", "message": "Key required"}, status_code=400)

    keys_data = load_keys()
    if key not in keys_data["keys"] or not keys_data["keys"][key].get("active"):
        return JSONResponse({"status": "error", "message": "Invalid key"}, status_code=403)

    if not uid or not region:
        return JSONResponse({"status": "error", "message": "uid & region required"}, status_code=400)

    if not EXTERNAL_API or EXTERNAL_API.strip() == "":
        return JSONResponse({
            "status": "error",
            "message": "EXTERNAL_API is not set in .env file"
        }, status_code=500)

    try:
        target_url = f"{EXTERNAL_API}?region={region}&uid={uid}"
        response = requests.get(target_url, timeout=11)
        try:
            data = response.json()
        except ValueError:
            # إذا الاستجابة غير صالحة أو فارغة
            data = {"error": "Invalid JSON from external API"}

        return JSONResponse({
            "status": "success",
            "key": key,
            "uid": uid,
            "region": region,
            "data": data
        })

    except requests.exceptions.Timeout:
        return JSONResponse({"status": "error", "message": "External API timeout"}, status_code=504)

    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)