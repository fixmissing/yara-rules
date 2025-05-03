#!/usr/bin/env python3

import sys
import requests
import json
from datetime import datetime

# === CONFIG ===
DISCORD_ROLE_ID = "XXXXXXX"  # Role ID Discord kamu
THUMBNAIL_URL = "https://XXXXXXXXXX/wazuh-logo.png"

# Baca argumen dari Wazuh
alert_file = sys.argv[1]
user = sys.argv[2].split(":")[0]
hook_url = sys.argv[3]

# Load alert file
with open(alert_file) as f:
    alert_json = json.load(f)

# Ambil informasi penting
level = alert_json.get("rule", {}).get("level", 0)
rule_id = alert_json.get("rule", {}).get("id", "N/A")
rule_desc = alert_json.get("rule", {}).get("description", "No description")
agent = alert_json.get("agent", {}).get("name", "agentless")
timestamp = alert_json.get("timestamp", datetime.utcnow().isoformat())

# Warna embed berdasarkan level
if level < 5:
    color = 5763719  # green
elif 5 <= level <= 7:
    color = 16705372  # yellow
else:
    color = 15548997  # red

# Buat field tambahan berdasarkan data alert
extra_fields = []

if "syscheck" in alert_json and "path" in alert_json["syscheck"]:
    path = alert_json["syscheck"]["path"]
    if alert_json["rule"]["id"] == 550:
        extra_fields.append({
            "name": "📄 Perubahan File",
            "value": f"📝 File diubah: `{path}`",
            "inline": False
        })
    elif alert_json["rule"]["id"] == 553:
        extra_fields.append({
            "name": "📄 Perubahan File",
            "value": f"❌ File dihapus: `{path}`",
            "inline": False
        })
    else:
        extra_fields.append({
            "name": "🔍 File Path",
            "value": f"`{path}`",
            "inline": False
        })

if alert_json["rule"]["id"] == 657:
    extra_fields.append({
        "name": "🚨 Notifikasi Active Response",
        "value": "🛡️ YARA telah mengambil tindakan terhadap file terindikasi Webshell dan Judi Online.",
        "inline": False
    })

if "location" in alert_json:
    extra_fields.append({
        "name": "📁 Log Source",
        "value": alert_json["location"],
        "inline": False
    })

extra_fields.append({
    "name": "📊 Rule Level",
    "value": str(level),
    "inline": True
})
extra_fields.append({
    "name": "🕒 Timestamp",
    "value": timestamp,
    "inline": True
})

# Payload ke Discord
payload = {
    "content": f"<@&{DISCORD_ROLE_ID}> ⚠️ Deteksi Wazuh Alert!",
    "embeds": [
        {
            "title": f"🚨 Wazuh Alert - Rule {rule_id}",
            "description": rule_desc,
            "color": color,
            "thumbnail": {"url": THUMBNAIL_URL},
            "fields": [
                {
                    "name": "💻 Agent",
                    "value": agent,
                    "inline": True
                },
                *extra_fields
            ],
            "footer": {
                "text": "Wazuh → Discord Integration",
                "icon_url": THUMBNAIL_URL
            }
        }
    ]
}

# Kirim ke Discord
headers = {"Content-Type": "application/json"}
requests.post(hook_url, data=json.dumps(payload), headers=headers)
