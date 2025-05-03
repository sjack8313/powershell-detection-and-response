import requests

def block_ip(ip):
    api_key = "YOUR_FIREWALL_API_KEY"
    url = "https://your-firewall.local/api/block"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "ip": ip,
        "reason": "Suspicious PowerShell activity"
    }

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        print(f"[+] Blocked IP: {ip}")
    else:
        print(f"[!] Failed to block IP: {ip} — {response.status_code}")

# Example: block_ip("192.168.1.5")
