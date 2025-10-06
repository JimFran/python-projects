import os
import time
import jwt
import requests
from dotenv import load_dotenv

# Load .env file
load_dotenv()

APP_ID = os.getenv("APP_ID")
INSTALLATION_ID = os.getenv("INSTALLATION_ID")
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")

if not APP_ID or not INSTALLATION_ID or not PRIVATE_KEY_PATH:
    raise Exception("Missing APP_ID, INSTALLATION_ID or PRIVATE_KEY_PATH")

# Read PEM private key (in this case we make sure it works in Windows)
with open(PRIVATE_KEY_PATH, "r", encoding="utf-8-sig") as f:
    PRIVATE_KEY = f.read().replace("\r\n", "\n")

print("APP_ID:", APP_ID)
print("INSTALLATION_ID:", INSTALLATION_ID)

# Create JWT
now = int(time.time())
payload = {
    "iat": now - 30,           # clock skew safety
    "exp": now + 540,          # < 10 min (GitHub limit)
    "iss": APP_ID
}

jwt_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
print("JWT generated OK")

# Request installation token
url = f"https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens"
headers = {
    "Authorization": f"Bearer {jwt_token}",
    "Accept": "application/vnd.github+json"
}

response = requests.post(url, headers=headers)

print("Status code:", response.status_code)
print("Response:", response.text)

response.raise_for_status()

token = response.json()["token"]
expires_at = response.json()["expires_at"]

print("Installation token generated successfully!")
print("Token (first 20 chars):", token[:20], "...")
print("Expires at:", expires_at)
