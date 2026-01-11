import os
import time
import jwt
import requests
from dotenv import load_dotenv

# Load variables from .env
load_dotenv()

APP_ID = os.getenv("APP_ID")
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")

# Read the private key and normalize line endings
with open(PRIVATE_KEY_PATH, "r", encoding="utf-8-sig") as f:
    PRIVATE_KEY = f.read().replace('\r\n', '\n')

# JWT creation for the GitHub App
iat = int(time.time()) -10
exp = iat + 60  # Expiration 60 seconds
payload = {"iat": iat, "exp": exp, "iss": APP_ID}
jwt_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
print("JWT generated correctly!")

# Check installations from the GitHub APP
url = "https://api.github.com/app/installations"
headers = {
    "Authorization": f"Bearer {jwt_token}",
    "Accept": "application/vnd.github+json"
}

response = requests.get(url, headers=headers)
response.raise_for_status()
installations = response.json()

# We show the installation IDs
if installations:
    print("Installation IDs:")
    for inst in installations:
        print(f"- ID: {inst['id']} | Account: {inst['account']['login']}")
else:
    print("There are not installation IDs for this GitHub APP")
