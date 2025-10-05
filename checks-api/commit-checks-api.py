from flask import Flask, request
import os
import jwt
import time
import requests
from dotenv import load_dotenv

load_dotenv()

APP_ID = os.getenv("APP_ID")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")

app = Flask(__name__)

# Cargar clave privada
with open(PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY = f.read()

def create_jwt():
    payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + (10 * 60),
        "iss": APP_ID
    }
    encoded_jwt = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    return encoded_jwt

@app.route("/webhook", methods=["POST"])
def webhook():
    event = request.headers.get("X-GitHub-Event")
    payload = request.json

    if event == "pull_request":
        print(f"➡️ PR detectada: {payload['pull_request']['title']}")
    
    return "ok", 200

if __name__ == "__main__":
    app.run(port=3000)
