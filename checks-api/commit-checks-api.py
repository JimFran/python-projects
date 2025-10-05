from flask import Flask, request, abort
import os
import jwt
import time
import hmac
import hashlib
from dotenv import load_dotenv

## Quickstart on FLASK:
## https://flask.palletsprojects.com/en/stable/quickstart/

# We load the env vars defined in .env into the environment
load_dotenv()

# After running load_dotenv() we can now extact the env vars with os.getenv 
APP_ID = os.getenv("APP_ID")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")

app = Flask(__name__)

# We store the private key into PRIVATE_KEY env var
with open(PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY = f.read()

# We create the JWT token with the PRIVATE_KEY to interact with the GITHUB APP
# https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app#example-using-python-to-generate-a-jwt
def create_jwt():
    payload = {
        # Issued at time
        "iat": int(time.time()),
        # Expiration time 10 min. maximum (600 seconds)
        "exp": int(time.time()) + 600,
        # Github APP ID
        "iss": APP_ID
    }
    encoded_jwt = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    print(f"Generated JWT: {encoded_jwt}")
    return encoded_jwt

# Payload signature verification
# https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#python-example
def verify_signature(payload_body, signature_header):
    
    # We verify if the signature is there in the header from the Webhook response
    if signature_header is None:
        abort(403, "No signature received in the Header!!!")

    # We verify if the signature is encoded in sha256
    sha_name, signature = signature_header.split('=')
    if sha_name != 'sha256':
        abort(403, "Signatures is not using sha256!!!")

    # We calculate the signature from the body payload received
    # and we calculate if the signature received maches it
    mac = hmac.new(WEBHOOK_SECRET.encode(), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = mac.hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        abort(403, "Invalid signature!!")


    print("Webhook signature verified successfully")

# Endpoint webhook to retrieve the Pull Request title
@app.route("/webhook", methods=["POST"])
def webhook():
    signature = request.headers.get('X-Hub-Signature-256')
    payload = request.data

    # Verify if the signature is coming from Github
    # verify_signature doesn't return true/false, it just aborts in case of any problem
    verify_signature(payload, signature)

    event = request.headers.get("X-GitHub-Event")
    json_payload = request.json
    
    print(f"JSON payload: {json_payload}")
    print(f"Webhook event received: {event}")
    
    # Webhook type event pull_request
    # https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request
    if event == "pull_request":
        print(f"PR detecetd: {json_payload['pull_request']['title']}")
    
    # We return [OK], 200 to the client, in this case Github
    return "[OK]", 200

# We start a Flask server locally on port 3000
if __name__ == "__main__":
    print("FLASK server runnin on http://127.0.0.1:3000/webhook")
    app.run(port=3000)
