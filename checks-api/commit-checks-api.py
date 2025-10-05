from flask import Flask, request, abort
# https://realpython.com/python-requests/
import requests
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
# https://stackoverflow.com/questions/74462420/where-can-we-find-github-apps-installation-id
INSTALLATION_ID = os.getenv("INSTALLATION_ID")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH")
FULL_REPO_NAME = os.getenv("FULL_REPO_NAME")

app = Flask(__name__)

# We store the private key into PRIVATE_KEY env var
with open(PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY = f.read()

######################
# JWT Token Creation #
######################

# We create the JWT token with the PRIVATE_KEY to interact with the GITHUB APP
# This JWT is necessary to create the Installation token 
# that we needs to create the check_run in the PRs
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

###############################
# Installation token creation #
###############################

# We create an installation token to create the check_run in the PRs
# https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app

def create_installation_token(installation_id):
    # We crete the JWT token
    jwt_token = create_jwt()
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json"
    }
    response = requests.post(url, headers=headers)
    response.raise_for_status()
    # We extract the token from the reponse.
    # The installation token will expire after 1h
    return response.json()["token"]

####################################
# Function to check the PR's title #
####################################

def is_title_ok(pr_title):
    # valid semantic-release words
    # https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716
    valid_keywords=["feat", "fix", "docs", "style", "refactor", "test", "chore"]
    title_lowercase = pr_title.lower()

    for k in valid_keywords:
        if k in title_lowercase:
            return True
    return False

##################################
# Payload signature verification #
##################################

# Function to verify the signature received from the webhook
# https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#python-example

def verify_signature(webhook_payload_body, webhook_signature):
    
    # We verify if the signature is there in the header from the Webhook response
    if webhook_signature is None:
        abort(403, "No signature received in the Header!!!")

    # We verify if the signature is encoded in sha256
    sha_name, signature = webhook_signature.split('=')
    if sha_name != 'sha256':
        abort(403, "Signature is not using sha256!!!")

    # We calculate the signature from the body payload received
    # and we calculate if the signature received maches it
    mac = hmac.new(WEBHOOK_SECRET.encode(), msg=webhook_payload_body, digestmod=hashlib.sha256)
    expected_signature = mac.hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        abort(403, "Invalid signature!!")

    print("Webhook signature verified successfully")

##################
# Check creation #
##################

# Function to create the check_run in the PRs
# https://docs.github.com/en/rest/checks/runs?apiVersion=2022-11-28#create-a-check-run

def create_check(pr_commit_sha, full_repo_name, installation_id, is_title_ok):
    # First we need the installation ID to create the installation token
    installation_token = create_installation_token(installation_id)
    url = f"https://api.github.com/repos/{full_repo_name}/check-runs"
    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json"
    }
    
    status = "completed"
    conclusion = "success" if is_title_ok else "failure"

    in_progress_data = {
        "name": "Title Check",
        "head_sha": pr_commit_sha,
        "status": "in_progress"
    }

    response = requests.post(url, json=in_progress_data, headers=headers)
    response.raise_for_status()
    check_run_id = response.json()["id"]
    print("Check_run created in-progress:", response.json()["html_url"])

    completed_data = {
        "status": status,
        "conclusion": conclusion,
        "output": {
            "title": "PR Title Check",
            "summary": "The PR title is valid" if is_title_ok else "The PR title is invalid"
        }
    }
    update_url = f"{url}/{check_run_id}"
    response = requests.patch(update_url, json=completed_data, headers=headers)
    response.raise_for_status()
    print("Check_run completed:", response.json()["html_url"])

####################
# Webhook endpoint #
####################

# Endpoint webhook to retrieve the Pull Request title
@app.route("/webhook", methods=["POST"])
def webhook():
    webhook_signature = request.headers.get('X-Hub-Signature-256')
    webhook_payload_body = request.data

    # Verify if the signature is coming from Github
    # verify_signature doesn't return true/false, it just aborts in case of any problem
    verify_signature(webhook_payload_body, webhook_signature)

    # X-GitHub-Event in the header contains the name of the event 
    # that triggered the delivery
    # https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers
    webhook_event = request.headers.get("X-GitHub-Event")
    json_payload = request.json
    
    print(f"JSON payload: {json_payload}")
    print(f"Webhook event received: {webhook_event}")
    
    # Webhook type event pull_request
    # https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request
    if webhook_event == "pull_request":
        # Title of the PR
        pr_title=json_payload['pull_request']['title']
        print(f"PR detecetd: {pr_title}")
        # PR commit SHA
        pr_commit_sha=json_payload['pull_request']['head']['sha']
        print(f"PR commit SHA: {pr_commit_sha}")
        # Installation ID
        # https://stackoverflow.com/questions/74462420/where-can-we-find-github-apps-installation-id
        installation_id=INSTALLATION_ID
        print(f"Installation ID: {installation_id}")

        try:
          create_check(pr_commit_sha, FULL_REPO_NAME, installation_id, is_title_ok(pr_title))
        except requests.exceptions.HTTPError as e:
          print(f"Error creating the check_run: {e.response.text}")
          return f"[ERROR creating check_run] {e.response.text}", 500
        
    else:
        print(f"Webhook Event ignored")

    # We return [OK], 200 to the client, in this case Github
    return "[OK]", 200

# We start a Flask server locally on port 3000
if __name__ == "__main__":
    print("FLASK server runnin on http://127.0.0.1:3000/webhook")
    app.run(port=3000)
