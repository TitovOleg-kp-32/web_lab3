from flask import Flask, redirect, request, jsonify, make_response
import ssl
import secrets
import requests
from urllib.parse import urlencode
import os
import subprocess

app = Flask(__name__)
app.secret_key = "lab3_secret_key_change_me"

CASDOOR_BASE_URL = "https://localhost:8443"
CLIENT_ID = "bc51d0983fe505ce310e"
CLIENT_SECRET = "5e61a2bfcc5b0da369c607e962d1db45a0bfdf59"
REDIRECT_URI = "https://127.0.0.1:5000/callback"


def get_mkcert_ca_bundle():
    try:
        caroot = subprocess.check_output(["mkcert", "-CAROOT"], text=True).strip()
        candidate = os.path.join(caroot, "rootCA.pem")
        if os.path.exists(candidate):
            return candidate
    except Exception:
        pass
    return True


VERIFY_CERT = get_mkcert_ca_bundle()


@app.get("/")
def index():
    return """
    <html>
      <body>
        <h2>Lab 3 OIDC</h2>
        <button onclick="window.location.href='/login'">Login via Casdoor</button>
        <button onclick="fetch('/user-info', {credentials: 'include'})
          .then(async r => {
            const text = await r.text();
            document.getElementById('result').textContent = text;
          })">
          Get user info
        </button>
        <pre id="result"></pre>
      </body>
    </html>
    """


@app.get("/login")
def login():
    state = secrets.token_urlsafe(16)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": state,
    }

    auth_url = f"{CASDOOR_BASE_URL}/login/oauth/authorize?{urlencode(params)}"
    response = make_response(redirect(auth_url))
    response.set_cookie("oidc_state", state, httponly=True, samesite="Lax", secure=True)
    return response


@app.get("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    saved_state = request.cookies.get("oidc_state")

    if not code or not state or state != saved_state:
        return jsonify({"error": "Invalid callback or state"}), 400

    token_url = f"{CASDOOR_BASE_URL}/api/login/oauth/access_token"

    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }

    token_resp = requests.post(token_url, data=data, timeout=15, verify=VERIFY_CERT)

    if token_resp.status_code != 200:
        return jsonify({
            "error": "Failed to obtain token",
            "status_code": token_resp.status_code,
            "response": token_resp.text
        }), 400

    token_json = token_resp.json()
    access_token = token_json.get("access_token")

    if not access_token:
        return jsonify({"error": "Access token is missing in response"}), 400

    response = make_response(redirect("/"))
    response.set_cookie("access_token", access_token, httponly=False, samesite="Lax", secure=True)
    response.set_cookie("oidc_state", "", expires=0)
    return response


@app.get("/user-info")
def user_info():
    access_token = request.cookies.get("access_token")
    if not access_token:
        return jsonify({"error": "Unauthorized: token is missing"}), 401

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    resp = requests.get(
        f"{CASDOOR_BASE_URL}/api/userinfo",
        headers=headers,
        timeout=15,
        verify=VERIFY_CERT
    )

    if resp.status_code == 200:
        return jsonify(resp.json())

    return jsonify({"error": "Unauthorized: token is invalid"}), 401


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("localhost+2.pem", "localhost+2-key.pem")

    app.run(host="127.0.0.1", port=5000, debug=True, ssl_context=context)