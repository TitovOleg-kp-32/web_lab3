from flask import Flask, redirect, request, jsonify, make_response
import ssl
import secrets
import requests
from urllib.parse import urlencode
import os
import subprocess
import jwt
from jwt import algorithms

app = Flask(__name__)
app.secret_key = "lab3_secret_key_change_me"

CASDOOR_BASE_URL = "https://localhost:8443"
CLIENT_ID = "bc51d0983fe505ce310e"
CLIENT_SECRET = "5e61a2bfcc5b0da369c607e962d1db45a0bfdf59"
REDIRECT_URI = "https://127.0.0.1:5000/callback"


APPLICATION_NAME = "web_lab3"


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


def get_jwks():
    jwks_url = f"{CASDOOR_BASE_URL}/.well-known/{APPLICATION_NAME}/jwks"
    resp = requests.get(jwks_url, timeout=15, verify=VERIFY_CERT)
    resp.raise_for_status()
    return resp.json()


def get_signing_key(token: str):
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    if not kid:
        raise jwt.InvalidTokenError("JWT header does not contain 'kid'")

    jwks = get_jwks()
    keys = jwks.get("keys", [])

    for jwk in keys:
        if jwk.get("kid") == kid:
            return algorithms.RSAAlgorithm.from_jwk(jwk)

    raise jwt.InvalidTokenError("Matching JWK for token 'kid' was not found")


def validate_jwt_token(token: str):
    signing_key = get_signing_key(token)

    expected_issuer = "http://localhost:8443"

    payload = jwt.decode(
        token,
        key=signing_key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=expected_issuer,
        options={
            "require": ["exp", "iss", "aud"]
        },
        leeway=30
    )
    return payload


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
    id_token = token_json.get("id_token")

    if not access_token:
        return jsonify({"error": "Access token is missing in response"}), 400

    if not id_token:
        return jsonify({"error": "ID token is missing in response"}), 400

    response = make_response(redirect("/"))
    response.set_cookie("access_token", access_token, httponly=False, samesite="Lax", secure=True)
    response.set_cookie("id_token", id_token, httponly=False, samesite="Lax", secure=True)
    response.set_cookie("oidc_state", "", expires=0)
    return response


@app.get("/user-info")
def user_info():
    id_token = request.cookies.get("id_token")
    if not id_token:
        return jsonify({"error": "Unauthorized: token is missing"}), 401

    try:
        payload = validate_jwt_token(id_token)

        user_info_payload = {
            "sub": payload.get("sub"),
            "aud": payload.get("aud"),
            "iss": payload.get("iss"),
            "name": payload.get("name"),
            "email": payload.get("email"),
            "email_verified": payload.get("email_verified"),
            "preferred_username": payload.get("preferred_username"),
            "picture": payload.get("picture"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat"),
        }

        return jsonify(user_info_payload)

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Unauthorized: token is expired"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Unauthorized: invalid token ({str(e)})"}), 401
    except Exception as e:
        return jsonify({"error": f"Unauthorized: validation failed ({str(e)})"}), 401


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("localhost+2.pem", "localhost+2-key.pem")

    app.run(host="127.0.0.1", port=5000, debug=True, ssl_context=context)