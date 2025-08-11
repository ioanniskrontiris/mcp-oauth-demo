import os
import sys
import json
import base64
import hashlib
import secrets
import threading
import webbrowser
from urllib.parse import urlencode, urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests

AUTH_SERVER = "http://localhost:9092"
RESOURCE_SERVER = "http://localhost:9091"
CLIENT_ID = "demo-client"
REDIRECT_URI = "http://localhost:9200/callback"
SCOPE = "echo:read"

# ===== PKCE Helpers =====
def generate_pkce_pair():
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge

# ===== HTTP Callback Server =====
class OAuthCallbackHandler(BaseHTTPRequestHandler):
    auth_code = None
    state = None

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return

        query = parse_qs(parsed.query)
        OAuthCallbackHandler.auth_code = query.get("code", [None])[0]
        OAuthCallbackHandler.state = query.get("state", [None])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>You can close this tab now.</h1>")

    @classmethod
    def wait_for_code(cls):
        while cls.auth_code is None:
            pass
        return cls.auth_code, cls.state

# ===== Main Flow =====
def discover_as_metadata():
    r = requests.get(f"{AUTH_SERVER}/.well-known/oauth-authorization-server")
    r.raise_for_status()
    return r.json()

def start_http_listener():
    server = HTTPServer(("localhost", 9200), OAuthCallbackHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    return server

def exchange_code_for_token(token_endpoint, code, code_verifier):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier
    }
    r = requests.post(token_endpoint, data=data)
    print("Token endpoint response:", r.status_code, r.text)
    r.raise_for_status()
    return r.json()["access_token"]

def call_mcp_echo(token):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{RESOURCE_SERVER}/echo?text=hello", headers=headers)
    print("MCP /echo status:", r.status_code)
    print("MCP /echo body:", r.text)

def main():
    meta = discover_as_metadata()
    auth_endpoint = meta["authorization_endpoint"]
    token_endpoint = meta["token_endpoint"]

    code_verifier, code_challenge = generate_pkce_pair()

    # Start local HTTP server for redirect
    httpd = start_http_listener()

    # Build auth URL
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": secrets.token_urlsafe(16)
    }
    url = f"{auth_endpoint}?{urlencode(params)}"
    print("Opening browser to:", url)
    webbrowser.open(url)

    # Wait for auth code
    code, state = OAuthCallbackHandler.wait_for_code()
    print("Got authorization code:", code)

    # Exchange code for token
    token = exchange_code_for_token(token_endpoint, code, code_verifier)
    print("Got access token:", token)

    # Call MCP
    call_mcp_echo(token)

    # Stop server
    httpd.shutdown()

if __name__ == "__main__":
    main()