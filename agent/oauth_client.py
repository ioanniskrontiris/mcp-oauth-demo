import re
import requests
from authlib.integrations.requests_client import OAuth2Session
import secrets
import base64
import hashlib
import json
import webbrowser

class OAuthHandler:
    def __init__(self, www_auth_header):
        self.metadata_url = self.extract_metadata_url(www_auth_header)

    def extract_metadata_url(self, header):
        # Example: Bearer realm="...", resource_metadata="http://localhost:9090/.well-known/oauth-protected-resource"
        match = re.search(r'resource_metadata="([^"]+)"', header)
        if not match:
            raise ValueError("No resource_metadata in WWW-Authenticate")
        return match.group(1)

    def run_full_flow(self):
        # 1) Get resource metadata
        rm = requests.get(self.metadata_url).json()
        as_url = rm['authorization_servers'][0]  # pick the first AS

        # 2) Get AS metadata
        as_meta = requests.get(as_url + '/.well-known/oauth-authorization-server').json()

        auth_endpoint = as_meta['authorization_endpoint']
        token_endpoint = as_meta['token_endpoint']

        # 3) PKCE
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('ascii')).digest()
        ).rstrip(b'=').decode('ascii')

        client_id = "demo-client"
        redirect_uri = "http://localhost:8081/callback"  # local redirect handler

        session = OAuth2Session(client_id, redirect_uri=redirect_uri, code_challenge=code_challenge, code_challenge_method="S256")

        uri, state = session.create_authorization_url(auth_endpoint, scope="echo:read")
        print(f"Open in browser: {uri}")
        webbrowser.open(uri)

        # 4) Run a small local server to receive the redirect with code
        from wsgiref.simple_server import make_server
        auth_code_holder = {}
        def app(env, start_response):
            from urllib.parse import parse_qs
            qs = parse_qs(env['QUERY_STRING'])
            auth_code_holder['code'] = qs.get('code', [''])[0]
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return [b'You can close this tab.']

        with make_server('', 8081, app) as httpd:
            httpd.handle_request()

        code = auth_code_holder['code']

        token = session.fetch_token(token_endpoint, code=code, code_verifier=code_verifier)
        return token